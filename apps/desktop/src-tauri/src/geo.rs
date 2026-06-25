//! Exit-IP and Geo-IP lookups.
//!
//! - Exit-IP lookup goes through the configured SOCKS5 proxy, so we observe the
//!   IP that the proxy egresses with.
//! - Country lookup also goes through the proxy by default. This avoids leaking
//!   the exit IP (and the user's home IP) to the geolocation provider via the
//!   default route. ipwho.is is tried first, then ipapi.co as a fallback.

use proxy_core::proxy_url::socks5_url;
use proxy_core::{format_endpoint_prefix, ResolvedProfile, TrayDisplayMode, TraySettings};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::types::{consts::HTTP_TIMEOUT, ExitStatus};
use crate::util::{country_code_to_flag, current_unix_timestamp};

#[derive(Debug, Deserialize)]
struct IpifyResponse {
    ip: String,
}

const CLOUDFLARE_TRACE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";

#[derive(Debug, Deserialize)]
struct IpWhoResponse {
    success: bool,
    country_code: Option<String>,
    flag: Option<IpWhoFlag>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoFlag {
    emoji: String,
}

#[derive(Debug, Deserialize)]
struct IpApiCoResponse {
    country_code: Option<String>,
    error: Option<bool>,
    reason: Option<String>,
}

pub fn lookup_exit_status(profile: &ResolvedProfile, tray_settings: &TraySettings) -> ExitStatus {
    lookup_exit_status_with_route(LookupRoute::Profile(profile), tray_settings)
}

pub fn lookup_exit_status_direct(tray_settings: &TraySettings) -> ExitStatus {
    lookup_exit_status_with_route(LookupRoute::Direct, tray_settings)
}

enum LookupRoute<'a> {
    Profile(&'a ResolvedProfile),
    Direct,
}

fn lookup_exit_status_with_route(
    route: LookupRoute<'_>,
    tray_settings: &TraySettings,
) -> ExitStatus {
    if !tray_settings.exit_ip_lookup_enabled {
        return ExitStatus::default();
    }

    let mut status = ExitStatus {
        last_checked_unix: Some(current_unix_timestamp()),
        ..ExitStatus::default()
    };

    // TUN mode: every connection already egresses through the proxy via the TUN, so
    // a *direct* client to an IP-literal endpoint is both correct and DNS-free. An
    // explicit SOCKS proxy client (as used for system mode) is wrong here — it would
    // have to resolve the proxy *hostname* locally, but DNS is virtualized in TUN
    // mode, so the lookup (and its same-client fallback) fails and the GUI hangs on
    // "Connecting…" even though the chain is up. The Cloudflare trace returns the
    // exit IP and its country in a single DNS-free request, so we skip ipify/ipwho.is.
    if let LookupRoute::Profile(profile) = &route {
        if profile.routing_mode == proxy_core::RoutingMode::Tun {
            match lookup_tun_exit_via_trace() {
                Ok((exit_ip, country_code)) => {
                    status.exit_ip = Some(exit_ip);
                    if tray_settings.geo_lookup_enabled {
                        if let Some(code) = country_code {
                            status.country_flag = country_code_to_flag(&code);
                            status.country_code = Some(code);
                        }
                    }
                    status.tray_text = tray_indicator_text(&status, tray_settings);
                }
                Err(error) => status.lookup_error = Some(error),
            }
            return status;
        }
    }

    match lookup_exit_ip(&route) {
        Ok(exit_ip) => {
            status.exit_ip = Some(exit_ip.clone());

            if tray_settings.geo_lookup_enabled {
                match lookup_country_data(&route, &exit_ip) {
                    Ok((country_code, flag)) => {
                        status.country_code = Some(country_code);
                        status.country_flag = flag;
                    }
                    Err(error) => status.lookup_error = Some(error),
                }
            }

            status.tray_text = tray_indicator_text(&status, tray_settings);
        }
        Err(error) => status.lookup_error = Some(error),
    }

    status
}

/// Build the tray indicator string for an already-resolved exit status, honoring the
/// configured display mode. Returns `None` when there is no exit IP yet. Kept separate
/// from the network lookup so the tray can be re-rendered (e.g. after a settings
/// change) without performing another lookup.
pub fn tray_indicator_text(
    exit_status: &ExitStatus,
    tray_settings: &TraySettings,
) -> Option<String> {
    let exit_ip = exit_status.exit_ip.as_deref()?;
    Some(match tray_settings.display_mode {
        TrayDisplayMode::Flag => exit_status
            .country_flag
            .clone()
            .unwrap_or_else(|| format_endpoint_prefix(exit_ip, tray_settings.ip_prefix_segments)),
        TrayDisplayMode::IpPrefix => {
            format_endpoint_prefix(exit_ip, tray_settings.ip_prefix_segments)
        }
    })
}

fn build_lookup_client(route: &LookupRoute<'_>) -> Result<Client, String> {
    let builder = Client::builder().timeout(HTTP_TIMEOUT);

    let LookupRoute::Profile(profile) = route else {
        return builder
            .build()
            .map_err(|error| format!("failed to build HTTP client: {error}"));
    };

    let proxy_url = socks5_url(&profile.endpoint).replacen("socks5://", "socks5h://", 1);
    let proxy = reqwest::Proxy::all(proxy_url)
        .map_err(|error| format!("failed to configure SOCKS5 client: {error}"))?;
    builder
        .proxy(proxy)
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))
}

fn lookup_exit_ip(route: &LookupRoute<'_>) -> Result<String, String> {
    let client = build_lookup_client(route)?;
    match client
        .get("https://api.ipify.org?format=json")
        .send()
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => response
            .json::<IpifyResponse>()
            .map(|response| response.ip)
            .map_err(|error| format!("failed to parse exit IP response: {error}")),
        Err(error)
            if matches!(
                route,
                LookupRoute::Profile(profile)
                    if profile.routing_mode == proxy_core::RoutingMode::Tun
            ) =>
        {
            lookup_exit_ip_with_cloudflare_trace(&client)
                .map_err(|fallback_error| {
                    format!(
                        "failed to query exit IP via ipify: {error}; DNS-free fallback failed: {fallback_error}"
                    )
                })
        }
        Err(error) => Err(format!("failed to query exit IP: {error}")),
    }
}

/// TUN-mode exit lookup: one DNS-free request to the Cloudflare trace through the
/// already-established TUN (direct client, no explicit proxy). Returns the exit IP
/// and, when present, its ISO country code (`loc=` field) so we avoid a second
/// hostname-based geo lookup that DNS virtualization would break.
fn lookup_tun_exit_via_trace() -> Result<(String, Option<String>), String> {
    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    let text = client
        .get(CLOUDFLARE_TRACE_URL)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("failed to query Cloudflare trace: {error}"))?
        .text()
        .map_err(|error| format!("failed to read Cloudflare trace: {error}"))?;

    let mut exit_ip = None;
    let mut country_code = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("ip=") {
            let value = value.trim();
            if !value.is_empty() {
                exit_ip = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("loc=") {
            let value = value.trim();
            if !value.is_empty() {
                country_code = Some(value.to_string());
            }
        }
    }

    exit_ip
        .map(|ip| (ip, country_code))
        .ok_or_else(|| "Cloudflare trace response did not include an ip field".to_string())
}

fn lookup_exit_ip_with_cloudflare_trace(client: &Client) -> Result<String, String> {
    let text = client
        .get(CLOUDFLARE_TRACE_URL)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("failed to query Cloudflare trace: {error}"))?
        .text()
        .map_err(|error| format!("failed to read Cloudflare trace: {error}"))?;

    text.lines()
        .find_map(|line| line.strip_prefix("ip="))
        .filter(|ip| !ip.trim().is_empty())
        .map(|ip| ip.trim().to_string())
        .ok_or_else(|| "Cloudflare trace response did not include an ip field".to_string())
}

fn lookup_country_data(
    route: &LookupRoute<'_>,
    exit_ip: &str,
) -> Result<(String, Option<String>), String> {
    // Route geo lookups through the proxy so the exit IP and country lookup are
    // observed by the egress endpoint, not by an arbitrary third party on the
    // user's default route. In TUN mode we use a direct client because the app
    // is already inside the effective TUN path.
    let client = build_lookup_client(route)?;

    match client
        .get(format!("https://ipwho.is/{exit_ip}"))
        .send()
        .and_then(|response| response.error_for_status())
    {
        Ok(response) => {
            let response = response
                .json::<IpWhoResponse>()
                .map_err(|error| format!("failed to parse ipwho.is response: {error}"))?;
            if response.success {
                if let Some(country_code) = response.country_code {
                    return Ok((
                        country_code.clone(),
                        preferred_flag(response.flag, &country_code),
                    ));
                }
            }

            if let Some(message) = response.message {
                return lookup_country_data_with_fallbacks(&client, exit_ip).map_err(
                    |fallback_error| {
                        format!("ipwho.is error: {message}; fallback failed: {fallback_error}")
                    },
                );
            }
        }
        Err(error) => {
            return lookup_country_data_with_fallbacks(&client, exit_ip).map_err(
                |fallback_error| {
                    format!("ipwho.is lookup failed: {error}; fallback failed: {fallback_error}")
                },
            );
        }
    }

    lookup_country_data_with_fallbacks(&client, exit_ip)
}

fn lookup_country_data_with_fallbacks(
    client: &Client,
    exit_ip: &str,
) -> Result<(String, Option<String>), String> {
    lookup_country_data_with_ipapi(client, exit_ip).map_err(|error| format!("ipapi.co: {error}"))
}

fn lookup_country_data_with_ipapi(
    client: &Client,
    exit_ip: &str,
) -> Result<(String, Option<String>), String> {
    let response = client
        .get(format!("https://ipapi.co/{exit_ip}/json/"))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("failed to query ipapi.co: {error}"))?
        .json::<IpApiCoResponse>()
        .map_err(|error| format!("failed to parse ipapi.co response: {error}"))?;

    if response.error.unwrap_or(false) {
        return Err(response
            .reason
            .unwrap_or_else(|| "ipapi.co reported an unknown error".to_string()));
    }

    let country_code = response
        .country_code
        .ok_or_else(|| "ipapi.co response did not include a country code".to_string())?;
    Ok((country_code.clone(), country_code_to_flag(&country_code)))
}

fn preferred_flag(flag: Option<IpWhoFlag>, country_code: &str) -> Option<String> {
    if let Some(flag) = flag {
        if !flag.emoji.is_empty() {
            return Some(flag.emoji);
        }
    }
    country_code_to_flag(country_code)
}
