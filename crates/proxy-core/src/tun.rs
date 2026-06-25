use std::collections::BTreeSet;
use std::net::ToSocketAddrs;

use sha2::{Digest, Sha256};

use crate::config::ResolvedProfile;
use crate::proxy_url::socks5_url;

pub fn effective_tun_profile(profile: &ResolvedProfile) -> ResolvedProfile {
    let mut effective = profile.clone();
    let resolved_ips = resolve_proxy_endpoint_ips(profile);

    if let Some(first_ip) = resolved_ips.first() {
        effective.endpoint.host = first_ip.clone();
    }

    let mut bypasses = BTreeSet::new();
    for bypass in &profile.bypass {
        bypasses.insert(bypass.clone());
    }
    for ip in resolved_ips {
        bypasses.insert(ip);
    }
    effective.bypass = bypasses.into_iter().collect();
    effective
}

pub fn tun2proxy_args(profile: &ResolvedProfile) -> Vec<String> {
    let mut args = vec![
        "--tun".to_string(),
        tun_device_name(&profile.id),
        "--setup".to_string(),
        "--proxy".to_string(),
        socks5_url(&profile.endpoint),
        "--dns".to_string(),
        if profile.proxy_dns {
            "virtual".to_string()
        } else {
            "direct".to_string()
        },
    ];

    for bypass in &profile.bypass {
        args.push("--bypass".to_string());
        args.push(bypass.clone());
    }

    args
}

fn resolve_proxy_endpoint_ips(profile: &ResolvedProfile) -> Vec<String> {
    let mut ips = BTreeSet::new();
    if let Ok(addrs) = (profile.endpoint.host.as_str(), profile.endpoint.port).to_socket_addrs() {
        for addr in addrs {
            ips.insert(addr.ip().to_string());
        }
    }
    ips.into_iter().collect()
}

/// Derive a stable, collision-resistant TUN device name from a profile id.
///
/// The previous implementation took the first 10 alphanumeric characters of
/// `profile_id`, which made profiles whose ids only differed past character 10
/// (or in non-alphanumeric characters) collapse onto the same interface name.
/// We now hash the full id and use the first 10 hex characters of the digest;
/// the resulting name (prefix `s5p` + 10 hex) is 13 characters, well within the
/// Linux IFNAMSIZ limit of 15.
pub fn tun_device_name(profile_id: &str) -> String {
    if profile_id.is_empty() {
        return "s5pdefault".to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(profile_id.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(5).map(|b| format!("{b:02x}")).collect();
    format!("s5p{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyEndpoint, ResolvedProfile, RoutingMode};

    fn sample_profile(id: &str) -> ResolvedProfile {
        ResolvedProfile {
            id: id.to_string(),
            name: "Primary".to_string(),
            endpoint: ProxyEndpoint {
                host: "proxy.example".to_string(),
                port: 1080,
                username: Some("user".to_string()),
                password: Some("secret".to_string()),
            },
            routing_mode: RoutingMode::Tun,
            proxy_dns: true,
            startup_cleanup_enabled: true,
            bypass: vec!["203.0.113.0/24".to_string()],
        }
    }

    #[test]
    fn builds_tun2proxy_arguments() {
        let profile = sample_profile("profile-a");
        let args = tun2proxy_args(&profile);
        assert_eq!(args[0], "--tun");
        assert!(args[1].starts_with("s5p"));
        assert_eq!(args[1].len(), 13);
        assert_eq!(args[2], "--setup");
        assert_eq!(args[3], "--proxy");
        assert_eq!(args[4], "socks5://user:secret@proxy.example:1080");
        assert_eq!(args[5], "--dns");
        assert_eq!(args[6], "virtual");
        assert_eq!(args[7], "--bypass");
        assert_eq!(args[8], "203.0.113.0/24");
    }

    #[test]
    fn effective_tun_profile_adds_proxy_ip_bypass_for_literal_hosts() {
        let profile = sample_profile("profile-a");
        let effective = effective_tun_profile(&ResolvedProfile {
            endpoint: ProxyEndpoint {
                host: "203.0.113.10".to_string(),
                port: 1080,
                username: Some("user".to_string()),
                password: Some("secret".to_string()),
            },
            ..profile
        });
        assert_eq!(effective.endpoint.host, "203.0.113.10");
        assert!(effective.bypass.iter().any(|entry| entry == "203.0.113.10"));
        assert!(effective
            .bypass
            .iter()
            .any(|entry| entry == "203.0.113.0/24"));
    }

    #[test]
    fn derives_stable_tun_device_name() {
        let a = tun_device_name("profile-a");
        let a_again = tun_device_name("profile-a");
        assert_eq!(a, a_again);
        assert!(a.starts_with("s5p"));
        assert_eq!(a.len(), 13);
        assert_eq!(tun_device_name(""), "s5pdefault");
    }

    #[test]
    fn distinct_profile_ids_yield_distinct_devices() {
        // Two ids that the legacy implementation would have collapsed.
        let a = tun_device_name("profile-12345abcdeXYZ");
        let b = tun_device_name("profile-12345abcdeZYX");
        assert_ne!(a, b, "hashed names must differ for distinct profile ids");
    }

    #[test]
    fn fits_linux_ifname_size_limit() {
        let name = tun_device_name(&"x".repeat(200));
        assert!(name.len() <= 15);
    }
}
