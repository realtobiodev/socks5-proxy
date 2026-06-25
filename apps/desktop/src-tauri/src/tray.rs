//! Tray icon rendering and status text updates.

use proxy_core::RoutingMode;
use tauri::image::Image;
use tauri::AppHandle;

use crate::types::consts::TRAY_ID;
use crate::types::{ConnectionState, RuntimeSnapshot, TrayConnectionState, TrayHandles};

pub fn update_tray_ui(app: &AppHandle, tray: &TrayHandles, runtime: &RuntimeSnapshot) {
    let connection_state = match runtime.connection_state {
        ConnectionState::Connected => TrayConnectionState::Connected,
        ConnectionState::Blocked => TrayConnectionState::Blocked,
        ConnectionState::Error => TrayConnectionState::Error,
        ConnectionState::Rebinding => TrayConnectionState::Blocked,
        ConnectionState::Stopped => TrayConnectionState::Disconnected,
    };

    let profile_name = runtime
        .active_profile_name
        .as_deref()
        .or(runtime.last_profile_name.as_deref())
        .unwrap_or("no profile");

    let status_text = match runtime.connection_state {
        ConnectionState::Connected => format!("Status: Connected ({})", profile_name),
        ConnectionState::Blocked => {
            format!("Status: Blocked waiting for VPN ({})", profile_name)
        }
        ConnectionState::Rebinding => {
            format!("Status: Rebinding after VPN change ({})", profile_name)
        }
        ConnectionState::Error => format!(
            "Status: Error ({}) ({})",
            runtime.last_error.as_deref().unwrap_or("unknown error"),
            profile_name
        ),
        ConnectionState::Stopped => format!("Status: Disconnected ({})", profile_name),
    };

    let exit_text = match (
        &runtime.exit_status.country_flag,
        &runtime.exit_status.exit_ip,
    ) {
        (Some(flag), Some(ip)) => format!("Exit IP: {flag} {ip}"),
        (None, Some(ip)) => format!("Exit IP: {ip}"),
        _ => {
            if let Some(error) = runtime.exit_status.lookup_error.as_deref() {
                format!("Exit IP: lookup failed ({error})")
            } else {
                "Exit IP: —".to_string()
            }
        }
    };

    let is_active = matches!(
        runtime.connection_state,
        ConnectionState::Connected | ConnectionState::Blocked | ConnectionState::Rebinding
    );
    let action_text = if is_active { "Disconnect" } else { "Connect" };

    let tooltip = {
        let mut lines = vec!["SOCKS5 Proxy".to_string(), status_text.clone()];
        if let Some(port) = runtime.local_system_proxy_port {
            lines.push(format!("Local adapter: 127.0.0.1:{port}"));
        }
        if let Some(ip) = &runtime.exit_status.exit_ip {
            let flag_prefix = runtime
                .exit_status
                .country_flag
                .as_deref()
                .map(|f| format!("{f} "))
                .unwrap_or_default();
            lines.push(format!("Exit: {flag_prefix}{ip}"));
        }
        if let Some(reason) = &runtime.vpn_status.last_reason {
            lines.push(format!("VPN: {reason}"));
        }
        if let Some(error) = &runtime.last_error {
            lines.push(format!("Error: {error}"));
        }
        lines.join("\n")
    };

    let _ = tray.status_item.set_text(&status_text);
    let _ = tray.exit_item.set_text(&exit_text);
    let _ = tray.action_item.set_text(action_text);
    let _ = tray.action_item.set_enabled(true);

    if let Some(tray_icon) = app.tray_by_id(TRAY_ID) {
        let system_warning = runtime.connection_state == ConnectionState::Connected
            && runtime.routing_mode == Some(RoutingMode::System);

        // Windows can't render flag emoji, so there we composite a raster country
        // flag with a status dot (falling back to the plain colored circle when the
        // exit country is unknown). Other platforms render flag emoji natively via
        // the tray title label below, so they keep the plain status circle here.
        #[cfg(target_os = "windows")]
        let icon = runtime
            .exit_status
            .country_code
            .as_deref()
            .and_then(|cc| flag_status_icon(connection_state, cc))
            .unwrap_or_else(|| connection_icon(connection_state, system_warning));
        #[cfg(not(target_os = "windows"))]
        let icon = connection_icon(connection_state, system_warning);

        let _ = tray_icon.set_icon(Some(icon));
        // Prefer the precomputed indicator text, which honors the configured display
        // mode (flag vs IP prefix). Fall back to the raw flag/IP only when it is absent.
        let title = runtime
            .exit_status
            .tray_text
            .as_deref()
            .or(runtime.exit_status.country_flag.as_deref())
            .or(runtime.exit_status.exit_ip.as_deref());
        let _ = tray_icon.set_title(title);
        let _ = tray_icon.set_tooltip(Some(tooltip));
    }
}

pub fn connection_icon(state: TrayConnectionState, show_warning: bool) -> Image<'static> {
    let (r, g, b) = match state {
        TrayConnectionState::Disconnected => (173_u8, 51_u8, 74_u8),
        TrayConnectionState::Connected => (20_u8, 127_u8, 91_u8),
        TrayConnectionState::Blocked => (200_u8, 104_u8, 27_u8),
        TrayConnectionState::Error => (138_u8, 41_u8, 68_u8),
    };

    let size = 16_u32;
    let mut rgba = vec![0_u8; (size * size * 4) as usize];
    let center = (size as f32 - 1.0) / 2.0;
    let radius = center - 1.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let distance = (dx * dx + dy * dy).sqrt();
            let offset = ((y * size + x) * 4) as usize;

            if distance <= radius {
                rgba[offset] = r;
                rgba[offset + 1] = g;
                rgba[offset + 2] = b;
                rgba[offset + 3] = 255;
            } else if distance <= radius + 0.7 {
                rgba[offset] = r / 2;
                rgba[offset + 1] = g / 2;
                rgba[offset + 2] = b / 2;
                rgba[offset + 3] = 160;
            }
        }
    }

    if show_warning {
        draw_warning_overlay(&mut rgba, size);
    }

    Image::new_owned(rgba, size, size)
}

/// Status-dot color for the tray, reused for the flag overlay: green when
/// connected, orange while blocked/rebinding, red otherwise. Windows-only — other
/// platforms render flag emoji in the tray title and keep the plain status circle.
#[cfg(target_os = "windows")]
fn status_dot_color(state: TrayConnectionState) -> (u8, u8, u8) {
    match state {
        TrayConnectionState::Connected => (20, 127, 91),
        TrayConnectionState::Blocked => (200, 104, 27),
        TrayConnectionState::Error => (138, 41, 68),
        TrayConnectionState::Disconnected => (173, 51, 74),
    }
}

/// Build a tray icon from the embedded country flag with a status dot in the
/// bottom-right corner, so a glance shows both the exit country and whether the
/// connection is up (green) or not (red/orange). Returns `None` when no flag asset
/// exists for `country_code`, letting the caller fall back to the plain circle.
#[cfg(target_os = "windows")]
fn flag_status_icon(state: TrayConnectionState, country_code: &str) -> Option<Image<'static>> {
    let size = crate::flags::FLAG_RGBA_SIZE;
    let src = crate::flags::flag_rgba(&country_code.to_ascii_lowercase())?;
    if src.len() != (size * size * 4) as usize {
        return None;
    }
    let mut rgba = src.to_vec();

    let (r, g, b) = status_dot_color(state);
    // Dot centered near the bottom-right corner.
    let cx = size as f32 - 8.0;
    let cy = size as f32 - 8.0;
    let dot_radius = 6.5_f32;
    let ring_radius = dot_radius + 1.6; // white border for contrast on any flag

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let distance = (dx * dx + dy * dy).sqrt();
            let offset = ((y * size + x) * 4) as usize;
            if distance <= dot_radius {
                rgba[offset] = r;
                rgba[offset + 1] = g;
                rgba[offset + 2] = b;
                rgba[offset + 3] = 255;
            } else if distance <= ring_radius {
                rgba[offset] = 255;
                rgba[offset + 1] = 255;
                rgba[offset + 2] = 255;
                rgba[offset + 3] = 255;
            }
        }
    }

    Some(Image::new_owned(rgba, size, size))
}

fn draw_warning_overlay(rgba: &mut [u8], size: u32) {
    let overlay_x = size.saturating_sub(6);
    let overlay_y = 1_u32;

    for y in overlay_y..(overlay_y + 5).min(size) {
        for x in overlay_x..(overlay_x + 5).min(size) {
            let offset = ((y * size + x) * 4) as usize;
            rgba[offset] = 245;
            rgba[offset + 1] = 190;
            rgba[offset + 2] = 64;
            rgba[offset + 3] = 255;
        }
    }

    for y in (overlay_y + 1)..(overlay_y + 4).min(size) {
        let x = overlay_x + 2;
        if x < size {
            let offset = ((y * size + x) * 4) as usize;
            rgba[offset] = 78;
            rgba[offset + 1] = 44;
            rgba[offset + 2] = 8;
            rgba[offset + 3] = 255;
        }
    }

    if overlay_x + 2 < size && overlay_y + 4 < size {
        let offset = (((overlay_y + 4) * size + (overlay_x + 2)) * 4) as usize;
        rgba[offset] = 78;
        rgba[offset + 1] = 44;
        rgba[offset + 2] = 8;
        rgba[offset + 3] = 255;
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn embeds_known_country_flags() {
        let size = (crate::flags::FLAG_RGBA_SIZE * crate::flags::FLAG_RGBA_SIZE * 4) as usize;
        for cc in ["fr", "us", "de"] {
            let bytes = crate::flags::flag_rgba(cc).expect("flag present");
            assert_eq!(bytes.len(), size, "flag {cc} must be 32x32 RGBA");
        }
        assert!(crate::flags::flag_rgba("zz").is_none(), "unknown code -> None");
        // Resolver lowercases, so an upper-case code still resolves.
        assert!(crate::flags::flag_rgba(&"FR".to_ascii_lowercase()).is_some());
    }

    #[test]
    fn flag_status_icon_composites_for_known_country() {
        assert!(flag_status_icon(TrayConnectionState::Connected, "fr").is_some());
        assert!(flag_status_icon(TrayConnectionState::Connected, "ZZ").is_none());
    }
}
