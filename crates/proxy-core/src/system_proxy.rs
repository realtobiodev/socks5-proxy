//! System proxy manipulation, shared by CLI and desktop.
//!
//! Snapshots can be persisted to disk so that the user's previous settings can be
//! restored after a crash (see [`save_snapshot`] / [`take_persisted_snapshot`]).

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::config::ResolvedProfile;
use crate::error::ProxyError;
use crate::local_socks::{LOCAL_SOCKS_HOST, LOCAL_SOCKS_PORT};
use crate::validate::validate_host;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SystemProxySnapshot {
    pub entries: Vec<(String, Option<String>)>,
}

pub fn compatibility_warning(profile: &ResolvedProfile) -> Option<String> {
    platform::compatibility_warning(profile)
}

pub fn enable(profile: &ResolvedProfile) -> Result<SystemProxySnapshot, ProxyError> {
    validate_host(&profile.endpoint.host)?;
    if let Some(message) = compatibility_warning(profile) {
        return Err(ProxyError::Invalid(message));
    }
    platform::enable(profile)
}

pub fn restore(snapshot: SystemProxySnapshot) -> Result<(), ProxyError> {
    platform::restore(snapshot)
}

fn command_output(command: &mut Command) -> Result<String, ProxyError> {
    let output = command.output().map_err(ProxyError::Io)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ProxyError::Command(stderr.trim().to_string()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "linux")]
fn command_output_trimmed(command: &mut Command) -> Result<String, ProxyError> {
    command_output(command).map(|s| s.trim().to_string())
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::ptr::null_mut;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };

    pub fn compatibility_warning(_profile: &ResolvedProfile) -> Option<String> {
        None
    }

    pub(super) const KEY: &str =
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    pub fn enable(_profile: &ResolvedProfile) -> Result<SystemProxySnapshot, ProxyError> {
        let snapshot = snapshot();
        set_reg_dword("ProxyEnable", "1")?;
        // Point Windows' system proxy at the embedded local SOCKS adapter, which
        // authenticates to the upstream on our behalf. WinINET's built-in SOCKS
        // support cannot do username/password auth, so pointing it straight at an
        // authenticated upstream would fail — mirror the Linux gsettings path.
        set_reg_sz(
            "ProxyServer",
            &format!("socks={LOCAL_SOCKS_HOST}:{LOCAL_SOCKS_PORT}"),
        )?;
        notify_proxy_settings_changed();
        Ok(snapshot)
    }

    pub fn restore(snapshot: SystemProxySnapshot) -> Result<(), ProxyError> {
        for (name, value) in snapshot.entries {
            match (name.as_str(), value) {
                ("ProxyEnable", Some(value)) => set_reg_dword("ProxyEnable", &value)?,
                ("ProxyEnable", None) => set_reg_dword("ProxyEnable", "0")?,
                ("ProxyServer", Some(value)) => set_reg_sz("ProxyServer", &value)?,
                ("ProxyServer", None) => delete_reg_value("ProxyServer")?,
                _ => {}
            }
        }
        notify_proxy_settings_changed();
        Ok(())
    }

    fn snapshot() -> SystemProxySnapshot {
        SystemProxySnapshot {
            entries: vec![
                ("ProxyEnable".to_string(), query_reg_value("ProxyEnable")),
                ("ProxyServer".to_string(), query_reg_value("ProxyServer")),
            ],
        }
    }

    fn query_reg_value(name: &str) -> Option<String> {
        let output = Command::new("reg")
            .args(["query", KEY, "/v", name])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        parse_reg_query(&text, name)
    }

    fn set_reg_dword(name: &str, value: &str) -> Result<(), ProxyError> {
        command_output(Command::new("reg").arg("add").arg(KEY).args([
            "/v",
            name,
            "/t",
            "REG_DWORD",
            "/d",
            value,
            "/f",
        ]))
        .map(|_| ())
    }

    fn set_reg_sz(name: &str, value: &str) -> Result<(), ProxyError> {
        command_output(
            Command::new("reg")
                .arg("add")
                .arg(KEY)
                .args(["/v", name, "/t", "REG_SZ", "/d", value, "/f"]),
        )
        .map(|_| ())
    }

    fn delete_reg_value(name: &str) -> Result<(), ProxyError> {
        let _ = Command::new("reg")
            .arg("delete")
            .arg(KEY)
            .args(["/v", name, "/f"])
            .output();
        Ok(())
    }

    fn notify_proxy_settings_changed() {
        // WinINET consumers cache proxy settings. These notifications tell already
        // running apps to re-read HKCU Internet Settings after we changed them.
        unsafe {
            let _ = InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0);
            let _ = InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0);
        }
    }

    /// Parse the human-readable `reg query` output and return the value.
    ///
    /// `reg query` emits a line such as
    /// `    ProxyServer    REG_SZ    socks=proxy host:1080`
    /// where the value can contain whitespace. Splitting by `split_whitespace().last()`
    /// truncates such values, hence the manual parser.
    pub(super) fn parse_reg_query(text: &str, name: &str) -> Option<String> {
        for line in text.lines() {
            let line = line.trim_start();
            if !line.starts_with(name) {
                continue;
            }
            let rest = line[name.len()..].trim_start();
            // Match the type token (REG_SZ, REG_DWORD, REG_EXPAND_SZ, ...).
            let (kind, value) = rest.split_once(char::is_whitespace)?;
            if !kind.starts_with("REG_") {
                continue;
            }
            return Some(value.trim().to_string());
        }
        None
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn compatibility_warning(_profile: &ResolvedProfile) -> Option<String> {
        None
    }

    pub fn enable(_profile: &ResolvedProfile) -> Result<SystemProxySnapshot, ProxyError> {
        ensure_gsettings()?;
        let snapshot = snapshot();

        set("org.gnome.system.proxy", "mode", "'manual'")?;
        set(
            "org.gnome.system.proxy.socks",
            "host",
            &format!("'{LOCAL_SOCKS_HOST}'"),
        )?;
        set(
            "org.gnome.system.proxy.socks",
            "port",
            &LOCAL_SOCKS_PORT.to_string(),
        )?;

        Ok(snapshot)
    }

    pub fn restore(snapshot: SystemProxySnapshot) -> Result<(), ProxyError> {
        ensure_gsettings()?;
        for (key, value) in snapshot.entries {
            let Some((schema, name)) = key.split_once('|') else {
                continue;
            };

            match value {
                Some(value) => {
                    set(schema, name, &value)?;
                }
                None => {
                    // Only reset if we previously could not read a value, which on a stock
                    // GNOME install does not happen; better to leave it alone than to
                    // clobber user state.
                    tracing::warn!(
                        "system_proxy: no previous value for {schema} {name}; skipping reset"
                    );
                }
            }
        }
        Ok(())
    }

    fn snapshot() -> SystemProxySnapshot {
        SystemProxySnapshot {
            entries: vec![
                entry("org.gnome.system.proxy", "mode"),
                entry("org.gnome.system.proxy.socks", "host"),
                entry("org.gnome.system.proxy.socks", "port"),
            ],
        }
    }

    fn ensure_gsettings() -> Result<(), ProxyError> {
        Command::new("gsettings")
            .arg("--version")
            .output()
            .map(|_| ())
            .map_err(|_| {
                ProxyError::Command(
                    "gsettings was not found; system proxy mode currently supports GNOME-compatible desktops on Linux".into(),
                )
            })
    }

    fn entry(schema: &str, name: &str) -> (String, Option<String>) {
        (
            format!("{schema}|{name}"),
            command_output_trimmed(Command::new("gsettings").args(["get", schema, name])).ok(),
        )
    }

    fn set(schema: &str, name: &str, value: &str) -> Result<(), ProxyError> {
        command_output(Command::new("gsettings").args(["set", schema, name, value])).map(|_| ())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::*;

    pub fn compatibility_warning(_profile: &ResolvedProfile) -> Option<String> {
        None
    }

    pub fn enable(_profile: &ResolvedProfile) -> Result<SystemProxySnapshot, ProxyError> {
        Err(ProxyError::Command(
            "system proxy mode is only implemented for Windows and Linux".into(),
        ))
    }

    pub fn restore(_snapshot: SystemProxySnapshot) -> Result<(), ProxyError> {
        Ok(())
    }
}

// --- Crash-recovery persistence -------------------------------------------------

use std::path::Path;

/// Persist a snapshot to disk so it can be restored after a crash.
pub fn save_snapshot(path: &Path, snapshot: &SystemProxySnapshot) -> Result<(), ProxyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let toml_text = toml::to_string(snapshot)?;
    crate::paths::write_secret_file(path, toml_text.as_bytes())?;
    Ok(())
}

/// Atomically take the persisted snapshot off disk (returning it if present).
pub fn take_persisted_snapshot(path: &Path) -> Result<Option<SystemProxySnapshot>, ProxyError> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path)?;
    let snapshot: SystemProxySnapshot = toml::from_str(&text)?;
    let _ = std::fs::remove_file(path);
    Ok(Some(snapshot))
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn parses_reg_query_with_spaces() {
        let text = "
            HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
                ProxyServer    REG_SZ    socks=proxy host:1080
                ProxyEnable    REG_DWORD    0x1
        ";
        assert_eq!(
            platform::parse_reg_query(text, "ProxyServer").as_deref(),
            Some("socks=proxy host:1080")
        );
        assert_eq!(
            platform::parse_reg_query(text, "ProxyEnable").as_deref(),
            Some("0x1")
        );
    }
}

#[cfg(test)]
mod common_tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use crate::{ProxyEndpoint, ResolvedProfile, RoutingMode};

    #[test]
    fn snapshot_roundtrips_via_toml() {
        let snapshot = SystemProxySnapshot {
            entries: vec![
                ("ProxyEnable".into(), Some("0x1".into())),
                ("ProxyServer".into(), Some("socks=proxy host:1080".into())),
            ],
        };
        let text = toml::to_string(&snapshot).unwrap();
        let parsed: SystemProxySnapshot = toml::from_str(&text).unwrap();
        assert_eq!(parsed.entries, snapshot.entries);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_system_proxy_accepts_authenticated_profiles() {
        let profile = ResolvedProfile {
            id: "profile-1".into(),
            name: "Test".into(),
            endpoint: ProxyEndpoint {
                host: "proxy.example".into(),
                port: 1080,
                username: Some("alice".into()),
                password: Some("secret".into()),
            },
            routing_mode: RoutingMode::System,
            proxy_dns: true,
            startup_cleanup_enabled: true,
            bypass: Vec::new(),
        };

        assert!(compatibility_warning(&profile).is_none());
    }
}
