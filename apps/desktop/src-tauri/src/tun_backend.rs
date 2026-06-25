use proxy_core::{NamespaceSessionStatus, ResolvedProfile};

#[cfg(target_os = "windows")]
pub fn start(profile: ResolvedProfile) -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_platform_windows::start_tun_session(&profile)
}

#[cfg(not(target_os = "windows"))]
pub fn start(profile: ResolvedProfile) -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_core::daemon_tun_start(profile)
}

#[cfg(target_os = "windows")]
pub fn stop() -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_platform_windows::stop_tun_session()
}

#[cfg(not(target_os = "windows"))]
pub fn stop() -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_core::daemon_tun_stop()
}

#[cfg(target_os = "windows")]
pub fn status() -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_platform_windows::tun_status()
}

#[cfg(not(target_os = "windows"))]
pub fn status() -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_core::daemon_tun_status()
}

#[cfg(target_os = "windows")]
pub fn recover() -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_platform_windows::recover_tun_state()
}

#[cfg(not(target_os = "windows"))]
pub fn recover() -> proxy_core::Result<NamespaceSessionStatus> {
    proxy_core::daemon_recover()
}
