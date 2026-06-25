//! Spawn the external `tun2proxy` binary with the args derived from a profile.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use crate::config::ResolvedProfile;
use crate::error::ProxyError;
use crate::tun::{effective_tun_profile, tun2proxy_args};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const BINARY_CANDIDATES: &[&str] = &["tun2proxy-bin", "tun2proxy"];
const PKEXEC_PATH: &str = "/usr/local/bin/tun2proxy-bin";

pub fn spawn(profile: &ResolvedProfile) -> Result<Child, ProxyError> {
    let effective = effective_tun_profile(profile);
    if effective.endpoint.host != profile.endpoint.host {
        tracing::info!(
            original_host = %profile.endpoint.host,
            resolved_host = %effective.endpoint.host,
            "resolved TUN upstream proxy host to direct IP before startup"
        );
    }
    let args = tun2proxy_args(&effective);

    // On current Linux tun2proxy builds, creating the TUN device is not the
    // only privileged operation: the process also performs TProxy/DNS setup
    // that still requires full root privileges. File capabilities alone are
    // therefore not sufficient for reliable non-root startup.
    if is_root() {
        for binary in direct_binary_candidates() {
            match Command::new(&binary).args(&args).spawn() {
                Ok(child) => {
                    tracing::info!(binary = %binary.display(), pid = child.id(), "spawned tun2proxy");
                    return Ok(child);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {}
            }
        }
    }

    // pkexec path: triggers the native desktop authentication dialog (polkit).
    // The policy installed by scripts/install-deps-linux.sh grants auth_admin_keep,
    // so the user is only prompted once per session.
    if Path::new(PKEXEC_PATH).is_file() {
        if let Some(pkexec) = which_binary("pkexec") {
            let mut cmd = Command::new(&pkexec);
            cmd.arg(PKEXEC_PATH).args(&args);
            #[cfg(unix)]
            cmd.process_group(0);
            match cmd.spawn() {
                Ok(child) => {
                    tracing::info!(pid = child.id(), "spawned tun2proxy via pkexec");
                    return Ok(child);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(ProxyError::Command(format!(
                        "failed to start tun2proxy-bin via pkexec: {error}"
                    )));
                }
            }
        }
    }

    // sudo -n fallback (non-interactive; requires a NOPASSWD sudoers rule).
    for binary in sudo_binary_candidates() {
        let mut cmd = Command::new("sudo");
        cmd.arg("-n").arg(&binary).args(&args);
        #[cfg(unix)]
        cmd.process_group(0);
        match cmd.spawn() {
            Ok(child) => {
                tracing::info!(binary = %binary.display(), pid = child.id(), "spawned tun2proxy via sudo -n");
                return Ok(child);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(ProxyError::Command(format!(
                    "failed to start {} via sudo: {error}",
                    binary.display()
                )));
            }
        }
    }

    let hint = if direct_binary_candidates()
        .iter()
        .any(|binary| binary_has_caps(binary))
    {
        "tun2proxy-bin is installed, but this Linux path still needs pkexec or sudo because tun2proxy performs privileged TProxy setup after startup."
    } else {
        "tun2proxy-bin not found or could not start. Run the install script (scripts/install-deps-linux.sh) to install it and grant privileges."
    };

    Err(ProxyError::Command(hint.into()))
}

pub fn resolve_tun2proxy_binary() -> Option<PathBuf> {
    direct_binary_candidates().into_iter().next()
}

/// Returns true when the process is running as root.
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: geteuid() is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Returns true when the named binary has file capabilities set (e.g. via setcap).
/// If the binary has cap_net_admin it can create TUN devices without sudo.
fn binary_has_caps(path: &Path) -> bool {
    // Try getcap first — it is available on any system with libcap-utils installed.
    if let Ok(out) = Command::new("getcap").arg(path).output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        return stdout.contains("cap_net_admin");
    }

    // Fallback: read the security.capability extended attribute directly.
    #[cfg(unix)]
    {
        use std::ffi::CString;
        if let Ok(cpath) = CString::new(path.as_os_str().as_encoded_bytes()) {
            let attr_name = c"security.capability";
            let mut buf = [0u8; 40];
            let ret = unsafe {
                libc::getxattr(
                    cpath.as_ptr(),
                    attr_name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            return ret > 0;
        }
    }

    false
}

fn direct_binary_candidates() -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    // Prefer the privileged copy installed by scripts/install-deps-linux.sh.
    push_candidate(&mut candidates, &mut seen, PathBuf::from(PKEXEC_PATH));

    for binary in BINARY_CANDIDATES {
        if let Some(path) = which_binary(binary) {
            push_candidate(&mut candidates, &mut seen, path);
        }
    }

    candidates
}

fn sudo_binary_candidates() -> Vec<PathBuf> {
    direct_binary_candidates()
}

fn push_candidate(candidates: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, path: PathBuf) {
    if !path.is_file() {
        return;
    }
    if seen.insert(path.clone()) {
        candidates.push(path);
    }
}

fn which_binary(binary: &str) -> Option<PathBuf> {
    if binary.contains('/') {
        return Some(PathBuf::from(binary));
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).find_map(|dir| {
            let full = dir.join(binary);
            if full.is_file() {
                Some(full)
            } else {
                None
            }
        })
    })
}
