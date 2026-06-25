#[cfg(target_os = "windows")]
mod imp {
    use proxy_core::paths::runtime_marker_dir;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub struct TunRecoveryWatchdog {
        child: Child,
        cancel_file: PathBuf,
    }

    impl TunRecoveryWatchdog {
        pub fn arm(tun_device: &str) -> Result<Self, String> {
            let script = resolve_watchdog_script_path()?;
            let dir = recovery_runtime_dir()?;
            fs::create_dir_all(&dir).map_err(|error| {
                format!(
                    "failed to create Windows recovery runtime directory '{}': {error}",
                    dir.display()
                )
            })?;

            let stamp = unique_stamp();
            let cancel_file = dir.join(format!("watchdog-cancel-{stamp}.txt"));
            let log_file = dir.join(format!("watchdog-{stamp}.log"));
            let parent_pid = std::process::id();

            let mut child = Command::new("powershell.exe");
            child
                .args(watchdog_invocation_args(
                    &script,
                    parent_pid,
                    &cancel_file,
                    tun_device,
                    &log_file,
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW);

            let mut child = child.spawn().map_err(|error| {
                format!(
                    "failed to start Windows recovery watchdog via '{}': {error}",
                    script.display()
                )
            })?;

            std::thread::sleep(std::time::Duration::from_millis(250));
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("failed to inspect Windows recovery watchdog: {error}"))?
            {
                return Err(format!(
                    "Windows recovery watchdog exited early with status {status}. Check '{}'.",
                    log_file.display()
                ));
            }

            Ok(Self { child, cancel_file })
        }

        pub fn cancel(mut self) -> Result<(), String> {
            fs::write(&self.cancel_file, unique_stamp()).map_err(|error| {
                format!(
                    "failed to write Windows recovery watchdog cancel file '{}': {error}",
                    self.cancel_file.display()
                )
            })?;

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Some(status) = self.child.try_wait().map_err(|error| {
                    format!("failed to inspect Windows recovery watchdog during cancel: {error}")
                })? {
                    tracing::debug!(%status, "Windows recovery watchdog exited after cancel");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }

            let _ = fs::remove_file(&self.cancel_file);
            Ok(())
        }
    }

    fn unique_stamp() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{nanos:x}")
    }

    fn recovery_runtime_dir() -> Result<PathBuf, String> {
        runtime_marker_dir()
            .map(|path| path.join("windows-recovery"))
            .map_err(|error| error.to_string())
    }

    fn resolve_watchdog_script_path() -> Result<PathBuf, String> {
        for candidate in watchdog_script_candidates() {
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(format!(
            "could not locate Windows recovery watchdog script '{}'",
            watchdog_script_relative_path().display()
        ))
    }

    fn watchdog_script_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();

        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                candidates.push(exe_dir.join(watchdog_script_relative_path()));
                candidates.push(exe_dir.join("watch-tun-recovery-windows.ps1"));
            }
        }

        if let Ok(current_dir) = std::env::current_dir() {
            candidates.push(
                current_dir
                    .join("scripts")
                    .join("watch-tun-recovery-windows.ps1"),
            );
        }

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        candidates.push(
            manifest_dir
                .parent()
                .and_then(Path::parent)
                .map(|root| root.join("scripts").join("watch-tun-recovery-windows.ps1"))
                .unwrap_or_else(|| manifest_dir.join("watch-tun-recovery-windows.ps1")),
        );

        candidates
    }

    fn watchdog_script_relative_path() -> PathBuf {
        PathBuf::from("recovery")
            .join("windows")
            .join("watch-tun-recovery-windows.ps1")
    }

    fn watchdog_invocation_args(
        script: &Path,
        parent_pid: u32,
        cancel_file: &Path,
        tun_device: &str,
        log_file: &Path,
    ) -> Vec<String> {
        vec![
            "-NoProfile".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-File".to_string(),
            script.display().to_string(),
            "-ParentPid".to_string(),
            parent_pid.to_string(),
            "-CancelFile".to_string(),
            cancel_file.display().to_string(),
            "-TunAdapterName".to_string(),
            tun_device.to_string(),
            "-LogPath".to_string(),
            log_file.display().to_string(),
        ]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn watchdog_invocation_passes_expected_arguments() {
            let args = watchdog_invocation_args(
                Path::new("C:\\tool\\watch-tun-recovery-windows.ps1"),
                4321,
                Path::new("C:\\state\\cancel.txt"),
                "s5pdeadbeef",
                Path::new("C:\\state\\watchdog.log"),
            );

            assert!(args.windows(2).any(|pair| pair == ["-ParentPid", "4321"]));
            assert!(args
                .windows(2)
                .any(|pair| pair == ["-TunAdapterName", "s5pdeadbeef"]));
            assert!(args
                .windows(2)
                .any(|pair| pair == ["-CancelFile", "C:\\state\\cancel.txt"]));
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::TunRecoveryWatchdog;
