use proxy_core::paths::config_dir;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;

pub struct SingleInstanceLock {
    #[allow(dead_code)]
    file: File,
    #[allow(dead_code)]
    path: PathBuf,
}

impl SingleInstanceLock {
    pub fn acquire() -> Result<Self, String> {
        let dir = config_dir().map_err(|error| error.to_string())?;
        fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
        let path = dir.join("desktop.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| format!("failed to open instance lock {}: {error}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                return Err(match error.raw_os_error() {
                    Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                        "socks5proxy-desktop is already running".to_string()
                    }
                    _ => format!("failed to acquire instance lock: {error}"),
                });
            }
        }

        Ok(Self { file, path })
    }
}
