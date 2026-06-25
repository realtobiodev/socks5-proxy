//! Shared filesystem locations and helpers for secrets-on-disk handling.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::AppConfig;
use crate::error::ProxyError;

pub const CONFIG_FILE_NAME: &str = "config.toml";
pub const RUNTIME_STATE_FILE: &str = "runtime-state.toml";
pub const SYSTEM_PROXY_SNAPSHOT_FILE: &str = "system-proxy-snapshot.toml";
pub const RUNTIME_MARKER_DIR: &str = "runtime";

pub fn config_dir() -> Result<PathBuf, ProxyError> {
    let path = AppConfig::config_path()?;
    path.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ProxyError::Invalid("config path has no parent directory".into()))
}

pub fn runtime_state_path() -> Result<PathBuf, ProxyError> {
    Ok(config_dir()?.join(RUNTIME_STATE_FILE))
}

pub fn system_proxy_snapshot_path() -> Result<PathBuf, ProxyError> {
    Ok(config_dir()?.join(SYSTEM_PROXY_SNAPSHOT_FILE))
}

pub fn runtime_marker_dir() -> Result<PathBuf, ProxyError> {
    Ok(config_dir()?.join(RUNTIME_MARKER_DIR))
}

/// Write a file containing sensitive data with restrictive permissions.
///
/// On Unix the file is created with mode 0600 via `OpenOptions::mode`. On
/// Windows the default ACL inherited from the user's profile directory is
/// already restrictive; we still write atomically via temp + rename.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp = path.with_extension("tmp");
    {
        let mut file = open_secret(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp, path)?;
    Ok(())
}

#[cfg(unix)]
fn open_secret(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_secret(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

/// `unlink` a file, treating "not found" as success.
pub fn remove_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_secret_file_sets_0600() {
        let dir = std::env::temp_dir().join(format!("socks5proxy-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("secret.txt");
        let _ = fs::remove_file(&path);

        write_secret_file(&path, b"hello").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
