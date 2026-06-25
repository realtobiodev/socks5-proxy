//! Read sensitive values (passwords) from sources other than command-line arguments.

use std::fs;
use std::io::{self, BufRead, IsTerminal};
use std::path::Path;

use crate::error::ProxyError;

/// Read a password from stdin. Reads the first non-empty line and trims trailing newlines.
///
/// Refuses to read if stdin is a TTY — interactive prompting is the caller's responsibility.
pub fn read_password_from_stdin() -> Result<String, ProxyError> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(ProxyError::Invalid(
            "stdin is a terminal; pipe a password or use --password-file".into(),
        ));
    }
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(ProxyError::Invalid(
            "stdin produced an empty password".into(),
        ));
    }
    Ok(trimmed)
}

/// Read a password from a file. The first line is used (trailing newlines stripped).
pub fn read_password_from_file(path: &Path) -> Result<String, ProxyError> {
    let text = fs::read_to_string(path).map_err(ProxyError::Io)?;
    let first = text
        .lines()
        .next()
        .ok_or_else(|| ProxyError::Invalid(format!("password file {} is empty", path.display())))?;
    let trimmed = first.trim().to_string();
    if trimmed.is_empty() {
        return Err(ProxyError::Invalid(format!(
            "password file {} contained only whitespace",
            path.display()
        )));
    }
    Ok(trimmed)
}
