//! Tiny shared helpers.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a `Command` that doesn't pop up a console window on Windows.
///
/// The release binary is a GUI-subsystem app (no console), so each child CLI
/// process would otherwise allocate its own console window and flash on screen.
/// CREATE_NO_WINDOW suppresses that. No-op on non-Windows.
pub fn console_hidden_command<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn generate_session_id() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("session-{stamp:x}")
}

pub fn country_code_to_flag(country_code: &str) -> Option<String> {
    let code = country_code.trim().to_ascii_uppercase();
    if code.len() != 2 || !code.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return None;
    }

    let mut output = String::new();
    for ch in code.chars() {
        let base = 0x1F1E6 + (ch as u32 - 'A' as u32);
        output.push(char::from_u32(base)?);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_code_to_flag_de() {
        assert_eq!(
            country_code_to_flag("DE").as_deref(),
            Some("\u{1F1E9}\u{1F1EA}")
        );
        assert_eq!(
            country_code_to_flag("de").as_deref(),
            Some("\u{1F1E9}\u{1F1EA}")
        );
        assert_eq!(
            country_code_to_flag(" us ").as_deref(),
            Some("\u{1F1FA}\u{1F1F8}")
        );
    }

    #[test]
    fn country_code_to_flag_rejects_invalid() {
        assert!(country_code_to_flag("").is_none());
        assert!(country_code_to_flag("X").is_none());
        assert!(country_code_to_flag("123").is_none());
        assert!(country_code_to_flag("DEU").is_none());
    }
}
