use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DesktopAppEntry {
    pub id: String,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub icon: Option<String>,
}

pub fn discover_desktop_apps() -> std::io::Result<Vec<DesktopAppEntry>> {
    let mut apps = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for dir in desktop_entry_dirs() {
        collect_desktop_apps_from_dir(&dir, &mut seen, &mut apps)?;
    }
    apps.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
    Ok(apps)
}

fn desktop_entry_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = env::var_os("XDG_DATA_HOME") {
        dirs.push(PathBuf::from(home).join("applications"));
    } else if let Some(home) = env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }

    if let Some(value) = env::var_os("XDG_DATA_DIRS") {
        dirs.extend(env::split_paths(&value).map(|path| path.join("applications")));
    } else {
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        dirs.push(PathBuf::from("/usr/share/applications"));
    }
    dirs
}

fn collect_desktop_apps_from_dir(
    dir: &Path,
    seen: &mut std::collections::BTreeSet<String>,
    apps: &mut Vec<DesktopAppEntry>,
) -> std::io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_desktop_apps_from_dir(&path, seen, apps)?;
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("desktop") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let id = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("desktop-app")
            .to_string();
        if seen.contains(&id) {
            continue;
        }
        if let Some(app) = parse_desktop_entry(&id, &text) {
            seen.insert(id);
            apps.push(app);
        }
    }

    Ok(())
}

pub fn parse_desktop_entry(id: &str, input: &str) -> Option<DesktopAppEntry> {
    let mut in_desktop_entry = false;
    let mut fields = BTreeMap::new();

    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_desktop_entry = trimmed == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            fields
                .entry(key.to_string())
                .or_insert_with(|| value.to_string());
        }
    }

    if fields.get("Type").map(String::as_str) != Some("Application") {
        return None;
    }
    if is_desktop_true(fields.get("NoDisplay")) || is_desktop_true(fields.get("Hidden")) {
        return None;
    }
    let name = fields.get("Name")?.trim().to_string();
    let exec = fields.get("Exec")?;
    let (command, args) = parse_exec(exec)?;

    Some(DesktopAppEntry {
        id: id.to_string(),
        name,
        command,
        args,
        icon: fields
            .get("Icon")
            .filter(|value| !value.trim().is_empty())
            .cloned(),
    })
}

fn is_desktop_true(value: Option<&String>) -> bool {
    value
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn parse_exec(input: &str) -> Option<(String, Vec<String>)> {
    let tokens = shell_words(input);
    let mut cleaned = tokens
        .into_iter()
        .filter_map(|token| strip_field_codes(&token))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        return None;
    }
    let command = cleaned.remove(0);
    Some((command, cleaned))
}

fn strip_field_codes(token: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('%') => out.push('%'),
                Some(_) => {}
                None => out.push('%'),
            }
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars();
    let mut quote: Option<char> = None;

    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(_), c) => current.push(c),
            (None, '\'' | '"') => quote = Some(ch),
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_desktop_entry_and_strips_field_codes() {
        let app = parse_desktop_entry(
            "firefox.desktop",
            r#"
            [Desktop Entry]
            Type=Application
            Name=Firefox
            Exec=firefox --new-window %u
            Icon=firefox
            "#,
        )
        .unwrap();

        assert_eq!(app.name, "Firefox");
        assert_eq!(app.command, "firefox");
        assert_eq!(app.args, vec!["--new-window"]);
        assert_eq!(app.icon.as_deref(), Some("firefox"));
    }

    #[test]
    fn parses_quoted_exec_values() {
        let (command, args) = parse_exec(r#"/opt/App/app "--profile=Work Space" %% %F"#).unwrap();
        assert_eq!(command, "/opt/App/app");
        assert_eq!(args, vec!["--profile=Work Space", "%"]);
    }

    #[test]
    fn ignores_hidden_entries() {
        assert!(parse_desktop_entry(
            "hidden.desktop",
            "[Desktop Entry]\nType=Application\nName=Hidden\nExec=hidden\nNoDisplay=true\n",
        )
        .is_none());
    }
}
