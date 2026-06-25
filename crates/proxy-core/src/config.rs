use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    System,
    Tun,
}

impl fmt::Display for RoutingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoutingMode::System => f.write_str("system"),
            RoutingMode::Tun => f.write_str("tun"),
        }
    }
}

impl FromStr for RoutingMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "system" => Ok(RoutingMode::System),
            "tun" => Ok(RoutingMode::Tun),
            other => Err(ConfigError::Invalid(format!(
                "unsupported routing_mode '{other}', expected 'system' or 'tun'"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_profiles")]
    pub profiles: Vec<ProxyProfile>,
    #[serde(default = "default_selected_profile_id")]
    pub selected_profile_id: Option<String>,
    #[serde(default = "default_active_profile_id")]
    pub active_profile_id: Option<String>,
    #[serde(default)]
    pub tray_settings: TraySettings,
    #[serde(default)]
    pub app_launchers: Vec<AppLauncher>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let profile = ProxyProfile::default_named("Default");
        let active_profile_id = Some(profile.id.clone());
        Self {
            enabled: false,
            profiles: vec![profile],
            selected_profile_id: active_profile_id.clone(),
            active_profile_id,
            tray_settings: TraySettings::default(),
            app_launchers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProxyProfile {
    pub id: String,
    pub name: String,
    pub target: StoredProxyTarget,
    pub routing_mode: RoutingMode,
    pub proxy_dns: bool,
    #[serde(default = "default_true")]
    pub startup_cleanup_enabled: bool,
    #[serde(default)]
    pub bypass: Vec<String>,
}

impl ProxyProfile {
    pub fn default_named(name: impl Into<String>) -> Self {
        Self {
            id: "profile-default".to_string(),
            name: name.into(),
            target: StoredProxyTarget::Structured(StructuredProxyTarget::default()),
            routing_mode: RoutingMode::Tun,
            proxy_dns: true,
            startup_cleanup_enabled: true,
            bypass: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "profile id must not be empty".to_string(),
            ));
        }
        if self.name.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "profile name must not be empty".to_string(),
            ));
        }

        match &self.target {
            StoredProxyTarget::Structured(target) => target.validate()?,
            StoredProxyTarget::RawImport(target) => target.validate()?,
        }

        Ok(())
    }

    pub fn canonicalize(&mut self) {
        match &mut self.target {
            StoredProxyTarget::Structured(target) => target.canonicalize(),
            StoredProxyTarget::RawImport(target) => target.canonicalize(),
        }
    }

    pub fn resolve(&self) -> Result<ResolvedProfile, ConfigError> {
        let endpoint = match &self.target {
            StoredProxyTarget::Structured(target) => target.resolve_endpoint()?,
            StoredProxyTarget::RawImport(target) => target.resolve_endpoint()?,
        };

        Ok(ResolvedProfile {
            id: self.id.clone(),
            name: self.name.clone(),
            endpoint,
            routing_mode: self.routing_mode.clone(),
            proxy_dns: self.proxy_dns,
            startup_cleanup_enabled: self.startup_cleanup_enabled,
            bypass: self.bypass.clone(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoredProxyTarget {
    Structured(StructuredProxyTarget),
    RawImport(RawImportTarget),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuredProxyTarget {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub credentials: Vec<CredentialEntry>,
    #[serde(default)]
    pub selected_credential_id: Option<String>,
}

impl Default for StructuredProxyTarget {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 1080,
            credentials: Vec::new(),
            selected_credential_id: None,
        }
    }
}

impl StructuredProxyTarget {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.host.trim().is_empty() {
            return Err(ConfigError::Invalid("host must not be empty".to_string()));
        }

        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "port must be between 1 and 65535".to_string(),
            ));
        }

        for credential in &self.credentials {
            credential.validate()?;
        }

        if let Some(selected) = &self.selected_credential_id {
            if !self
                .credentials
                .iter()
                .any(|credential| &credential.id == selected)
            {
                return Err(ConfigError::Invalid(format!(
                    "selected credential '{selected}' does not exist"
                )));
            }
        }

        Ok(())
    }

    fn canonicalize(&mut self) {
        for (index, credential) in self.credentials.iter_mut().enumerate() {
            if credential.id.trim().is_empty() {
                credential.id = generate_id("cred");
            }
            if credential.label.trim().is_empty() {
                credential.label = format!("Credential {}", index + 1);
            }
        }

        if self.selected_credential_id.is_none() && !self.credentials.is_empty() {
            self.selected_credential_id = Some(self.credentials[0].id.clone());
        }
    }

    fn resolve_endpoint(&self) -> Result<ProxyEndpoint, ConfigError> {
        let credential = self
            .selected_credential_id
            .as_ref()
            .and_then(|selected| self.credentials.iter().find(|item| &item.id == selected))
            .or_else(|| self.credentials.first());

        Ok(ProxyEndpoint {
            host: self.host.trim().to_string(),
            port: self.port,
            username: credential.map(|credential| credential.username.clone()),
            password: credential.map(|credential| credential.password.clone()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub username: String,
    pub password: String,
}

impl CredentialEntry {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "credential id must not be empty".to_string(),
            ));
        }
        if self.username.is_empty() {
            return Err(ConfigError::Invalid(
                "credential username must not be empty".to_string(),
            ));
        }
        if self.password.is_empty() {
            return Err(ConfigError::Invalid(
                "credential password must not be empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawImportTarget {
    #[serde(default)]
    pub entries: Vec<ImportedProxyEntry>,
    #[serde(default)]
    pub selected_entry_id: Option<String>,
}

impl RawImportTarget {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.entries.is_empty() {
            return Err(ConfigError::Invalid(
                "raw import target must contain at least one entry".to_string(),
            ));
        }

        for entry in &self.entries {
            entry.validate()?;
        }

        if let Some(selected) = &self.selected_entry_id {
            if !self.entries.iter().any(|entry| &entry.id == selected) {
                return Err(ConfigError::Invalid(format!(
                    "selected raw import entry '{selected}' does not exist"
                )));
            }
        }

        Ok(())
    }

    fn canonicalize(&mut self) {
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if entry.id.trim().is_empty() {
                entry.id = generate_id("entry");
            }
            if entry.label.trim().is_empty() {
                entry.label = format!("Credential {}", index + 1);
            }
        }

        if self.selected_entry_id.is_none() && !self.entries.is_empty() {
            self.selected_entry_id = Some(self.entries[0].id.clone());
        }
    }

    fn resolve_endpoint(&self) -> Result<ProxyEndpoint, ConfigError> {
        let entry = self
            .selected_entry_id
            .as_ref()
            .and_then(|selected| self.entries.iter().find(|item| &item.id == selected))
            .or_else(|| self.entries.first())
            .ok_or_else(|| {
                ConfigError::Invalid("raw import target does not contain any entries".to_string())
            })?;

        Ok(ProxyEndpoint {
            host: entry.host.trim().to_string(),
            port: entry.port,
            username: Some(entry.username.clone()),
            password: Some(entry.password.clone()),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImportedProxyEntry {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub username: String,
    pub password: String,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppLauncher {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub kind: AppLauncherKind,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl AppLauncher {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "app launcher id must not be empty".to_string(),
            ));
        }
        if self.label.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "app launcher label must not be empty".to_string(),
            ));
        }
        if self.command.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "app launcher command must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn canonicalize(&mut self) {
        if self.id.trim().is_empty() {
            self.id = generate_id("app");
        }
        if self.label.trim().is_empty() {
            self.label = self.command.clone();
        }
        self.command = self.command.trim().to_string();
        if self
            .working_dir
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            self.working_dir = None;
        }
        if self
            .icon
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            self.icon = None;
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppLauncherKind {
    Desktop,
    #[default]
    Manual,
}

impl ImportedProxyEntry {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "raw import entry id must not be empty".to_string(),
            ));
        }
        if self.username.is_empty() {
            return Err(ConfigError::Invalid(
                "raw import entry username must not be empty".to_string(),
            ));
        }
        if self.password.is_empty() {
            return Err(ConfigError::Invalid(
                "raw import entry password must not be empty".to_string(),
            ));
        }
        if self.host.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "raw import entry host must not be empty".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(ConfigError::Invalid(
                "raw import entry port must be between 1 and 65535".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraySettings {
    #[serde(default = "default_true")]
    pub exit_ip_lookup_enabled: bool,
    #[serde(default = "default_true")]
    pub geo_lookup_enabled: bool,
    #[serde(default)]
    pub display_mode: TrayDisplayMode,
    #[serde(default = "default_ip_prefix_segments")]
    pub ip_prefix_segments: u8,
    #[serde(default = "default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

impl Default for TraySettings {
    fn default() -> Self {
        Self {
            exit_ip_lookup_enabled: true,
            geo_lookup_enabled: true,
            display_mode: TrayDisplayMode::Flag,
            ip_prefix_segments: default_ip_prefix_segments(),
            refresh_interval_secs: default_refresh_interval_secs(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrayDisplayMode {
    #[default]
    Flag,
    IpPrefix,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedProfile {
    pub id: String,
    pub name: String,
    pub endpoint: ProxyEndpoint,
    pub routing_mode: RoutingMode,
    pub proxy_dns: bool,
    pub startup_cleanup_enabled: bool,
    pub bypass: Vec<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Invalid(String),
    TomlDeserialize(toml::de::Error),
    TomlSerialize(toml::ser::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(error) => write!(f, "{error}"),
            ConfigError::Invalid(message) => f.write_str(message),
            ConfigError::TomlDeserialize(error) => write!(f, "{error}"),
            ConfigError::TomlSerialize(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(value: std::io::Error) -> Self {
        ConfigError::Io(value)
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(value: toml::de::Error) -> Self {
        ConfigError::TomlDeserialize(value)
    }
}

impl From<toml::ser::Error> for ConfigError {
    fn from(value: toml::ser::Error) -> Self {
        ConfigError::TomlSerialize(value)
    }
}

impl AppConfig {
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let dir = config_dir()?.join("socks5proxy");
        Ok(dir.join("config.toml"))
    }

    pub fn load_default_path() -> Result<Self, ConfigError> {
        let path = Self::config_path()?;
        let text = fs::read_to_string(path)?;
        Self::from_toml(&text)
    }

    pub fn save_default_path(&self) -> Result<PathBuf, ConfigError> {
        let canonical = self.clone().canonicalized()?;
        let path = Self::config_path()?;
        let bytes = canonical.to_toml()?.into_bytes();
        crate::paths::write_secret_file(&path, &bytes)?;
        Ok(path)
    }

    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        toml::from_str::<Self>(input)
            .map_err(ConfigError::TomlDeserialize)?
            .canonicalized()
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(&self.clone().canonicalized()?)?)
    }

    pub fn canonicalized(mut self) -> Result<Self, ConfigError> {
        if self.profiles.is_empty() {
            self.profiles.push(ProxyProfile::default_named("Default"));
        }

        let is_single_profile = self.profiles.len() == 1;
        for (index, profile) in self.profiles.iter_mut().enumerate() {
            if profile.id.trim().is_empty() {
                profile.id = generate_id("profile");
            } else if index == 0 && profile.id == "profile-default" && is_single_profile {
                // Keep the default id stable for first-run configs.
            }
            profile.canonicalize();
        }

        for launcher in &mut self.app_launchers {
            launcher.canonicalize();
        }

        if self.active_profile_id.is_none() {
            self.active_profile_id = self.profiles.first().map(|profile| profile.id.clone());
        }
        if self.selected_profile_id.is_none() {
            self.selected_profile_id = self
                .active_profile_id
                .clone()
                .or_else(|| self.profiles.first().map(|profile| profile.id.clone()));
        }

        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.profiles.is_empty() {
            return Err(ConfigError::Invalid(
                "app config must contain at least one profile".to_string(),
            ));
        }

        let mut profile_ids = std::collections::BTreeSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            if !profile_ids.insert(profile.id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate profile id '{}'",
                    profile.id
                )));
            }
        }

        let mut launcher_ids = std::collections::BTreeSet::new();
        for launcher in &self.app_launchers {
            launcher.validate()?;
            if !launcher_ids.insert(launcher.id.clone()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate app launcher id '{}'",
                    launcher.id
                )));
            }
        }

        let selected_profile_id = self.selected_profile_id.as_ref().ok_or_else(|| {
            ConfigError::Invalid("selected_profile_id must not be empty".to_string())
        })?;

        if !self
            .profiles
            .iter()
            .any(|profile| &profile.id == selected_profile_id)
        {
            return Err(ConfigError::Invalid(format!(
                "selected profile '{selected_profile_id}' does not exist"
            )));
        }

        let active_profile_id = self.active_profile_id.as_ref().ok_or_else(|| {
            ConfigError::Invalid("active_profile_id must not be empty".to_string())
        })?;

        if !self
            .profiles
            .iter()
            .any(|profile| &profile.id == active_profile_id)
        {
            return Err(ConfigError::Invalid(format!(
                "active profile '{active_profile_id}' does not exist"
            )));
        }

        if self.tray_settings.ip_prefix_segments == 0 {
            return Err(ConfigError::Invalid(
                "tray ip_prefix_segments must be at least 1".to_string(),
            ));
        }
        if self.tray_settings.refresh_interval_secs == 0 {
            return Err(ConfigError::Invalid(
                "tray refresh_interval_secs must be at least 1".to_string(),
            ));
        }

        Ok(())
    }

    pub fn active_profile(&self) -> Result<&ProxyProfile, ConfigError> {
        let active_profile_id = self
            .active_profile_id
            .as_ref()
            .ok_or_else(|| ConfigError::Invalid("active profile is not configured".to_string()))?;
        self.profile_by_selector(active_profile_id)
    }

    pub fn selected_profile(&self) -> Result<&ProxyProfile, ConfigError> {
        let selected_profile_id = self.selected_profile_id.as_ref().ok_or_else(|| {
            ConfigError::Invalid("selected profile is not configured".to_string())
        })?;
        self.profile_by_selector(selected_profile_id)
    }

    pub fn profile_by_selector(&self, selector: &str) -> Result<&ProxyProfile, ConfigError> {
        self.profiles
            .iter()
            .find(|profile| profile.id == selector || profile.name == selector)
            .ok_or_else(|| ConfigError::Invalid(format!("unknown profile '{selector}'")))
    }

    pub fn resolve_profile_by_selector(
        &self,
        selector: Option<&str>,
    ) -> Result<ResolvedProfile, ConfigError> {
        let profile = match selector {
            Some(selector) => self.profile_by_selector(selector)?,
            None => self.active_profile()?,
        };
        profile.resolve()
    }
}

pub fn parse_raw_import_text(input: &str) -> Result<Vec<ImportedProxyEntry>, ConfigError> {
    let mut entries = Vec::new();

    for (line_no, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut entry = parse_raw_proxy_entry(trimmed)
            .map_err(|error| ConfigError::Invalid(format!("line {}: {error}", line_no + 1)))?;
        if entry.id.trim().is_empty() {
            entry.id = generate_id("entry");
        }
        if entry.label.trim().is_empty() {
            entry.label = format!("Proxy {}", entries.len() + 1);
        }
        entries.push(entry);
    }

    if entries.is_empty() {
        return Err(ConfigError::Invalid(
            "at least one raw import entry is required".to_string(),
        ));
    }

    Ok(entries)
}

pub fn ensure_single_proxy_entries(
    entries: &[ImportedProxyEntry],
) -> Result<(String, u16), ConfigError> {
    let first = entries.first().ok_or_else(|| {
        ConfigError::Invalid("at least one raw import entry is required".to_string())
    })?;

    let host = first.host.trim().to_string();
    let port = first.port;

    for entry in entries.iter().skip(1) {
        if entry.host.trim() != host || entry.port != port {
            return Err(ConfigError::Invalid(
                "raw import lines must all target the same proxy host and port".to_string(),
            ));
        }
    }

    Ok((host, port))
}

pub fn parse_raw_proxy_entry(input: &str) -> Result<ImportedProxyEntry, String> {
    if let Some((credential_part, proxy_part)) = input.split_once('@') {
        let (username, password) = split_username_password(credential_part)?;
        let (host, port) = split_host_port(proxy_part)?;
        return Ok(ImportedProxyEntry {
            id: String::new(),
            label: String::new(),
            username,
            password,
            host,
            port,
        });
    }

    let segments = input.split(':').collect::<Vec<_>>();
    if segments.len() < 4 {
        return Err(
            "expected '<username>:<password>@<proxy-host>:<port>' or '<username>:<password>:<proxy-host>:<port>'"
                .to_string(),
        );
    }

    let username = segments[0].trim().to_string();
    let password = segments[1].trim().to_string();
    let host = segments[2..segments.len() - 1].join(":").trim().to_string();
    let port = parse_port(segments[segments.len() - 1].trim())?;

    if username.is_empty() || password.is_empty() || host.is_empty() {
        return Err("username, password and host must not be empty".to_string());
    }

    Ok(ImportedProxyEntry {
        id: String::new(),
        label: String::new(),
        username,
        password,
        host,
        port,
    })
}

pub fn format_raw_proxy_entry(entry: &ImportedProxyEntry) -> String {
    format!(
        "{}:{}@{}:{}",
        entry.username, entry.password, entry.host, entry.port
    )
}

pub fn format_endpoint_prefix(ip: &str, segments: u8) -> String {
    if ip.contains(':') {
        let parts = ip.split(':').take(segments as usize).collect::<Vec<_>>();
        parts.join(":")
    } else {
        let parts = ip.split('.').take(segments as usize).collect::<Vec<_>>();
        parts.join(".")
    }
}

fn split_username_password(input: &str) -> Result<(String, String), String> {
    let (username, password) = input
        .split_once(':')
        .ok_or_else(|| "credential section must contain '<username>:<password>'".to_string())?;

    let username = username.trim().to_string();
    let password = password.trim().to_string();
    if username.is_empty() || password.is_empty() {
        return Err("username and password must not be empty".to_string());
    }

    Ok((username, password))
}

fn split_host_port(input: &str) -> Result<(String, u16), String> {
    if let Some(rest) = input.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "unterminated IPv6 host, expected closing ']'".to_string())?;
        let host = rest[..end].trim().to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| "proxy host must be followed by ':<port>'".to_string())?;
        return Ok((host, parse_port(port.trim())?));
    }

    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| "proxy section must contain '<host>:<port>'".to_string())?;

    let host = host.trim().to_string();
    if host.is_empty() {
        return Err("proxy host must not be empty".to_string());
    }

    Ok((host, parse_port(port.trim())?))
}

fn parse_port(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| "port must be between 1 and 65535".to_string())
}

fn config_dir() -> Result<PathBuf, ConfigError> {
    #[cfg(target_os = "windows")]
    {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| ConfigError::Invalid("APPDATA is not set".to_string()))
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Some(value) = env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(value));
        }

        env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".config"))
            .ok_or_else(|| ConfigError::Invalid("HOME is not set".to_string()))
    }
}

fn default_active_profile_id() -> Option<String> {
    Some("profile-default".to_string())
}

fn default_selected_profile_id() -> Option<String> {
    Some("profile-default".to_string())
}

fn default_profiles() -> Vec<ProxyProfile> {
    vec![ProxyProfile::default_named("Default")]
}

fn default_true() -> bool {
    true
}

fn default_ip_prefix_segments() -> u8 {
    2
}

fn default_refresh_interval_secs() -> u64 {
    300
}

fn generate_id(prefix: &str) -> String {
    let counter = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{stamp:x}-{counter:x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_at_format_raw_entries() {
        let entry = parse_raw_proxy_entry("alice:secret@proxy.example:1080").unwrap();
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.password, "secret");
        assert_eq!(entry.host, "proxy.example");
        assert_eq!(entry.port, 1080);
    }

    #[test]
    fn parses_colon_format_raw_entries() {
        let entry = parse_raw_proxy_entry("alice:secret:proxy.example:1080").unwrap();
        assert_eq!(entry.username, "alice");
        assert_eq!(entry.password, "secret");
        assert_eq!(entry.host, "proxy.example");
        assert_eq!(entry.port, 1080);
    }

    #[test]
    fn rejects_invalid_raw_entries() {
        let error = parse_raw_proxy_entry("proxy.example:1080").unwrap_err();
        assert!(error.contains("expected"));
    }

    #[test]
    fn rejects_mixed_proxy_hosts_inside_raw_import() {
        let error = ensure_single_proxy_entries(&[
            ImportedProxyEntry {
                id: "entry-a".to_string(),
                label: String::new(),
                username: "alice".to_string(),
                password: "secret".to_string(),
                host: "proxy-a.example".to_string(),
                port: 1080,
            },
            ImportedProxyEntry {
                id: "entry-b".to_string(),
                label: String::new(),
                username: "bob".to_string(),
                password: "secret".to_string(),
                host: "proxy-b.example".to_string(),
                port: 1080,
            },
        ])
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("raw import lines must all target the same proxy host and port"));
    }

    #[test]
    fn round_trips_app_config() {
        let config = AppConfig {
            enabled: true,
            selected_profile_id: Some("profile-a".to_string()),
            active_profile_id: Some("profile-a".to_string()),
            tray_settings: TraySettings::default(),
            app_launchers: vec![AppLauncher {
                id: "app-firefox".to_string(),
                label: "Firefox".to_string(),
                kind: AppLauncherKind::Desktop,
                command: "firefox".to_string(),
                args: vec!["--new-window".to_string()],
                working_dir: None,
                icon: Some("firefox".to_string()),
                enabled: true,
            }],
            profiles: vec![ProxyProfile {
                id: "profile-a".to_string(),
                name: "Primary".to_string(),
                target: StoredProxyTarget::RawImport(RawImportTarget {
                    selected_entry_id: Some("entry-a".to_string()),
                    entries: vec![ImportedProxyEntry {
                        id: "entry-a".to_string(),
                        label: "Proxy 1".to_string(),
                        username: "user".to_string(),
                        password: "pass".to_string(),
                        host: "proxy.example".to_string(),
                        port: 1080,
                    }],
                }),
                routing_mode: RoutingMode::Tun,
                proxy_dns: true,
                startup_cleanup_enabled: true,
                bypass: vec!["10.0.0.0/8".to_string()],
            }],
        };

        let parsed = AppConfig::from_toml(&config.to_toml().unwrap()).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn defaults_missing_selections_to_first_entry() {
        let config = AppConfig {
            enabled: false,
            selected_profile_id: Some("profile-a".to_string()),
            active_profile_id: Some("profile-a".to_string()),
            tray_settings: TraySettings::default(),
            app_launchers: Vec::new(),
            profiles: vec![ProxyProfile {
                id: "profile-a".to_string(),
                name: "Primary".to_string(),
                target: StoredProxyTarget::Structured(StructuredProxyTarget {
                    host: "proxy.example".to_string(),
                    port: 1080,
                    selected_credential_id: None,
                    credentials: vec![CredentialEntry {
                        id: "cred-a".to_string(),
                        label: String::new(),
                        username: "user".to_string(),
                        password: "secret".to_string(),
                    }],
                }),
                routing_mode: RoutingMode::System,
                proxy_dns: true,
                startup_cleanup_enabled: true,
                bypass: Vec::new(),
            }],
        }
        .canonicalized()
        .unwrap();

        let resolved = config.resolve_profile_by_selector(None).unwrap();
        assert_eq!(resolved.endpoint.username.as_deref(), Some("user"));
    }

    #[test]
    fn builds_ip_prefix_text() {
        assert_eq!(format_endpoint_prefix("203.0.113.42", 2), "203.0");
        assert_eq!(format_endpoint_prefix("2001:db8:85a3::8a2e", 2), "2001:db8");
    }

    #[test]
    fn defaults_selected_profile_to_active_profile() {
        let mut profile = ProxyProfile::default_named("Default");
        profile.target = StoredProxyTarget::Structured(StructuredProxyTarget {
            host: "proxy.example".to_string(),
            port: 1080,
            credentials: Vec::new(),
            selected_credential_id: None,
        });
        let config = AppConfig {
            enabled: false,
            selected_profile_id: None,
            active_profile_id: Some("profile-default".to_string()),
            tray_settings: TraySettings::default(),
            app_launchers: Vec::new(),
            profiles: vec![profile],
        }
        .canonicalized()
        .unwrap();

        assert_eq!(config.selected_profile_id, config.active_profile_id);
    }

    #[test]
    fn loads_legacy_config_ignoring_unknown_fields() {
        // Older configs carry fields we no longer model (`version`,
        // `vpn_awareness_enabled`) and omit newer ones (`app_launchers`). They
        // must still load: unknown keys are ignored and missing keys default.
        let parsed = AppConfig::from_toml(
            r#"
version = 2
enabled = false
selected_profile_id = "profile-default"
active_profile_id = "profile-default"

[[profiles]]
id = "profile-default"
name = "Default"
routing_mode = "system"
proxy_dns = true
vpn_awareness_enabled = false
startup_cleanup_enabled = true
bypass = []

[profiles.target]
kind = "structured"
host = "proxy.example"
port = 1080
credentials = []
"#,
        )
        .unwrap();

        assert!(parsed.app_launchers.is_empty());
        assert_eq!(parsed.profiles.len(), 1);
        assert_eq!(parsed.profiles[0].name, "Default");
    }
}
