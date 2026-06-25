use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("{0}")]
    Config(#[from] crate::config::ConfigError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("socks5 handshake failed: {0}")]
    Socks5(String),
    #[error("command failed: {0}")]
    Command(String),
    #[error("toml serialize: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml deserialize: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T, E = ProxyError> = std::result::Result<T, E>;
