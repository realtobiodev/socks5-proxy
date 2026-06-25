//! Argument validation for values that get embedded into platform shell/command-line
//! payloads (gsettings gvariant strings, `reg add /d ...`, PowerShell snippets).

use crate::error::ProxyError;

/// Validate a host string before it is interpolated into a platform command.
///
/// Rejects characters that could break out of a gvariant single-quoted string,
/// chain registry values, or otherwise inject shell/PowerShell syntax.
pub fn validate_host(host: &str) -> Result<(), ProxyError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Invalid("host must not be empty".into()));
    }
    if trimmed.len() > 253 {
        return Err(ProxyError::Invalid("host exceeds 253 characters".into()));
    }
    for ch in trimmed.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '_' | '[' | ']');
        if !ok {
            return Err(ProxyError::Invalid(format!(
                "host contains disallowed character {ch:?}; only ASCII letters/digits and .-:_[] are permitted"
            )));
        }
    }
    Ok(())
}

/// Validate a TUN device name (must be safe for `ip link` / PowerShell adapter cmdlets).
pub fn validate_tun_device(name: &str) -> Result<(), ProxyError> {
    if name.is_empty() || name.len() > 15 {
        return Err(ProxyError::Invalid(
            "tun device name must be 1..=15 chars".into(),
        ));
    }
    for ch in name.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-') {
            return Err(ProxyError::Invalid(format!(
                "tun device name contains disallowed character {ch:?}"
            )));
        }
    }
    Ok(())
}

/// Validate that a target string for `ip route get` / `Find-NetRoute` parses as an IP literal.
pub fn validate_ip_literal(target: &str) -> Result<(), ProxyError> {
    use std::net::IpAddr;
    target
        .parse::<IpAddr>()
        .map(|_| ())
        .map_err(|_| ProxyError::Invalid(format!("expected IP literal, got {target:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_hosts() {
        validate_host("proxy.example.com").unwrap();
        validate_host("10.0.0.1").unwrap();
        validate_host("[2001:db8::1]").unwrap();
        validate_host("2001:db8::1").unwrap();
    }

    #[test]
    fn rejects_quote_injection() {
        assert!(validate_host("x' '").is_err());
        assert!(validate_host("x;y").is_err());
        assert!(validate_host("x y").is_err());
        assert!(validate_host("x|y").is_err());
        assert!(validate_host("$(rm -rf /)").is_err());
    }

    #[test]
    fn validates_tun_device() {
        validate_tun_device("s5pabc").unwrap();
        assert!(validate_tun_device("").is_err());
        assert!(validate_tun_device("a b").is_err());
        assert!(validate_tun_device(&"a".repeat(16)).is_err());
    }

    #[test]
    fn validates_ip_literal() {
        validate_ip_literal("1.2.3.4").unwrap();
        validate_ip_literal("::1").unwrap();
        assert!(validate_ip_literal("not-an-ip").is_err());
        assert!(validate_ip_literal("$(evil)").is_err());
    }
}
