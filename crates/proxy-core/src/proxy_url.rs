use crate::config::ProxyEndpoint;

pub fn socks5_url(endpoint: &ProxyEndpoint) -> String {
    let host = normalize_host(&endpoint.host);

    match (&endpoint.username, &endpoint.password) {
        (Some(username), Some(password)) => format!(
            "socks5://{}:{}@{}:{}",
            percent_encode(username),
            percent_encode(password),
            host,
            endpoint.port
        ),
        (Some(username), None) => format!(
            "socks5://{}@{}:{}",
            percent_encode(username),
            host,
            endpoint.port
        ),
        _ => format!("socks5://{}:{}", host, endpoint.port),
    }
}

pub fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            byte => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn normalize_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyEndpoint;

    #[test]
    fn builds_authenticated_socks5_url() {
        let endpoint = ProxyEndpoint {
            host: "127.0.0.1".to_string(),
            port: 1080,
            username: Some("my name".to_string()),
            password: Some("p@ss:word".to_string()),
        };

        assert_eq!(
            socks5_url(&endpoint),
            "socks5://my%20name:p%40ss%3Aword@127.0.0.1:1080"
        );
    }

    #[test]
    fn wraps_ipv6_hosts() {
        let endpoint = ProxyEndpoint {
            host: "::1".to_string(),
            port: 1080,
            username: None,
            password: None,
        };

        assert_eq!(socks5_url(&endpoint), "socks5://[::1]:1080");
    }
}
