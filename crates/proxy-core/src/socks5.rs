//! Shared SOCKS5 client primitives used by the CLI, desktop diagnostics, and
//! the embedded local system-proxy adapter.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::config::ProxyEndpoint;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

const VER_SOCKS5: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const AUTH_VER: u8 = 0x01;
const AUTH_OK: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SocksFailure {
    Reply(u8),
}

impl SocksFailure {
    pub fn reply_code(self) -> u8 {
        match self {
            Self::Reply(code) => code,
        }
    }
}

impl std::fmt::Display for SocksFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reply(code) => write!(f, "SOCKS5 request failed: {}", reply_code_text(*code)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl SocksAddr {
    pub fn resolve_first(&self) -> Result<SocketAddr, String> {
        match self {
            Self::Ip(addr) => Ok(*addr),
            Self::Domain(host, port) => (host.as_str(), *port)
                .to_socket_addrs()
                .map_err(|error| format!("failed to resolve target host: {error}"))?
                .next()
                .ok_or_else(|| "target host resolved to no addresses".to_string()),
        }
    }
}

pub struct UdpAssociate {
    pub udp_socket: UdpSocket,
    pub relay_addr: SocketAddr,
    _control_stream: TcpStream,
}

pub fn handshake(endpoint: &ProxyEndpoint) -> Result<(), String> {
    handshake_with_timeout(endpoint, HANDSHAKE_TIMEOUT)
}

pub fn handshake_with_timeout(endpoint: &ProxyEndpoint, timeout: Duration) -> Result<(), String> {
    let stream = connect_authenticated(endpoint, timeout)?;
    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

pub fn connect_stream(
    endpoint: &ProxyEndpoint,
    target: &SocksAddr,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let mut stream = connect_authenticated(endpoint, timeout)?;
    send_command(&mut stream, CMD_CONNECT, target).map_err(|error| error.to_string())?;
    Ok(stream)
}

pub fn udp_associate(endpoint: &ProxyEndpoint, timeout: Duration) -> Result<UdpAssociate, String> {
    let udp_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| format!("failed to bind UDP socket: {error}"))?;
    udp_socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure UDP socket timeout: {error}"))?;
    udp_socket
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to configure UDP socket timeout: {error}"))?;

    let udp_port = udp_socket
        .local_addr()
        .map_err(|error| format!("failed to inspect UDP socket: {error}"))?
        .port();
    let announced = SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), udp_port));

    let mut control_stream = connect_authenticated(endpoint, timeout)?;
    let relay = send_command(&mut control_stream, CMD_UDP_ASSOCIATE, &announced)
        .map_err(|error| error.to_string())?;

    Ok(UdpAssociate {
        udp_socket,
        relay_addr: relay.resolve_first()?,
        _control_stream: control_stream,
    })
}

fn connect_authenticated(endpoint: &ProxyEndpoint, timeout: Duration) -> Result<TcpStream, String> {
    let socket = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve proxy host: {error}"))?
        .next()
        .ok_or_else(|| "proxy host resolved to no addresses".to_string())?;

    let mut stream = TcpStream::connect_timeout(&socket, timeout)
        .map_err(|error| format!("failed to connect to proxy: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;

    perform_handshake(&mut stream, endpoint)?;
    Ok(stream)
}

/// Perform the SOCKS5 greeting + (optional) username/password authentication on
/// an already-connected stream. Shared by the client connect paths and the local
/// SOCKS5 server's upstream connection.
pub fn perform_handshake(stream: &mut TcpStream, endpoint: &ProxyEndpoint) -> Result<(), String> {
    let has_credentials = endpoint.username.is_some() && endpoint.password.is_some();
    let greeting: &[u8] = if has_credentials {
        &[VER_SOCKS5, 2, METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        &[VER_SOCKS5, 1, METHOD_NO_AUTH]
    };
    stream
        .write_all(greeting)
        .map_err(|error| format!("failed to write SOCKS5 greeting: {error}"))?;

    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("failed to read SOCKS5 greeting: {error}"))?;

    if response[0] != VER_SOCKS5 {
        return Err("remote endpoint did not speak SOCKS5".to_string());
    }

    match response[1] {
        METHOD_NO_AUTH => Ok(()),
        METHOD_USER_PASS => authenticate(stream, endpoint),
        METHOD_NONE_ACCEPTABLE => {
            Err("SOCKS5 proxy rejected all authentication methods".to_string())
        }
        method => Err(format!(
            "SOCKS5 proxy selected unsupported auth method 0x{method:02x}"
        )),
    }
}

fn send_command(
    stream: &mut TcpStream,
    command: u8,
    target: &SocksAddr,
) -> Result<SocksAddr, String> {
    let mut request = vec![VER_SOCKS5, command, 0x00];
    encode_addr_into(target, &mut request)?;
    stream
        .write_all(&request)
        .map_err(|error| format!("failed to write SOCKS5 request: {error}"))?;

    let mut response_head = [0_u8; 3];
    stream
        .read_exact(&mut response_head)
        .map_err(|error| format!("failed to read SOCKS5 response: {error}"))?;

    if response_head[0] != VER_SOCKS5 {
        return Err("proxy returned an invalid SOCKS5 response".to_string());
    }
    if response_head[1] != 0x00 {
        return Err(format!(
            "SOCKS5 request failed: {}",
            reply_code_text(response_head[1])
        ));
    }

    read_addr_from(stream)
}

pub fn send_command_with_reply(
    stream: &mut TcpStream,
    command: u8,
    target: &SocksAddr,
) -> Result<SocksAddr, SocksFailure> {
    let mut request = vec![VER_SOCKS5, command, 0x00];
    encode_addr_into(target, &mut request).map_err(|_| SocksFailure::Reply(0x01))?;
    stream
        .write_all(&request)
        .map_err(|_| SocksFailure::Reply(0x01))?;

    let mut response_head = [0_u8; 3];
    stream
        .read_exact(&mut response_head)
        .map_err(|_| SocksFailure::Reply(0x01))?;

    if response_head[0] != VER_SOCKS5 {
        return Err(SocksFailure::Reply(0x01));
    }
    if response_head[1] != 0x00 {
        return Err(SocksFailure::Reply(response_head[1]));
    }

    read_addr_from(stream).map_err(|_| SocksFailure::Reply(0x01))
}

fn authenticate(stream: &mut TcpStream, endpoint: &ProxyEndpoint) -> Result<(), String> {
    let username = endpoint.username.as_deref().unwrap_or_default().as_bytes();
    let password = endpoint.password.as_deref().unwrap_or_default().as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err("SOCKS5 username/password must be shorter than 256 bytes".to_string());
    }

    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
    auth.push(AUTH_VER);
    auth.push(username.len() as u8);
    auth.extend_from_slice(username);
    auth.push(password.len() as u8);
    auth.extend_from_slice(password);
    stream
        .write_all(&auth)
        .map_err(|error| format!("failed to write SOCKS5 auth: {error}"))?;

    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("failed to read SOCKS5 auth: {error}"))?;

    if response == [AUTH_VER, AUTH_OK] {
        Ok(())
    } else {
        Err("SOCKS5 username/password authentication failed".to_string())
    }
}

pub(crate) fn read_addr_from<R: Read>(reader: &mut R) -> Result<SocksAddr, String> {
    let mut atyp = [0_u8; 1];
    reader
        .read_exact(&mut atyp)
        .map_err(|error| format!("failed to read SOCKS5 address type: {error}"))?;
    read_addr_with_type(reader, atyp[0])
}

pub(crate) fn read_addr_with_type<R: Read>(reader: &mut R, atyp: u8) -> Result<SocksAddr, String> {
    match atyp {
        ATYP_IPV4 => {
            let mut ip = [0_u8; 4];
            let mut port = [0_u8; 2];
            reader
                .read_exact(&mut ip)
                .map_err(|error| format!("failed to read SOCKS5 IPv4 address: {error}"))?;
            reader
                .read_exact(&mut port)
                .map_err(|error| format!("failed to read SOCKS5 port: {error}"))?;
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                u16::from_be_bytes(port),
            )))
        }
        ATYP_DOMAIN => {
            let mut len = [0_u8; 1];
            let mut port = [0_u8; 2];
            reader
                .read_exact(&mut len)
                .map_err(|error| format!("failed to read SOCKS5 host length: {error}"))?;
            let mut host = vec![0_u8; len[0] as usize];
            reader
                .read_exact(&mut host)
                .map_err(|error| format!("failed to read SOCKS5 host: {error}"))?;
            reader
                .read_exact(&mut port)
                .map_err(|error| format!("failed to read SOCKS5 port: {error}"))?;
            let host = String::from_utf8(host)
                .map_err(|_| "SOCKS5 host was not valid UTF-8".to_string())?;
            Ok(SocksAddr::Domain(host, u16::from_be_bytes(port)))
        }
        ATYP_IPV6 => {
            let mut ip = [0_u8; 16];
            let mut port = [0_u8; 2];
            reader
                .read_exact(&mut ip)
                .map_err(|error| format!("failed to read SOCKS5 IPv6 address: {error}"))?;
            reader
                .read_exact(&mut port)
                .map_err(|error| format!("failed to read SOCKS5 port: {error}"))?;
            Ok(SocksAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                u16::from_be_bytes(port),
            )))
        }
        other => Err(format!("unsupported SOCKS5 address type 0x{other:02x}")),
    }
}

pub(crate) fn encode_addr_into(addr: &SocksAddr, out: &mut Vec<u8>) -> Result<(), String> {
    match addr {
        SocksAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocksAddr::Domain(host, port) => {
            if host.len() > u8::MAX as usize {
                return Err("SOCKS5 host must be shorter than 256 bytes".to_string());
            }
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

fn reply_code_text(code: u8) -> &'static str {
    match code {
        0x01 => "general server failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_domain_target() {
        let addr = SocksAddr::Domain("example.com".into(), 443);
        let mut bytes = Vec::new();
        encode_addr_into(&addr, &mut bytes).unwrap();
        let mut slice = bytes.as_slice();
        assert_eq!(read_addr_from(&mut slice).unwrap(), addr);
    }
}
