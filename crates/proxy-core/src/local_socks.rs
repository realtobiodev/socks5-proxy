use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::config::ProxyEndpoint;
use crate::socks5::{self, read_addr_with_type, SocksAddr, HANDSHAKE_TIMEOUT};

pub const LOCAL_SOCKS_HOST: &str = "127.0.0.1";
pub const LOCAL_SOCKS_PORT: u16 = 1081;

const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const UDP_FRAGMENTED: u8 = 0x00;
const LOOP_TICK: Duration = Duration::from_millis(200);

pub struct LocalSocksServer {
    listen_addr: SocketAddr,
    stop_sender: mpsc::Sender<()>,
    join_handle: Option<JoinHandle<()>>,
}

impl Drop for LocalSocksServer {
    fn drop(&mut self) {
        let _ = self.stop_sender.send(());
    }
}

impl LocalSocksServer {
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn shutdown(mut self) -> Result<(), String> {
        let _ = self.stop_sender.send(());
        if let Some(handle) = self.join_handle.take() {
            handle
                .join()
                .map_err(|_| "local SOCKS5 server thread panicked".to_string())?;
        }
        Ok(())
    }
}

pub fn local_endpoint() -> ProxyEndpoint {
    ProxyEndpoint {
        host: LOCAL_SOCKS_HOST.to_string(),
        port: LOCAL_SOCKS_PORT,
        username: None,
        password: None,
    }
}

pub fn start(upstream: ProxyEndpoint) -> Result<LocalSocksServer, String> {
    start_with_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), LOCAL_SOCKS_PORT, upstream)
}

pub fn start_with_addr(
    listen_ip: IpAddr,
    listen_port: u16,
    upstream: ProxyEndpoint,
) -> Result<LocalSocksServer, String> {
    let listener = TcpListener::bind(SocketAddr::new(listen_ip, listen_port)).map_err(|error| {
        format!("failed to bind local SOCKS5 server on {listen_ip}:{listen_port}: {error}")
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("failed to configure local SOCKS5 listener: {error}"))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| format!("failed to inspect local SOCKS5 listener: {error}"))?;
    let (stop_sender, stop_receiver) = mpsc::channel();

    let join_handle = thread::spawn(move || loop {
        if stop_receiver.try_recv().is_ok() {
            break;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(error) = stream.set_nonblocking(false) {
                    tracing::warn!(error = %error, "failed to configure local SOCKS5 client socket");
                    continue;
                }
                let upstream = upstream.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_client(stream, upstream) {
                        tracing::debug!(error = %error, "local SOCKS5 client session failed");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(LOOP_TICK);
            }
            Err(error) => {
                tracing::warn!(error = %error, "local SOCKS5 accept failed");
                thread::sleep(LOOP_TICK);
            }
        }
    });

    Ok(LocalSocksServer {
        listen_addr,
        stop_sender,
        join_handle: Some(join_handle),
    })
}

fn handle_client(mut client: TcpStream, upstream: ProxyEndpoint) -> Result<(), String> {
    client
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("failed to configure local SOCKS5 client timeout: {error}"))?;
    client
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("failed to configure local SOCKS5 client timeout: {error}"))?;

    negotiate_no_auth(&mut client)?;

    let mut request_head = [0_u8; 4];
    client
        .read_exact(&mut request_head)
        .map_err(|error| format!("failed to read local SOCKS5 request: {error}"))?;
    if request_head[0] != 0x05 {
        return Err("local SOCKS5 client used an unsupported version".to_string());
    }

    let target = read_addr_with_type(&mut client, request_head[3])?;
    match request_head[1] {
        CMD_CONNECT => handle_connect(client, upstream, target),
        CMD_UDP_ASSOCIATE => handle_udp_associate(client, upstream),
        _ => {
            send_reply(
                &mut client,
                REPLY_COMMAND_NOT_SUPPORTED,
                &SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            )?;
            Err("local SOCKS5 command is not supported".to_string())
        }
    }
}

fn negotiate_no_auth(client: &mut TcpStream) -> Result<(), String> {
    let mut head = [0_u8; 2];
    client
        .read_exact(&mut head)
        .map_err(|error| format!("failed to read local SOCKS5 greeting: {error}"))?;
    if head[0] != 0x05 {
        return Err("local SOCKS5 client used an unsupported version".to_string());
    }

    let mut methods = vec![0_u8; head[1] as usize];
    client
        .read_exact(&mut methods)
        .map_err(|error| format!("failed to read local SOCKS5 methods: {error}"))?;
    let method = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NONE_ACCEPTABLE
    };
    client
        .write_all(&[0x05, method])
        .map_err(|error| format!("failed to write local SOCKS5 method selection: {error}"))?;

    if method == METHOD_NO_AUTH {
        Ok(())
    } else {
        Err("local SOCKS5 client requires authentication, which is not supported".to_string())
    }
}

fn handle_connect(
    mut client: TcpStream,
    upstream: ProxyEndpoint,
    target: SocksAddr,
) -> Result<(), String> {
    let upstream_socket = (upstream.host.as_str(), upstream.port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve proxy host: {error}"))?
        .next()
        .ok_or_else(|| "proxy host resolved to no addresses".to_string())?;
    let mut upstream_stream = match TcpStream::connect_timeout(&upstream_socket, HANDSHAKE_TIMEOUT)
    {
        Ok(stream) => stream,
        Err(error) => {
            let _ = send_reply(
                &mut client,
                REPLY_GENERAL_FAILURE,
                &SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            );
            return Err(format!("failed to connect to upstream proxy: {error}"));
        }
    };
    upstream_stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("failed to configure upstream timeout: {error}"))?;
    upstream_stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|error| format!("failed to configure upstream timeout: {error}"))?;

    match connect_via_upstream(&mut upstream_stream, &upstream, &target) {
        Ok(reply_addr) => {
            send_reply(&mut client, REPLY_SUCCEEDED, &reply_addr)?;
            relay_bidirectional(client, &mut upstream_stream)
        }
        Err(code) => {
            let _ = send_reply(
                &mut client,
                code,
                &SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            );
            Err(format!(
                "upstream SOCKS5 CONNECT failed with reply code {code}"
            ))
        }
    }
}

fn connect_via_upstream(
    upstream_stream: &mut TcpStream,
    upstream: &ProxyEndpoint,
    target: &SocksAddr,
) -> Result<SocksAddr, u8> {
    // Reuse the client handshake/auth flow against the upstream proxy.
    socks5::perform_handshake(upstream_stream, upstream).map_err(|_| REPLY_GENERAL_FAILURE)?;
    socks5::send_command_with_reply(upstream_stream, CMD_CONNECT, target)
        .map_err(|error| error.reply_code())
}

fn handle_udp_associate(mut client: TcpStream, upstream: ProxyEndpoint) -> Result<(), String> {
    match socks5::udp_associate(&upstream, HANDSHAKE_TIMEOUT) {
        Ok(associate) => {
            let client_reply_addr = SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                associate
                    .udp_socket
                    .local_addr()
                    .map_err(|error| format!("failed to inspect local UDP socket: {error}"))?
                    .port(),
            ));
            send_reply(&mut client, REPLY_SUCCEEDED, &client_reply_addr)?;
            relay_udp(client, associate)
        }
        Err(error) => {
            let reply_code = if error.contains("command not supported") {
                REPLY_COMMAND_NOT_SUPPORTED
            } else if error.contains("address type not supported") {
                REPLY_ADDRESS_TYPE_NOT_SUPPORTED
            } else if error.contains("host unreachable") {
                0x04
            } else if error.contains("network unreachable") {
                0x03
            } else if error.contains("connection refused") {
                0x05
            } else {
                REPLY_GENERAL_FAILURE
            };
            let _ = send_reply(
                &mut client,
                reply_code,
                &SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            );
            Err(format!("upstream SOCKS5 UDP associate failed: {error}"))
        }
    }
}

fn send_reply(client: &mut TcpStream, code: u8, addr: &SocksAddr) -> Result<(), String> {
    let mut response = vec![0x05, code, 0x00];
    crate::socks5::encode_addr_into(addr, &mut response)?;
    client
        .write_all(&response)
        .map_err(|error| format!("failed to write local SOCKS5 reply: {error}"))
}

fn relay_bidirectional(mut client: TcpStream, remote: &mut TcpStream) -> Result<(), String> {
    let mut client_writer = client
        .try_clone()
        .map_err(|error| format!("failed to clone local SOCKS5 client socket: {error}"))?;
    let mut remote_writer = remote
        .try_clone()
        .map_err(|error| format!("failed to clone upstream TCP socket: {error}"))?;

    let forward = thread::spawn(move || {
        let _ = io::copy(&mut client, &mut remote_writer);
        let _ = remote_writer.shutdown(Shutdown::Write);
    });

    let _ = io::copy(remote, &mut client_writer);
    let _ = client_writer.shutdown(Shutdown::Write);
    let _ = forward.join();
    Ok(())
}

fn relay_udp(control_stream: TcpStream, associate: socks5::UdpAssociate) -> Result<(), String> {
    let socks5::UdpAssociate {
        udp_socket,
        relay_addr,
        ..
    } = associate;

    udp_socket
        .set_read_timeout(Some(LOOP_TICK))
        .map_err(|error| format!("failed to configure local UDP relay timeout: {error}"))?;
    control_stream
        .set_read_timeout(Some(LOOP_TICK))
        .map_err(|error| format!("failed to configure UDP control timeout: {error}"))?;

    let mut client_udp_addr: Option<SocketAddr> = None;
    let mut udp_buf = [0_u8; 65535];
    let mut peek_buf = [0_u8; 1];

    loop {
        match control_stream.peek(&mut peek_buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                return Err(format!(
                    "failed while monitoring UDP control connection: {error}"
                ));
            }
        }

        match udp_socket.recv_from(&mut udp_buf) {
            Ok((size, source)) if source == relay_addr => {
                if let Some(client_addr) = client_udp_addr {
                    let _ = udp_socket.send_to(&udp_buf[..size], client_addr);
                }
            }
            Ok((size, source)) if source.ip().is_loopback() => {
                if udp_buf.get(2).copied().unwrap_or(UDP_FRAGMENTED + 1) != UDP_FRAGMENTED {
                    continue;
                }
                if client_udp_addr.is_none() {
                    client_udp_addr = Some(source);
                }
                if Some(source) == client_udp_addr {
                    let _ = udp_socket.send_to(&udp_buf[..size], relay_addr);
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(format!("local UDP relay failed: {error}")),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn test_upstream_endpoint(port: u16, with_auth: bool) -> ProxyEndpoint {
        ProxyEndpoint {
            host: "127.0.0.1".into(),
            port,
            username: with_auth.then(|| "user".into()),
            password: with_auth.then(|| "pass".into()),
        }
    }

    #[test]
    fn local_server_rejects_port_conflict() {
        let occupied = TcpListener::bind((LOCAL_SOCKS_HOST, 0)).unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let result = start_with_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            occupied_port,
            test_upstream_endpoint(9, false),
        );
        assert!(result.is_err());
        drop(occupied);
    }

    #[test]
    fn local_server_starts_and_stops_on_ephemeral_port() {
        let upstream = start_mock_upstream(false, false);
        let server = start_with_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            test_upstream_endpoint(upstream.port, false),
        )
        .unwrap();
        assert!(server.listen_addr().port() > 0);
        server.shutdown().unwrap();
        upstream.stop();
    }

    #[test]
    fn local_server_connects_through_authenticated_upstream() {
        let echo = start_tcp_echo();
        let upstream = start_mock_upstream(true, false);
        let server = start_with_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            test_upstream_endpoint(upstream.port, true),
        )
        .unwrap();

        let mut client = TcpStream::connect(server.listen_addr()).unwrap();
        client.write_all(&[0x05, 1, METHOD_NO_AUTH]).unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, METHOD_NO_AUTH]);

        let mut request = vec![0x05, CMD_CONNECT, 0x00];
        crate::socks5::encode_addr_into(
            &SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), echo.port)),
            &mut request,
        )
        .unwrap();
        client.write_all(&request).unwrap();
        let mut reply_head = [0_u8; 4];
        client.read_exact(&mut reply_head).unwrap();
        assert_eq!(reply_head[..2], [0x05, REPLY_SUCCEEDED]);
        let _ = read_addr_with_type(&mut client, reply_head[3]).unwrap();

        client.write_all(b"ping").unwrap();
        let mut buf = [0_u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        server.shutdown().unwrap();
        echo.stop();
        upstream.stop();
    }

    #[test]
    fn local_server_proxies_udp_associate() {
        let udp_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_echo_port = udp_echo.local_addr().unwrap().port();
        let echo_thread = thread::spawn(move || {
            let mut buf = [0_u8; 1500];
            let (size, from) = udp_echo.recv_from(&mut buf).unwrap();
            udp_echo.send_to(&buf[..size], from).unwrap();
        });

        let upstream = start_mock_upstream(true, true);
        let server = start_with_addr(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            test_upstream_endpoint(upstream.port, true),
        )
        .unwrap();

        let mut control = TcpStream::connect(server.listen_addr()).unwrap();
        control.write_all(&[0x05, 1, METHOD_NO_AUTH]).unwrap();
        let mut method = [0_u8; 2];
        control.read_exact(&mut method).unwrap();
        assert_eq!(method, [0x05, METHOD_NO_AUTH]);

        let mut request = vec![0x05, CMD_UDP_ASSOCIATE, 0x00];
        crate::socks5::encode_addr_into(
            &SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            &mut request,
        )
        .unwrap();
        control.write_all(&request).unwrap();
        let mut reply_head = [0_u8; 4];
        control.read_exact(&mut reply_head).unwrap();
        assert_eq!(reply_head[..2], [0x05, REPLY_SUCCEEDED]);
        let bound = read_addr_with_type(&mut control, reply_head[3]).unwrap();
        let udp_target = bound.resolve_first().unwrap();

        let udp_client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut datagram = vec![0_u8, 0_u8, UDP_FRAGMENTED];
        crate::socks5::encode_addr_into(
            &SocksAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                udp_echo_port,
            )),
            &mut datagram,
        )
        .unwrap();
        datagram.extend_from_slice(b"udp");
        udp_client.send_to(&datagram, udp_target).unwrap();

        let mut buf = [0_u8; 1500];
        let (size, _) = udp_client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[size - 3..size], b"udp");

        drop(control);
        let _ = echo_thread.join();
        server.shutdown().unwrap();
        upstream.stop();
    }

    struct TcpEcho {
        port: u16,
        stop: mpsc::Sender<()>,
        join: JoinHandle<()>,
    }

    impl TcpEcho {
        fn stop(self) {
            let _ = self.stop.send(());
            let _ = self.join.join();
        }
    }

    fn start_tcp_echo() -> TcpEcho {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stop_rx) = mpsc::channel();
        let join = thread::spawn(move || loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    let mut buf = [0_u8; 1024];
                    let size = stream.read(&mut buf).unwrap();
                    stream.write_all(&buf[..size]).unwrap();
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        });
        TcpEcho { port, stop, join }
    }

    struct MockUpstream {
        port: u16,
        stop: mpsc::Sender<()>,
        join: JoinHandle<()>,
    }

    impl MockUpstream {
        fn stop(self) {
            let _ = self.stop.send(());
            let _ = self.join.join();
        }
    }

    fn start_mock_upstream(require_auth: bool, support_udp: bool) -> MockUpstream {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stop_rx) = mpsc::channel();
        let join = thread::spawn(move || loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    if let Err(error) = handle_mock_upstream(&mut stream, require_auth, support_udp)
                    {
                        panic!("mock upstream failed: {error}");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        });
        MockUpstream { port, stop, join }
    }

    fn handle_mock_upstream(
        stream: &mut TcpStream,
        require_auth: bool,
        support_udp: bool,
    ) -> Result<(), String> {
        let mut head = [0_u8; 2];
        stream.read_exact(&mut head).map_err(|e| e.to_string())?;
        let mut methods = vec![0_u8; head[1] as usize];
        stream.read_exact(&mut methods).map_err(|e| e.to_string())?;
        let method = if require_auth { 0x02 } else { 0x00 };
        stream
            .write_all(&[0x05, method])
            .map_err(|e| e.to_string())?;

        if require_auth {
            let mut auth_head = [0_u8; 2];
            stream
                .read_exact(&mut auth_head)
                .map_err(|e| e.to_string())?;
            if auth_head[0] != 0x01 {
                return Err("unsupported username/password auth version".to_string());
            }
            let mut username = vec![0_u8; auth_head[1] as usize];
            stream
                .read_exact(&mut username)
                .map_err(|e| e.to_string())?;
            let mut plen = [0_u8; 1];
            stream.read_exact(&mut plen).map_err(|e| e.to_string())?;
            let mut password = vec![0_u8; plen[0] as usize];
            stream
                .read_exact(&mut password)
                .map_err(|e| e.to_string())?;
            let status = if username == b"user" && password == b"pass" {
                0x00
            } else {
                0x01
            };
            stream
                .write_all(&[0x01, status])
                .map_err(|e| e.to_string())?;
            if status != 0x00 {
                return Ok(());
            }
        }

        let mut request_head = [0_u8; 4];
        stream
            .read_exact(&mut request_head)
            .map_err(|e| e.to_string())?;
        let target = read_addr_with_type(stream, request_head[3])?;
        match request_head[1] {
            CMD_CONNECT => {
                let target = target.resolve_first()?;
                let mut remote = TcpStream::connect(target).map_err(|e| e.to_string())?;
                let reply_addr = SocksAddr::Ip(remote.local_addr().map_err(|e| e.to_string())?);
                let mut response = vec![0x05, 0x00, 0x00];
                crate::socks5::encode_addr_into(&reply_addr, &mut response)?;
                stream.write_all(&response).map_err(|e| e.to_string())?;
                let mut client_reader = stream.try_clone().map_err(|e| e.to_string())?;
                let mut remote_writer = remote.try_clone().map_err(|e| e.to_string())?;
                let forward = thread::spawn(move || {
                    let _ = io::copy(&mut client_reader, &mut remote_writer);
                });
                let _ = io::copy(&mut remote, stream);
                let _ = forward.join();
            }
            CMD_UDP_ASSOCIATE => {
                if !support_udp {
                    stream
                        .write_all(&[
                            0x05,
                            REPLY_COMMAND_NOT_SUPPORTED,
                            0x00,
                            0x01,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                        ])
                        .map_err(|e| e.to_string())?;
                    return Ok(());
                }

                let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .map_err(|e| e.to_string())?;
                let relay_addr = udp.local_addr().map_err(|e| e.to_string())?;
                let relay_sock = udp.try_clone().map_err(|e| e.to_string())?;
                let mut response = vec![0x05, 0x00, 0x00];
                crate::socks5::encode_addr_into(&SocksAddr::Ip(relay_addr), &mut response)?;
                stream.write_all(&response).map_err(|e| e.to_string())?;

                let relay_thread = thread::spawn(move || {
                    let mut buf = [0_u8; 1500];
                    let (size, from) = relay_sock.recv_from(&mut buf).unwrap();
                    let mut cursor = &buf[3..size];
                    let target = socks5::read_addr_from(&mut cursor).unwrap();
                    let payload_offset = size - cursor.len();
                    let payload = &buf[payload_offset..size];
                    let target = target.resolve_first().unwrap();
                    relay_sock.send_to(payload, target).unwrap();
                    let (resp_size, target_from) = relay_sock.recv_from(&mut buf).unwrap();
                    let mut datagram = vec![0, 0, 0];
                    crate::socks5::encode_addr_into(&SocksAddr::Ip(target_from), &mut datagram)
                        .unwrap();
                    datagram.extend_from_slice(&buf[..resp_size]);
                    relay_sock.send_to(&datagram, from).unwrap();
                });

                let mut blocker = [0_u8; 1];
                let _ = stream.read(&mut blocker);
                let _ = relay_thread.join();
            }
            _ => {}
        }

        Ok(())
    }
}
