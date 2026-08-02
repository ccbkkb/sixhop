//! SOCKS5 代理的真实协议集成测试。
//! 通过 CARGO_BIN_EXE_ 启动编译产物，逐字节完成握手/认证/CONNECT/BIND/UDP 测试。

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

// ---------- 工具函数 ----------

/// 把 IpAddr 转成网络序字节（IPv4 -> 4 字节，IPv6 -> 16 字节）
fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn find_free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_ready(addr: SocketAddr, child: &mut Child) {
    for _ in 0..100 {
        if let Some(st) = child.try_wait().unwrap() {
            panic!("代理进程提前退出: {st}");
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("代理未就绪: {addr}");
}

struct ProxyGuard {
    child: Child,
    addr: SocketAddr,
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 启动代理：固定绑定 127.0.0.1:随机端口，且不读取仓库里的 socks5.toml
fn spawn_proxy(args: &[&str]) -> ProxyGuard {
    let port = find_free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sixhop"));
    cmd.arg("--config").arg("__no_such_config__.toml");
    cmd.arg("--bind").arg(format!("127.0.0.1:{port}"));
    for a in args {
        cmd.arg(a);
    }
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = cmd.spawn().expect("无法启动代理进程");
    wait_ready(addr, &mut child);
    ProxyGuard { child, addr }
}

/// 本地 TCP 回显服务（每个连接开一个线程回显）
fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });
    addr
}

/// SOCKS5 无认证握手，然后 CONNECT 到指定地址
fn socks_connect_no_auth(proxy: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let mut s = TcpStream::connect(proxy).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 0], "应选择无认证方法");

    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip_bytes(target.ip()));
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).unwrap();

    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[..3], &[5, 0, 0], "CONNECT 应成功");

    s.write_all(payload).unwrap();
    let mut out = vec![0u8; payload.len()];
    s.read_exact(&mut out).unwrap();
    assert_eq!(&out, payload, "回显数据应一致");
}

// ---------- 测试用例 ----------

#[test]
fn test_no_auth_connect_echo() {
    let echo = spawn_echo_server();
    let proxy = spawn_proxy(&[]);
    socks_connect_no_auth(proxy.addr, echo, b"hello socks5");
}

#[test]
fn test_auth_connect_echo() {
    let echo = spawn_echo_server();
    let proxy = spawn_proxy(&["--username", "test", "--password", "secret"]);

    let mut s = TcpStream::connect(proxy.addr).unwrap();
    // 只提议 user/pass 方法
    s.write_all(&[5, 1, 2]).unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 2]);

    // RFC 1929 认证：user=test(4) pass=secret(6)
    s.write_all(&[
        1, 4, b't', b'e', b's', b't', 6, b's', b'e', b'c', b'r', b'e', b't',
    ])
    .unwrap();
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).unwrap();
    assert_eq!(auth, [1, 0], "认证应成功");

    // CONNECT 并回显
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip_bytes(echo.ip()));
    req.extend_from_slice(&echo.port().to_be_bytes());
    s.write_all(&req).unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[..3], &[5, 0, 0]);
    s.write_all(b"auth ok").unwrap();
    let mut out = [0u8; 7];
    s.read_exact(&mut out).unwrap();
    assert_eq!(&out, b"auth ok");
}

#[test]
fn test_wrong_password_rejected() {
    let proxy = spawn_proxy(&["--username", "test", "--password", "secret"]);
    let mut s = TcpStream::connect(proxy.addr).unwrap();
    s.write_all(&[5, 1, 2]).unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 2]);

    // user=test(4) pass=wrong(5)
    s.write_all(&[1, 4, b't', b'e', b's', b't', 5, b'w', b'r', b'o', b'n', b'g'])
        .unwrap();
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).unwrap();
    assert_eq!(auth, [1, 1], "错误密码应返回失败");

    // 服务端应立刻断开
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).unwrap(), 0, "认证失败后连接应被关闭");
}

#[test]
fn test_no_auth_rejected_when_auth_enabled() {
    let proxy = spawn_proxy(&["--username", "test", "--password", "secret"]);
    let mut s = TcpStream::connect(proxy.addr).unwrap();
    // 只提议 no-auth
    s.write_all(&[5, 1, 0]).unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 0xff], "开启认证时应拒绝无认证方法");
}

#[test]
fn test_bind_command() {
    let proxy = spawn_proxy(&[]);
    let mut c = TcpStream::connect(proxy.addr).unwrap();
    c.write_all(&[5, 1, 0]).unwrap();
    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 0]);

    // BIND 请求：0.0.0.0:0
    c.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[..3], &[5, 0, 0]);
    assert_eq!(rep[3], 1, "BIND 应返回 IPv4 地址");
    let mut bind_ip = Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
    if bind_ip.is_unspecified() {
        bind_ip = Ipv4Addr::LOCALHOST;
    }
    let bind_port = u16::from_be_bytes([rep[8], rep[9]]);
    let bind_addr = SocketAddr::new(IpAddr::V4(bind_ip), bind_port);

    // 目标连上监听地址并发数据
    let mut target = TcpStream::connect(bind_addr).unwrap();
    target.write_all(b"bind hello").unwrap();

    // 代理第二次应答（包含目标地址）
    let mut rep2 = [0u8; 10];
    c.read_exact(&mut rep2).unwrap();
    assert_eq!(&rep2[..3], &[5, 0, 0]);

    // 数据从 target 流向 client
    let mut out = [0u8; 10];
    c.read_exact(&mut out).unwrap();
    assert_eq!(&out, b"bind hello");
}

#[test]
#[cfg(not(windows))] // 需要 127.0.0.2 作为独立回包源
fn test_udp_associate() {
    // UDP 回显服务绑定在 127.0.0.2（与客户端 127.0.0.1 区分，便于中继区分方向）
    let echo = UdpSocket::bind("127.0.0.2:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match echo.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let _ = echo.send_to(&buf[..n], src);
                }
                Err(_) => break,
            }
        }
    });

    let proxy = spawn_proxy(&[]);
    let mut c = TcpStream::connect(proxy.addr).unwrap();
    c.write_all(&[5, 1, 0]).unwrap();
    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 0]);

    // UDP ASSOCIATE 请求：0.0.0.0:0
    c.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[..3], &[5, 0, 0]);
    assert_eq!(rep[3], 1);
    let mut relay_ip = Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
    if relay_ip.is_unspecified() {
        relay_ip = Ipv4Addr::LOCALHOST;
    }
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    let relay_addr = SocketAddr::new(IpAddr::V4(relay_ip), relay_port);

    // 客户端 UDP 套接字（端口与 TCP 控制连接不同，验证中继按真实来源回包）
    let client_udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // SOCKS5 UDP 头：RSV(2)+FRAG(1)+ATYP(1)+目标IP(4)+端口(2)+载荷
    let mut pkt = vec![0u8; 4 + 4 + 2];
    pkt[..4].copy_from_slice(&[0, 0, 0, 1]);
    let echo_bytes = ip_bytes(echo_addr.ip());
    assert_eq!(echo_bytes.len(), 4, "UDP 测试中 echo 服务器应为 IPv4");
    pkt[4..8].copy_from_slice(&echo_bytes);
    pkt[8..10].copy_from_slice(&echo_addr.port().to_be_bytes());
    pkt.extend_from_slice(b"udp-ping");
    client_udp.send_to(&pkt, relay_addr).unwrap();

    let mut resp = [0u8; 1024];
    let (n, _) = client_udp.recv_from(&mut resp).unwrap();
    assert!(n >= 10);
    assert_eq!(&resp[..3], &[0, 0, 0]);
    assert_eq!(resp[3], 1, "回包头应为 IPv4");
    let src_ip = Ipv4Addr::new(resp[4], resp[5], resp[6], resp[7]);
    let src_port = u16::from_be_bytes([resp[8], resp[9]]);
    assert_eq!(
        SocketAddr::new(IpAddr::V4(src_ip), src_port),
        echo_addr,
        "回包头应包含回显服务器地址"
    );
    assert_eq!(&resp[10..n], b"udp-ping", "UDP 载荷应被回显");

    drop(c);
    drop(client_udp);
    let _ = echo_task.join();
}

#[test]
fn test_env_config() {
    // 验证环境变量配置（SOCKS5_BIND + SOCKS5_USERNAME/PASSWORD）
    let port = find_free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sixhop"));
    cmd.arg("--config").arg("__no_such_config__.toml");
    cmd.env("SOCKS5_BIND", addr.to_string());
    cmd.env("SOCKS5_USERNAME", "envuser");
    cmd.env("SOCKS5_PASSWORD", "envpass");
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    wait_ready(addr, &mut child);

    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&[5, 1, 2]).unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [5, 2]);
    // user=envuser(7) pass=envpass(7)
    s.write_all(&[
        1, 7, b'e', b'n', b'v', b'u', b's', b'e', b'r', 7, b'e', b'n', b'v', b'p', b'a', b's', b's',
    ])
    .unwrap();
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).unwrap();
    assert_eq!(auth, [1, 0], "环境变量中的凭据应认证成功");

    let _ = child.kill();
    let _ = child.wait();
}
