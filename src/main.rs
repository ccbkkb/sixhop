#![forbid(unsafe_code)]

//! # sixhop — 单文件高性能 SOCKS5 代理
//!
//! 特性：
//! - SOCKS5 完整握手 + 用户名/密码认证（RFC 1929）
//! - CONNECT / BIND / UDP ASSOCIATE
//! - 随机出口 IPv6：按 /48、/64、/128 等块随机生成源地址
//! - 配置优先级：命令行参数 > 环境变量 > TOML 配置文件 > 默认值
//! - tokio 全异步，面向百万级并发设计

use std::env;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use rand::Rng;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

// ============================ 命令行参数 ============================

#[derive(Parser, Debug)]
#[command(name = "sixhop", version, about = "单文件高性能 SOCKS5 代理，支持认证与随机出口 IPv6")]
struct Args {
    /// 配置文件路径（TOML）
    #[arg(short = 'c', long, default_value = "socks5.toml")]
    config: String,

    /// 监听地址，例如 0.0.0.0:1080 或 [::]:1080
    #[arg(short = 'b', long)]
    bind: Option<String>,

    /// 认证用户名（与密码同时提供才启用认证）
    #[arg(long)]
    username: Option<String>,

    /// 认证密码
    #[arg(long)]
    password: Option<String>,

    /// 是否启用随机出口 IPv6（true/false）
    #[arg(long)]
    random_ipv6: Option<bool>,

    /// IPv6 块，例如 2001:db8::/48（可重复，也支持逗号分隔）
    #[arg(long)]
    ipv6_block: Vec<String>,

    /// 启用随机出口 IPv6 时，拒绝 IPv4 目标
    #[arg(long)]
    force_ipv6: Option<bool>,

    /// 双向拷贝缓冲区大小（字节）
    #[arg(long)]
    buffer_size: Option<usize>,

    /// 最大并发连接数（0 = 不限）
    #[arg(long)]
    max_connections: Option<usize>,

    /// 握手/请求超时（秒）
    #[arg(long)]
    handshake_timeout: Option<u64>,

    /// 连接空闲超时（秒，0 = 禁用；双向共享）
    #[arg(long)]
    idle_timeout: Option<u64>,

    /// 日志级别 trace/debug/info/warn/error
    #[arg(long)]
    log_level: Option<String>,
}

// ============================ 配置 ============================

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    bind_addr: Option<String>,
    username: Option<String>,
    password: Option<String>,
    random_egress_ipv6: Option<bool>,
    ipv6_blocks: Option<Vec<String>>,
    force_ipv6: Option<bool>,
    buffer_size: Option<usize>,
    max_connections: Option<usize>,
    handshake_timeout: Option<u64>,
    idle_timeout: Option<u64>,
    log_level: Option<String>,
}

#[derive(Debug, Clone)]
struct Config {
    bind_addr: String,
    username: Option<String>,
    password: Option<String>,
    random_egress_ipv6: bool,
    ipv6_blocks: Vec<String>,
    force_ipv6: bool,
    buffer_size: usize,
    max_connections: usize,
    handshake_timeout_secs: u64,
    idle_timeout_secs: u64,
    log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: "0.0.0.0:1080".to_string(),
            username: None,
            password: None,
            random_egress_ipv6: false,
            ipv6_blocks: Vec::new(),
            force_ipv6: false,
            buffer_size: 4096,
            max_connections: 0,
            handshake_timeout_secs: 10,
            idle_timeout_secs: 0,
            log_level: "info".to_string(),
        }
    }
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1) 配置文件
    let file_cfg: FileConfig = {
        let path = Path::new(&args.config);
        if path.exists() {
            let s = fs::read_to_string(path)?;
            toml::from_str(&s)?
        } else {
            FileConfig::default()
        }
    };

    let mut cfg = Config::default();

    if let Some(v) = file_cfg.bind_addr { cfg.bind_addr = v; }
    if let Some(v) = file_cfg.username { cfg.username = Some(v); }
    if let Some(v) = file_cfg.password { cfg.password = Some(v); }
    if let Some(v) = file_cfg.random_egress_ipv6 { cfg.random_egress_ipv6 = v; }
    if let Some(v) = file_cfg.force_ipv6 { cfg.force_ipv6 = v; }
    if let Some(v) = file_cfg.buffer_size { cfg.buffer_size = v; }
    if let Some(v) = file_cfg.max_connections { cfg.max_connections = v; }
    if let Some(v) = file_cfg.handshake_timeout { cfg.handshake_timeout_secs = v; }
    if let Some(v) = file_cfg.idle_timeout { cfg.idle_timeout_secs = v; }
    if let Some(v) = file_cfg.log_level { cfg.log_level = v; }
    if let Some(v) = file_cfg.ipv6_blocks { cfg.ipv6_blocks.extend(v); }

    // 2) 环境变量（优先级高于配置文件）
    if let Ok(v) = env::var("SOCKS5_BIND") { cfg.bind_addr = v; }
    if let Ok(v) = env::var("SOCKS5_USERNAME") { cfg.username = Some(v); }
    if let Ok(v) = env::var("SOCKS5_PASSWORD") { cfg.password = Some(v); }
    if let Ok(v) = env::var("SOCKS5_RANDOM_IPV6") {
        cfg.random_egress_ipv6 = v.eq_ignore_ascii_case("true") || v == "1";
    }
    if let Ok(v) = env::var("SOCKS5_IPV6_BLOCKS") {
        cfg.ipv6_blocks.extend(
            v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        );
    }
    if let Ok(v) = env::var("SOCKS5_FORCE_IPV6") {
        cfg.force_ipv6 = v.eq_ignore_ascii_case("true") || v == "1";
    }
    if let Ok(v) = env::var("SOCKS5_BUFFER_SIZE") {
        if let Ok(n) = v.parse::<usize>() { cfg.buffer_size = n; }
    }
    if let Ok(v) = env::var("SOCKS5_MAX_CONNECTIONS") {
        if let Ok(n) = v.parse::<usize>() { cfg.max_connections = n; }
    }
    if let Ok(v) = env::var("SOCKS5_HANDSHAKE_TIMEOUT") {
        if let Ok(n) = v.parse::<u64>() { cfg.handshake_timeout_secs = n; }
    }
    if let Ok(v) = env::var("SOCKS5_IDLE_TIMEOUT") {
        if let Ok(n) = v.parse::<u64>() { cfg.idle_timeout_secs = n; }
    }
    if let Ok(v) = env::var("SOCKS5_LOG") { cfg.log_level = v; }

    // 3) 命令行参数（优先级最高）
    if let Some(v) = args.bind { cfg.bind_addr = v; }
    if let Some(v) = args.username { cfg.username = Some(v); }
    if let Some(v) = args.password { cfg.password = Some(v); }
    if let Some(v) = args.random_ipv6 { cfg.random_egress_ipv6 = v; }
    if let Some(v) = args.force_ipv6 { cfg.force_ipv6 = v; }
    if let Some(v) = args.buffer_size { cfg.buffer_size = v; }
    if let Some(v) = args.max_connections { cfg.max_connections = v; }
    if let Some(v) = args.handshake_timeout { cfg.handshake_timeout_secs = v; }
    if let Some(v) = args.idle_timeout { cfg.idle_timeout_secs = v; }
    if let Some(v) = args.log_level { cfg.log_level = v; }
    if !args.ipv6_block.is_empty() {
        cfg.ipv6_blocks.extend(args.ipv6_block);
    }

    // 校验
    if cfg.random_egress_ipv6 && cfg.ipv6_blocks.is_empty() {
        return Err("random_egress_ipv6 已启用，但未配置 ipv6_blocks".into());
    }
    if cfg.username.is_some() != cfg.password.is_some() {
        return Err("username 和 password 必须同时配置或同时不配置".into());
    }
    cfg.buffer_size = cfg.buffer_size.clamp(1024, 65536);

    Ok(cfg)
}

// ============================ IPv6 块 ============================

#[derive(Debug, Clone, Copy)]
struct Ipv6Block {
    network: Ipv6Addr,
    prefix_len: u8,
}

fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let mut o = addr.octets();
    let full = (prefix_len / 8) as usize;
    let rem = prefix_len % 8;
    for i in full..16 {
        o[i] = 0;
    }
    if rem > 0 && full < 16 {
        let mask: u8 = 0xff << (8 - rem);
        o[full] &= mask;
    }
    Ipv6Addr::from(o)
}

impl Ipv6Block {
    fn parse(s: &str) -> Result<Self, String> {
        let (ip_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| format!("IPv6 块格式错误（缺少 '/'）: {s}"))?;
        let network: Ipv6Addr = ip_str
            .trim()
            .parse()
            .map_err(|_| format!("非法 IPv6 地址: {ip_str}"))?;
        let prefix_len: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| format!("非法前缀长度: {prefix_str}"))?;
        if prefix_len > 128 {
            return Err(format!("前缀长度不能大于 128: {s}"));
        }
        Ok(Ipv6Block { network: mask_ipv6(network, prefix_len), prefix_len })
    }

    /// 在块内随机生成一个可用的源地址
    fn random_ip(&self, rng: &mut impl Rng) -> Ipv6Addr {
        let mut o = self.network.octets();
        let full = (self.prefix_len / 8) as usize;
        let rem = (self.prefix_len % 8) as u32;

        // 前缀保持不变，主机位随机
        for i in full..16 {
            o[i] = rng.gen::<u8>();
        }
        if rem > 0 {
            let mask: u8 = 0xff << (8 - rem);
            o[full] = (o[full] & mask) | (rng.gen::<u8>() & !mask);
        }

        // 避免主机位全 0（子网路由器任播 / 全零接口标识，不能作为源地址）
        let host_bits = 128 - self.prefix_len as u32;
        if host_bits > 0 && host_bits < 128 {
            let mut host_zero = true;
            for i in full..16 {
                if i == full && rem > 0 {
                    let mask: u8 = 0xff << (8 - rem);
                    if o[i] & !mask != 0 { host_zero = false; }
                } else if o[i] != 0 {
                    host_zero = false;
                }
            }
            if host_zero {
                if rem > 0 {
                    o[full] |= 1;
                } else {
                    o[15] |= 1;
                }
            }
        }
        Ipv6Addr::from(o)
    }
}

fn parse_ipv6_blocks(list: &[String]) -> Result<Vec<Ipv6Block>, String> {
    let mut out = Vec::new();
    for item in list {
        for part in item.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            out.push(Ipv6Block::parse(part)?);
        }
    }
    Ok(out)
}

fn random_egress_ipv6(blocks: &[Ipv6Block]) -> Option<Ipv6Addr> {
    if blocks.is_empty() {
        return None;
    }
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..blocks.len());
    Some(blocks[idx].random_ip(&mut rng))
}

// ============================ 运行上下文 ============================

struct Ctx {
    config: Config,
    blocks: Vec<Ipv6Block>,
    semaphore: Option<Arc<Semaphore>>,
    handshake_timeout: Duration,
    idle_timeout: Option<Duration>,
    active: AtomicUsize,
}

/// 活跃连接守卫：无论任务是否 panic，都会正确递减连接计数
struct ActiveGuard(Arc<Ctx>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

// ============================ SOCKS5 协议 ============================

enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

/// 常数时间比较，避免时序侧信道泄露密码
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SOCKS5 握手：协商 + 可选 RFC1929 用户名/密码认证
async fn handshake(stream: &mut TcpStream, ctx: &Ctx) -> io::Result<()> {
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "非 SOCKS5 协议"));
    }
    let nmethods = stream.read_u8().await?;
    if nmethods == 0 {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(Error::new(ErrorKind::InvalidData, "无认证方法"));
    }
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    let auth_required = ctx.config.username.is_some() && ctx.config.password.is_some();
    let method = if auth_required {
        if methods.contains(&0x02) { 0x02 } else { 0xff }
    } else {
        if methods.contains(&0x00) { 0x00 } else { 0xff }
    };
    stream.write_all(&[0x05, method]).await?;
    if method == 0xff {
        return Err(Error::new(ErrorKind::Other, "没有可接受的认证方法"));
    }

    if method == 0x02 {
        let ver = stream.read_u8().await?;
        if ver != 0x01 {
            return Err(Error::new(ErrorKind::InvalidData, "非 RFC1929 认证"));
        }
        let ulen = stream.read_u8().await? as usize;
        let mut user = vec![0u8; ulen];
        stream.read_exact(&mut user).await?;
        let plen = stream.read_u8().await? as usize;
        let mut pass = vec![0u8; plen];
        stream.read_exact(&mut pass).await?;

        let user_ok = ctx
            .config
            .username
            .as_ref()
            .map(|u| constant_time_eq(u.as_bytes(), &user))
            .unwrap_or(false);
        let pass_ok = ctx
            .config
            .password
            .as_ref()
            .map(|p| constant_time_eq(p.as_bytes(), &pass))
            .unwrap_or(false);
        let ok = user_ok && pass_ok;
        stream.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await?;
        if !ok {
            return Err(Error::new(ErrorKind::PermissionDenied, "认证失败"));
        }
    }
    Ok(())
}

async fn read_target_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(TargetAddr, u16)> {
    let atyp = r.read_u8().await?;
    let addr = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        0x03 => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            let domain = String::from_utf8(b)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "域名非法"))?;
            TargetAddr::Domain(domain)
        }
        0x04 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "不支持的地址类型")),
    };
    let port = r.read_u16().await?;
    Ok((addr, port))
}

/// 读取 SOCKS5 请求（VER/CMD/RSV/ATYP/ADDR/PORT）
async fn read_request(stream: &mut TcpStream) -> io::Result<(u8, TargetAddr, u16)> {
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "非 SOCKS5 请求"));
    }
    let cmd = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    if rsv != 0x00 {
        return Err(Error::new(ErrorKind::InvalidData, "RSV 字段必须为 0"));
    }
    let (target, port) = read_target_addr(stream).await?;
    Ok((cmd, target, port))
}

async fn write_reply<W: AsyncWrite + Unpin>(w: &mut W, rep: u8, addr: SocketAddr) -> io::Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.push(0x05);
    buf.push(rep);
    buf.push(0x00);
    match addr {
        SocketAddr::V4(a) => {
            buf.push(0x01);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(0x04);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    w.write_all(&buf).await
}

async fn fail_reply(w: &mut TcpStream, rep: u8) -> io::Result<()> {
    write_reply(w, rep, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await
}

async fn resolve_target(target: &TargetAddr, port: u16, prefer_v6: bool) -> io::Result<SocketAddr> {
    match target {
        TargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        TargetAddr::Domain(domain) => {
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((domain.as_str(), port)).await?.collect();
            if addrs.is_empty() {
                return Err(Error::new(ErrorKind::NotFound, "域名解析无结果"));
            }
            if prefer_v6 {
                if let Some(a) = addrs.iter().find(|a| a.is_ipv6()) {
                    return Ok(*a);
                }
            }
            Ok(addrs[0])
        }
    }
}

/// 出站连接：可先绑定随机源 IPv6，再 connect
async fn connect_to(target: SocketAddr, egress: Option<Ipv6Addr>) -> io::Result<TcpStream> {
    match target {
        SocketAddr::V4(addr) => {
            let sock = TcpSocket::new_v4()?;
            sock.connect(SocketAddr::V4(addr)).await
        }
        SocketAddr::V6(addr) => {
            let sock = TcpSocket::new_v6()?;
            if let Some(src) = egress {
                sock.bind(SocketAddr::new(IpAddr::V6(src), 0))?;
            }
            sock.connect(SocketAddr::V6(addr)).await
        }
    }
}

/// CONNECT 命令
async fn cmd_connect(client: TcpStream, ctx: Arc<Ctx>, target: TargetAddr, port: u16) -> io::Result<()> {
    let prefer_v6 = ctx.config.random_egress_ipv6;

    let target_addr = match resolve_target(&target, port, prefer_v6).await {
        Ok(a) => a,
        Err(e) => {
            let mut c = client;
            fail_reply(&mut c, 0x04).await?; // 主机不可达
            return Err(e);
        }
    };

    // 强制 IPv6 出口时拒绝 IPv4 目标
    if ctx.config.random_egress_ipv6 && ctx.config.force_ipv6 && target_addr.is_ipv4() {
        let mut c = client;
        fail_reply(&mut c, 0x02).await?; // 规则不允许
        return Err(Error::new(ErrorKind::AddrNotAvailable, "强制 IPv6 出口，拒绝 IPv4 目标"));
    }

    let egress = if ctx.config.random_egress_ipv6 && target_addr.is_ipv6() {
        random_egress_ipv6(&ctx.blocks)
    } else {
        None
    };

    // 出站连接加 30s 上限，避免连黑洞 IP 时任务长时间挂起
    let server = match tokio::time::timeout(
        Duration::from_secs(30),
        connect_to(target_addr, egress),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let mut c = client;
            fail_reply(&mut c, 0x05).await?; // 连接被拒
            return Err(e);
        }
        Err(_) => {
            let mut c = client;
            fail_reply(&mut c, 0x05).await?;
            return Err(Error::new(ErrorKind::TimedOut, "出站连接超时"));
        }
    };
    let _ = server.set_nodelay(true);
    let local = server.local_addr()?;

    let mut c = client;
    write_reply(&mut c, 0x00, local).await?;
    let peer = c.peer_addr().ok();
    debug!("CONNECT {:?} -> {}（出口 {}）", peer, target_addr, local);
    // 转发阶段无整体超时，仅受可选的“双向共享空闲超时”约束
    bidirectional_copy(c, server, ctx.config.buffer_size, ctx.idle_timeout).await
}

/// BIND 命令（FTP 主动模式等）
async fn cmd_bind(client: TcpStream, ctx: Arc<Ctx>, _target: TargetAddr, _port: u16) -> io::Result<()> {
    let mut c = client;
    let client_is_v6 = c.peer_addr()?.is_ipv6();

    let listener = if client_is_v6 {
        let egress = if ctx.config.random_egress_ipv6 {
            random_egress_ipv6(&ctx.blocks)
        } else {
            None
        };
        let ip = egress.unwrap_or(Ipv6Addr::UNSPECIFIED);
        let sock = TcpSocket::new_v6()?;
        sock.bind(SocketAddr::new(IpAddr::V6(ip), 0))?;
        sock.listen(1024)?
    } else {
        let sock = TcpSocket::new_v4()?;
        sock.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        sock.listen(1024)?
    };

    let local = listener.local_addr()?;
    write_reply(&mut c, 0x00, local).await?;

    let (target, taddr) =
        match tokio::time::timeout(Duration::from_secs(120), listener.accept()).await {
            Ok(res) => res?,
            Err(_) => {
                write_reply(&mut c, 0x05, local).await?;
                return Err(Error::new(ErrorKind::TimedOut, "BIND 等待对端连接超时"));
            }
        };
    let _ = target.set_nodelay(true);
    write_reply(&mut c, 0x00, taddr).await?;
    let peer = c.peer_addr().ok();
    debug!("BIND {:?} -> {}（监听 {}）", peer, taddr, local);
    bidirectional_copy(c, target, ctx.config.buffer_size, ctx.idle_timeout).await
}

/// UDP ASSOCIATE：创建 UDP 中继（支持随机出口 IPv6 源地址）
async fn cmd_udp_associate(client: TcpStream, ctx: Arc<Ctx>) -> io::Result<()> {
    let mut c = client;
    let client_addr = c.peer_addr()?;
    let client_is_v6 = client_addr.is_ipv6();

    let relay = if client_is_v6 {
        let egress = if ctx.config.random_egress_ipv6 {
            random_egress_ipv6(&ctx.blocks)
        } else {
            None
        };
        let ip = egress.unwrap_or(Ipv6Addr::UNSPECIFIED);
        UdpSocket::bind(SocketAddr::new(IpAddr::V6(ip), 0)).await?
    } else {
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?
    };
    let relay_addr = relay.local_addr()?;
    write_reply(&mut c, 0x00, relay_addr).await?;

    let mut task = tokio::spawn(udp_relay(relay, client_addr, ctx.idle_timeout));
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            r = c.read(&mut buf) => {
                match r {
                    Ok(0) | Err(_) => break, // 控制连接关闭
                    Ok(_) => continue,       // 忽略控制通道上的杂散数据
                }
            }
            _ = &mut task => break, // 中继已结束（如空闲超时）
        }
    }
    task.abort();
    Ok(())
}

/// UDP 中继循环：解析 SOCKS5 UDP 头并双向转发。
///
/// 方向判定：来源 IP == 客户端 IP 视为客户端数据报（同时更新客户端实际 UDP 来源）；
/// 其余来源一律视为目标回包转发给客户端（宽松策略，兼容回包源端口与请求端口不一致的场景）。
async fn udp_relay(sock: UdpSocket, control_client: SocketAddr, idle_timeout: Option<Duration>) {
    let mut buf = vec![0u8; 65536];
    let mut client = control_client;
    loop {
        let recv = sock.recv_from(&mut buf);
        let (n, src) = match idle_timeout {
            Some(t) => match tokio::time::timeout(t, recv).await {
                Ok(Ok(x)) => x,
                _ => break,
            },
            None => match recv.await {
                Ok(x) => x,
                Err(_) => break,
            },
        };

        if src.ip() == client.ip() {
            // 来自客户端的 SOCKS5 UDP 数据报，记录实际 UDP 来源
            client = src;
            if n < 4 { continue; }
            if buf[0] != 0 || buf[1] != 0 { continue; } // RSV 必须为 0
            if buf[2] != 0 { continue; }                // 暂不支持分片（FRAG）
            let atyp = buf[3];
            let mut off = 4usize;

            let target_ip = match atyp {
                0x01 => {
                    if n < off + 4 + 2 { continue; }
                    let ip = Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
                    off += 4;
                    IpAddr::V4(ip)
                }
                0x03 => {
                    if n < off + 1 { continue; }
                    let len = buf[off] as usize;
                    off += 1;
                    if n < off + len + 2 { continue; }
                    let domain = match std::str::from_utf8(&buf[off..off + len]) {
                        Ok(d) => d.to_string(),
                        Err(_) => continue,
                    };
                    off += len;
                    // 先取出 owned 的解析结果，避免 domain 的借用跨块存活
                    let resolved: Option<IpAddr> =
                        match tokio::net::lookup_host((domain.as_str(), 0)).await {
                            Ok(mut addrs) => addrs.next().map(|a| a.ip()),
                            Err(_) => None,
                        };
                    match resolved {
                        Some(ip) => ip,
                        None => continue,
                    }
                }
                0x04 => {
                    if n < off + 16 + 2 { continue; }
                    let mut oct = [0u8; 16];
                    oct.copy_from_slice(&buf[off..off + 16]);
                    off += 16;
                    IpAddr::V6(Ipv6Addr::from(oct))
                }
                _ => continue,
            };
            if n < off + 2 { continue; }
            let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
            off += 2;
            let target = SocketAddr::new(target_ip, port);
            if let Err(e) = sock.send_to(&buf[off..n], target).await {
                debug!("UDP 转发失败: {e}");
            }
        } else {
            // 来自目标的回包，封装 SOCKS5 UDP 头后发给客户端
            let mut hdr = Vec::with_capacity(4 + 18 + n);
            hdr.push(0);
            hdr.push(0);
            hdr.push(0);
            match src {
                SocketAddr::V4(a) => {
                    hdr.push(0x01);
                    hdr.extend_from_slice(&a.ip().octets());
                }
                SocketAddr::V6(a) => {
                    hdr.push(0x04);
                    hdr.extend_from_slice(&a.ip().octets());
                }
            }
            hdr.extend_from_slice(&src.port().to_be_bytes());
            hdr.extend_from_slice(&buf[..n]);
            if let Err(e) = sock.send_to(&hdr, client).await {
                debug!("UDP 回包失败: {e}");
            }
        }
    }
}

/// 分发命令并执行（数据转发阶段）
async fn dispatch(
    stream: TcpStream,
    ctx: Arc<Ctx>,
    cmd: u8,
    target: TargetAddr,
    port: u16,
) -> io::Result<()> {
    match cmd {
        0x01 => cmd_connect(stream, ctx, target, port).await,
        0x02 => cmd_bind(stream, ctx, target, port).await,
        0x03 => cmd_udp_associate(stream, ctx).await,
        _ => {
            let mut s = stream;
            fail_reply(&mut s, 0x07).await?; // 命令不支持
            Err(Error::new(ErrorKind::InvalidData, "不支持的命令"))
        }
    }
}

/// 每个客户端连接的总入口
async fn handle_connection(stream: TcpStream, ctx: Arc<Ctx>) {
    let peer = stream.peer_addr().ok();
    let mut s = stream;
    let _ = s.set_nodelay(true);

    // 只有“握手 + 读取请求”需要超时保护；进入数据转发阶段后不做整体超时，
    // 避免长连接（下载/SSH/流媒体）被误杀。
    let req = async {
        tokio::time::timeout(ctx.handshake_timeout, handshake(&mut s, &ctx))
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "握手超时"))??;
        tokio::time::timeout(ctx.handshake_timeout, read_request(&mut s))
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "请求读取超时"))?
    }
    .await;

    match req {
        Ok((cmd, target, port)) => {
            let result = dispatch(s, ctx, cmd, target, port).await;
            if let Err(e) = result {
                debug!("连接结束（{e}）: {:?}", peer);
            }
        }
        Err(e) => {
            debug!("握手/请求失败（{e}）: {:?}", peer);
        }
    }
}

// ============================ 双向数据搬运 ============================

/// 连接级空闲计时器：两个方向共享，任一方向有数据即刷新，
/// 避免“单向长传（如下载大文件）”被误判为空闲。
struct IdleTimer {
    last: Mutex<tokio::time::Instant>,
    timeout: Duration,
}

impl IdleTimer {
    fn new(timeout: Duration) -> Self {
        IdleTimer { last: Mutex::new(tokio::time::Instant::now()), timeout }
    }

    fn touch(&self) {
        if let Ok(mut g) = self.last.lock() {
            *g = tokio::time::Instant::now();
        }
    }

    fn deadline(&self) -> tokio::time::Instant {
        let last = self
            .last
            .lock()
            .map(|g| *g)
            .unwrap_or_else(|_| tokio::time::Instant::now());
        last + self.timeout
    }
}

/// 单向拷贝：读 r、写 w；可选共享空闲计时器
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    buf: &mut [u8],
    timer: Option<&IdleTimer>,
) -> io::Result<()> {
    loop {
        match timer {
            None => {
                let n = match r.read(buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                w.write_all(&buf[..n]).await?;
            }
            Some(t) => {
                let sleep = tokio::time::sleep_until(t.deadline());
                tokio::pin!(sleep);
                tokio::select! {
                    res = r.read(buf) => {
                        match res {
                            Ok(0) => break,
                            Ok(n) => {
                                t.touch(); // 收到数据即视为连接活跃
                                w.write_all(&buf[..n]).await?;
                            }
                            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    _ = &mut sleep => {
                        // 到期后复查：另一方向可能刚刷新过计时器
                        if tokio::time::Instant::now() >= t.deadline() {
                            return Err(Error::new(ErrorKind::TimedOut, "连接空闲超时"));
                        }
                        // 否则继续循环，按新 deadline 重建 sleep
                    }
                }
            }
        }
    }
    Ok(())
}

/// 双向并发拷贝：任一方结束/出错立即返回，避免另一方向长时间挂起
async fn bidirectional_copy(
    a: TcpStream,
    b: TcpStream,
    buf_size: usize,
    idle_timeout: Option<Duration>,
) -> io::Result<()> {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();
    let mut buf_a = vec![0u8; buf_size];
    let mut buf_b = vec![0u8; buf_size];

    let timer = idle_timeout.map(IdleTimer::new);

    let a_to_b = pump(&mut br, &mut aw, &mut buf_a, timer.as_ref());
    let b_to_a = pump(&mut ar, &mut bw, &mut buf_b, timer.as_ref());

    tokio::pin!(a_to_b);
    tokio::pin!(b_to_a);

    tokio::select! {
        r = &mut a_to_b => r,
        r = &mut b_to_a => r,
    }
}

// ============================ 监听器 / 信号 / 统计 ============================

fn create_listener(bind: SocketAddr) -> io::Result<TcpListener> {
    let sock = match bind {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    sock.set_reuseaddr(true)?;
    sock.bind(bind)?;
    sock.listen(16384)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("安装 SIGTERM 信号处理器失败");
        let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("安装 SIGINT 信号处理器失败");
        tokio::select! {
            _ = term.recv() => info!("收到 SIGTERM"),
            _ = int.recv() => info!("收到 SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn stats_loop(ctx: Arc<Ctx>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.tick().await; // 跳过首次立即触发的 tick
    loop {
        interval.tick().await;
        info!("当前活跃连接数: {}", ctx.active.load(Ordering::Relaxed));
    }
}

// ============================ main ============================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load_config()?;

    // 日志
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let bind: SocketAddr = cfg
        .bind_addr
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, format!("无效的监听地址: {}", cfg.bind_addr)))?;

    let listener = create_listener(bind)?;
    let local = listener.local_addr()?;

    let blocks = parse_ipv6_blocks(&cfg.ipv6_blocks)?;
    let semaphore = if cfg.max_connections > 0 {
        Some(Arc::new(Semaphore::new(cfg.max_connections)))
    } else {
        None
    };

    let ctx = Arc::new(Ctx {
        config: cfg.clone(),
        blocks,
        semaphore,
        handshake_timeout: Duration::from_secs(cfg.handshake_timeout_secs),
        idle_timeout: if cfg.idle_timeout_secs > 0 {
            Some(Duration::from_secs(cfg.idle_timeout_secs))
        } else {
            None
        },
        active: AtomicUsize::new(0),
    });

    info!("SOCKS5 代理已启动，监听 {local}");
    info!("认证: {}", if cfg.username.is_some() { "启用" } else { "未启用" });
    if cfg.random_egress_ipv6 {
        info!("随机出口 IPv6: 启用，共 {} 个块: {:?}", ctx.blocks.len(), cfg.ipv6_blocks);
    }

    let stats_handle = tokio::spawn(stats_loop(ctx.clone()));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("收到退出信号，停止接受新连接");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, addr)) => {
                        let ctx_for_task = ctx.clone();

                        // 有最大连接数限制时获取信号量；无限制时始终放行
                        let mut permit: Option<tokio::sync::OwnedSemaphorePermit> = None;
                        let mut accepted = true;
                        if let Some(sem) = &ctx_for_task.semaphore {
                            match sem.clone().try_acquire_owned() {
                                Ok(p) => permit = Some(p),
                                Err(_) => accepted = false,
                            }
                        }

                        if accepted {
                            ctx_for_task.active.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _guard = ActiveGuard(ctx_for_task.clone()); // 保证计数递减
                                let _permit = permit;                          // 连接结束才释放信号量
                                handle_connection(stream, ctx_for_task).await;
                            });
                        } else {
                            warn!("达到最大连接数上限，拒绝 {addr}");
                            drop(stream);
                        }
                    }
                    Err(e) => {
                        error!("accept 错误: {e}");
                        // 防止 accept 持续报错（如 EMFILE）时 CPU 空转
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    // 优雅退出：停止接受新连接，等待在途连接结束（最多 10 秒）
    drop(listener);
    info!("等待在途连接结束（最多 10 秒）...");
    let mut waited = 0u32;
    while ctx.active.load(Ordering::Relaxed) > 0 {
        if waited >= 100 {
            warn!(
                "等待超时，强制退出（仍有 {} 个连接）",
                ctx.active.load(Ordering::Relaxed)
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        waited += 1;
    }
    stats_handle.abort();
    info!("代理已退出");
    Ok(())
}
