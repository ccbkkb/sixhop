# sixhop

单文件高性能 SOCKS5 代理，支持**用户名/密码认证**与**随机出口 IPv6**。基于 tokio 全异步实现，面向百万级并发连接设计。

## ✨ 特性

- ✅ 完整 SOCKS5 协议（RFC 1928）
  - `CONNECT`：正向代理（主场景）
  - `BIND`：支持 FTP 主动模式等反向连接场景
  - `UDP ASSOCIATE`：UDP 中继（DNS over SOCKS5、QUIC 等）
- ✅ 用户名/密码认证（RFC 1929），密码比较使用常数时间算法防时序侧信道
- ✅ **随机出口 IPv6**：支持配置一个或多个 IPv6 块（`/48`、`/64`、`/128` 等），每个出站连接绑定一个随机源 IPv6；`/128` 即固定出口
- ✅ 三种配置方式：命令行参数 / 环境变量 / TOML 配置文件（优先级从高到低）
- ✅ 全异步 tokio 多线程 runtime，无线程/连接，天然承载高并发
- ✅ 可调优参数：缓冲区大小、最大并发数、握手超时、双向共享空闲超时
- ✅ 优雅退出（SIGINT / SIGTERM）、信号量限流、活跃连接统计
- ✅ 完整 CI：多平台交叉编译 + 真实协议测试 + Alpine/Windows 实测 + GitHub Release

## 🧱 项目结构

```
sixhop/
├── .github/
│   └── workflows/
│       └── build.yml              # CI：编译矩阵 + 真实测试 + 产物导出 + Release
├── src/
│   └── main.rs                    # 全部程序逻辑（单文件）
├── tests/
│   └── socks5.rs                  # 真实 SOCKS5 协议集成测试（黑盒启动编译产物）
├── .gitignore
├── rust-toolchain.toml            # 固定 stable 工具链
├── Cargo.toml
├── Cargo.lock                     # 必须提交，保证可复现构建
├── socks5.example.toml            # 配置示例
└── README.md
```

## 🚀 快速开始

### 本地编译

```bash
cargo build --release
./target/release/sixhop --bind 127.0.0.1:1080
```

### 最小运行（无认证）

```bash
./target/release/sixhop --bind 127.0.0.1:1080
```

### 验证代理是否工作

```bash
curl --socks5-hostname 127.0.0.1:1080 http://example.com -o /dev/null

# 查看代理出口 IP（IPv4）
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

## ⚙️ 配置

配置优先级：**命令行参数 > 环境变量 > 配置文件 > 默认值**

### 1. 命令行参数

```bash
./target/release/sixhop \
  --bind 0.0.0.0:1080 \
  --username alice --password secret \
  --random-ipv6 true \
  --ipv6-block 2001:db8:aaaa::/48 \
  --ipv6-block 2400:1234::/64
```

完整参数：

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-c, --config <FILE>` | 配置文件路径 | `socks5.toml` |
| `-b, --bind <ADDR>` | 监听地址，如 `0.0.0.0:1080`、`[::]:1080` | `0.0.0.0:1080` |
| `--username <USER>` | 认证用户名（与密码同时设置才启用认证） | 无 |
| `--password <PASS>` | 认证密码 | 无 |
| `--random-ipv6 <BOOL>` | 启用随机出口 IPv6（`true`/`false`） | `false` |
| `--ipv6-block <CIDR>` | IPv6 块，可重复，也支持逗号分隔 | 无 |
| `--force-ipv6 <BOOL>` | 启用随机出口后，拒绝 IPv4 目标 | `false` |
| `--buffer-size <N>` | 每方向拷贝缓冲区（字节），范围 1024~65536 | `4096` |
| `--max-connections <N>` | 最大并发连接数，`0` = 不限 | `0` |
| `--handshake-timeout <SEC>` | 握手/请求读取超时（秒） | `10` |
| `--idle-timeout <SEC>` | 连接空闲超时（秒），`0` = 禁用（双向共享） | `0` |
| `--log-level <LVL>` | `trace` / `debug` / `info` / `warn` / `error` | `info` |

### 2. 环境变量

所有配置项都有对应的环境变量（前缀 `SOCKS5_`）：

| 环境变量 | 对应参数 |
|---|---|
| `SOCKS5_BIND` | `--bind` |
| `SOCKS5_USERNAME` | `--username` |
| `SOCKS5_PASSWORD` | `--password` |
| `SOCKS5_RANDOM_IPV6` | `--random-ipv6`（`true`/`1`） |
| `SOCKS5_IPV6_BLOCKS` | `--ipv6-block`（逗号分隔） |
| `SOCKS5_FORCE_IPV6` | `--force-ipv6` |
| `SOCKS5_BUFFER_SIZE` | `--buffer-size` |
| `SOCKS5_MAX_CONNECTIONS` | `--max-connections` |
| `SOCKS5_HANDSHAKE_TIMEOUT` | `--handshake-timeout` |
| `SOCKS5_IDLE_TIMEOUT` | `--idle-timeout` |
| `SOCKS5_LOG` | `--log-level` |

示例：

```bash
SOCKS5_BIND="0.0.0.0:1080" \
SOCKS5_USERNAME="alice" \
SOCKS5_PASSWORD="secret" \
SOCKS5_RANDOM_IPV6="true" \
SOCKS5_IPV6_BLOCKS="2001:db8:aaaa::/48,2400:1234::/64" \
./target/release/sixhop
```

### 3. 配置文件（TOML）

复制 `socks5.example.toml` 为 `socks5.toml`：

```toml
bind_addr = "0.0.0.0:1080"
username = "alice"
password = "secret"

# 随机出口 IPv6
random_egress_ipv6 = true
ipv6_blocks = [
    "2001:db8:aaaa::/48",
    "2400:1234:5678::/64",
    "2001:db8:cccc::1/128",   # /128 即固定出口
]

# 启用后 IPv4 目标一律拒绝（确保全部流量走 IPv6 出口）
force_ipv6 = false

# 调优
buffer_size = 4096
max_connections = 0
handshake_timeout = 10
idle_timeout = 0
log_level = "info"
```

```bash
./target/release/sixhop --config /path/to/socks5.toml
```

## 🌍 随机出口 IPv6（核心特性）

### 原理

开启 `random_egress_ipv6` 后，出站 TCP 连接不再使用系统默认路由，而是：

1. 从配置的 IPv6 块中随机选一块；
2. 在块内随机生成一个主机位非零的源地址；
3. 用 `tokio::net::TcpSocket` **先绑定该随机源地址，再 `connect`**；
4. 由内核根据源地址路由出去。

因此**每个连接都可以拥有独立的出口 IPv6**，适合需要"按连接轮换出口 IP"的场景。

### 系统前置要求

程序本身不配置网络，需要系统层面已就绪（用户自备）：

```bash
# 方式一：把整个块作为前缀配置到接口（内核视块内任意地址为本机地址）
ip -6 addr add 2001:db8:aaaa::1/48 dev eth0

# 方式二：允许绑定"非本机地址"（未配置前缀时的兜底方案）
sysctl -w net.ipv6.ip_nonlocal_bind=1
```

### 块规则

- `/128`：固定出口 IP
- `/64`、`/48` 等：主机位随机
- 生成时会避免"主机位全 0"（子网路由器任播地址，不能作为源地址）
- 多个块之间随机选取

### 与 IPv4 目标的组合

| 配置 | 行为 |
|---|---|
| `random_egress_ipv6=true, force_ipv6=false`（默认） | IPv6 目标走随机出口；IPv4 目标退回系统默认出口 |
| `random_egress_ipv6=true, force_ipv6=true` | IPv4 目标直接拒绝（`REP=0x02`），保证所有流量走 IPv6 |

## 🧪 测试

### 本地测试

```bash
cargo test --release
```

集成测试通过 `CARGO_BIN_EXE_sixhop` **黑盒启动真实编译产物**，用原始字节逐帧完成协议交互，不依赖任何外部服务：

| 测试 | 覆盖点 |
|---|---|
| `test_no_auth_connect_echo` | 无认证握手 + CONNECT + 数据回显 |
| `test_auth_connect_echo` | RFC1929 用户名/密码认证 + CONNECT |
| `test_wrong_password_rejected` | 错误密码被拒且连接关闭 |
| `test_no_auth_rejected_when_auth_enabled` | 开启认证后拒绝无认证方法 |
| `test_bind_command` | BIND 命令（FTP 主动模式场景） |
| `test_udp_associate` | UDP ASSOCIATE + 中继回显（UDP 端口与 TCP 端口不同） |
| `test_env_config` | 环境变量配置（`SOCKS5_BIND`/`SOCKS5_USERNAME`/`SOCKS5_PASSWORD`） |

### CI 测试

GitHub Actions 全流程覆盖（`random_egress_ipv6` 在 CI 中不启用）：

1. **协议级测试**：`cargo test --release`（上面 7 个用例）
2. **冒烟测试**：`127.0.0.1:1080` 启动代理，curl 实测裸 IP CONNECT、代理侧 DNS、真实公网出口、认证成功/失败
3. **Alpine 实测**：把 musl 产物放进 `alpine:3.20` 容器（x86_64 原生 + arm64 走 QEMU）真实运行
4. **Windows 实测**：在 `windows-latest` 上启动 MSVC 产物用 curl 验证

## 📦 编译与产物

### 本地交叉编译（用 cross）

```bash
# 安装 cross（GitHub Actions 中由 taiki-e/install-action 自动安装）
cargo install cross --locked

# 示例：编译 aarch64 静态 musl（Alpine 适用）
cross build --release --target aarch64-unknown-linux-musl
```

### GitHub Actions 自动产出的二进制

| 产物 | 适用平台 | 说明 |
|---|---|---|
| `sixhop-x86_64-unknown-linux-gnu.tar.gz` | 主流 Linux x64 | glibc |
| `sixhop-aarch64-unknown-linux-gnu.tar.gz` | 主流 Linux ARM64 | glibc |
| `sixhop-armv7-unknown-linux-gnueabihf.tar.gz` | 主流 Linux ARM32 | glibc |
| `sixhop-x86_64-unknown-linux-musl.tar.gz` | Alpine x86_64 | 静态 musl |
| `sixhop-aarch64-unknown-linux-musl.tar.gz` | Alpine ARM64 | 静态 musl |
| `sixhop-armv7-unknown-linux-musleabihf.tar.gz` | Alpine ARM32 | 静态 musl |
| `sixhop-x86_64-pc-windows-gnu.tar.gz` | Windows x64 | 无 VC 运行时依赖 |
| `sixhop-i686-pc-windows-gnu.tar.gz` | Windows 32 位 | 无 VC 运行时依赖 |
| `sixhop-x86_64-pc-windows-msvc.zip` | Windows x64 | MSVC 原生 |
| `sixhop-all-targets.tar.gz` | 全部汇总 + `SHA256SUMS.txt` | 最终交付包 |

### 触发方式

```bash
git push origin main                    # 自动触发全部构建与测试
git tag v0.1.0 && git push origin v0.1.0  # 自动发布 GitHub Release（含全部二进制）
```

## ⚡ 性能与百万级并发

### 设计要点

- **全异步**：tokio 多线程 runtime（worker = CPU 核数），每连接一个轻量任务，无线程/连接
- **低内存**：每连接仅 `2 × buffer_size` 字节缓冲区 + 任务开销；默认 4096 字节下，100 万连接约需 8GB 缓冲
- **无 JoinSet 泄漏**：连接任务使用 `tokio::spawn` + 活跃计数守卫，长期运行内存稳定
- **双向共享空闲超时**：下载大文件时"单向无数据"不会误杀连接
- **超时只覆盖握手/请求**：数据转发阶段无整体超时，长连接（SSH/下载/流媒体）不受限

### 部署调优建议

```bash
# 1. 文件描述符上限（systemd 用 LimitNOFILE=1048576）
ulimit -n 1048576

# 2. 内核参数
sysctl -w net.core.somaxconn=65535
sysctl -w fs.file-max=2000000
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# 3. 内存紧张时调小缓冲区
./sixhop --buffer-size 2048
```

### 内存预算公式

```
内存 ≈ 并发连接数 × (2 × buffer_size + 每任务约 3~5KB)
```

- 100 万连接 + 4KB 缓冲区 ≈ 12~16GB
- 想容纳更多连接就调小 `--buffer-size`

## 🔒 安全与健壮性

- 密码常数时间比较，防时序侧信道
- 握手/请求超时保护，防慢速攻击占资源
- 请求字段严格校验（协议版本、RSV 必须为 0）
- 出站连接 30s 超时，防连黑洞 IP 挂起
- 可选的 `max_connections` 信号量限流
- `accept` 报错时退避，避免 CPU 空转
- 优雅退出：SIGINT/SIGTERM → 停止接受新连接 → 等待在途连接（最多 10s）
- 纯安全代码：`#![forbid(unsafe_code)]`

## ⚠️ 已知限制

1. **UDP 分片（FRAG）不支持**：`FRAG != 0` 的数据报会被丢弃。绝大多数场景（DNS/QUIC）都使用 `FRAG=0`，如需分片重组可自行扩展。
2. **UDP 中继方向判定**：以"来源 IP 是否为客户端 IP"区分客户端数据报与目标回包；若客户端与目标位于**同一 IP**（生产环境几乎不会出现），回包可能被误判丢弃。
3. **IPv6 出口依赖系统配置**：随机源地址需系统已配置对应前缀（见上文"系统前置要求"），否则 `bind` 失败会返回连接失败。
4. **监听地址必须是 IP:端口**，不支持域名形式的 bind 地址。
5. **无内置流量统计/审计**：仅提供活跃连接数日志。

## 📜 License

MIT
