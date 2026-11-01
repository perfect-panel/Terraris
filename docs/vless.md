# B5 VLESS 接入

日期：2026-11-01。首个协议由原计划的 SS2022 改为 VLESS，包含普通 UDP、XUDP 和 VLESS Encryption。现在有实际 Rust 协议驱动、共享 flow 策略、监听器和 `terraris run`，已在本机用固定版本 Xray 客户端验证；尚未完成生产面板、跨节点 Redis 竞争、Linux 部署和性能验证。

## 能力范围

| 项目 | 当前实现 |
| --- | --- |
| VLESS | version 0、UUID 多用户、TCP command 1、UDP command 2、XUDP command 3 |
| UDP | u16 长度报文，保留空包与边界，最大应用报文 65507 字节 |
| XUDP | New / Keep / End / KeepAlive、多个逻辑 UDP 会话、逐包目的地址、回复来源地址、会话与队列上限 |
| Encryption | `mlkem768x25519plus`；`native`、`xorpub`、`random` |
| 密钥 | X25519 32 字节私钥、ML-KEM-768 64 字节 seed，以及最多 8 项混合密钥链 |
| 握手 | 混合 ML-KEM-768 + X25519 PFS、1-RTT、带票据的 0-RTT；AES-256-GCM / ChaCha20-Poly1305 自动识别 |
| 记录 | 认证的长度/记录头、增量 nonce、溢出后换钥、短读写、取消/截断/认证失败处理 |
| 用户策略 | 热增删、改凭据撤销、跨连接和上下行共享限速、全局订阅/IP 设备准入、TTL 续期 |
| 重载 | 同端口共享 accept loop，候选失败保留活跃路由，旧连接限时排空；相同 Encryption 配置保留票据缓存 |
| 出站 | 系统 DNS、直连 TCP/UDP、地址族策略；配置了未实现的 DNS/路由/block/outbound 会拒绝候选 |

当前载体为 TCP。TLS、REALITY、Vision、XHTTP、WebSocket/gRPC 等组合没有实现；相关非默认字段会拒绝，不能仅凭 VLESS 名称认为所有组合均可用。VLESS 用户凭据须是可解析的 UUID，等价 UUID 编码冲突会拒绝整个用户快照。

XUDP 的 UDP socket 生命周期绑定当前承载连接。GlobalID 字段可以解析，但当前不在断开后通过 GlobalID 恢复旧 UDP socket，不承诺跨承载连接的出口端口保持。逻辑会话内的多个目的地址使用同一地址族 socket。普通 VLESS UDP 则只接受指定目标的回复。

## 运行

本地配置继续使用 [examples/terraris.toml](../examples/terraris.toml)。面板提供 VLESS 端口、UUID 用户及 Encryption 字段；本地配置控制监听地址和资源约束。

```toml
[node]
listen = "0.0.0.0"
allow_plaintext = false
memory_bytes = 67108864
buffer_slots = 16384
max_connections = 4096
max_handshakes = 128
```

```sh
cargo build --locked --release
./target/release/terraris check --config terraris.toml
./target/release/terraris run --config terraris.toml
```

`check` 保持只读；`run` 会拉取并提交配置、开启监听器、申请设备名额并发送在线/流量报告。外部地址监听默认要求启用 VLESS Encryption；没有 Encryption 的本地受信任承载可监听 loopback，或由操作者显式开启 `allow_plaintext`。不自动创建 TLS 证书，也不把面板要求的安全层降级为明文。

SIGINT/SIGTERM 先关闭准入，再排空、取消和等待任务回收，并冲刷待确认报告。`drain_timeout_seconds` 默认 30，`shutdown_timeout_seconds` 默认 5。宿主仍需遵守 Tokio 的协作式执行约束。

## 面板 Encryption 字段

- `encryption`：`none` 或 `mlkem768x25519plus`。
- `encryption_mode`：`native` / `xorpub` / `random`。
- `encryption_private_key`：无 padding 的 base64url 私钥或 seed，多个值以点连接。
- `encryption_ticket`：秒数或范围，例如 `0`、`600s`、`300-900s`。0 禁止服务端 0-RTT 恢复。
- `encryption_server_padding`：概率、长度、间隔规则，沿用 Xray 格式；为空时使用其默认规则。长度总量、规则数量和间隔总量均受限；padding 间隔计入握手超时，本地 `handshake_timeout_seconds` 需为所配规则留足时间。
- `encryption_rtt`、`encryption_client_padding`、`encryption_password` 是客户端订阅元数据。存在时校验其格式；提供客户端公钥链时还会验证它与服务端私钥链一致。

`encryption_rtt=1rtt` 描述客户端行为，服务端是否允许恢复由 ticket 生命周期决定。配置的客户端 metadata 不会被当成可忽略的任意字符串。

恢复票据只存在内存中，默认最多 1024 个，每票据最多 4096 个已用 NFS key 摘要。满额的新握手得到不缓存的票据；单票据重放集合满时使整个票据失效，要求重新握手，不删除旧摘要后继续接受该票据。重放检测不会因相同配置的代次切换而清零。票据过期/失效使用与 Xray 客户端兼容的重新握手响应；进程重启后也需要重新握手。

## Flow 与资源

每个 TCP/UDP 会话在任何设备请求、DNS、拨号或转发之前取得 B4 的准入许可，XUDP 新逻辑会话也单独检查准入。旧代次停止接入后，已有会话可以排空，但不能新增逻辑会话；用户删除或改 UUID 会取消相关旧版本。

限速按协议作用域和订阅 ID 聚合，所有连接、TCP/UDP 和两个方向共用一个桶。速率为 `Mbps × 125000` 字节/秒，0 为不限速。等待配额可取消，未实际写出的配额会退还；切换配置不会为仍在使用的用户重新发放一份独立带宽。

有限额设备使用面板 `/device` 的原子结果。规范化后的同一订阅/IP 跨协议合并申请，最多 32 个在途设备请求。确认有效期内，暂时续期失败允许继续使用；达到 TTL 或明确拒绝后停止转发。用户改为有限额时，未取得设备许可的旧会话不能继续发送。`/alivelist` 仅用于观测，不替代准入。

流量计数先预留用户记录和整数 headroom，再发起 I/O，成功后只提交实际写出的前缀。上传按目标 socket 接受的 payload 计，下载按客户端协议载体接受的 payload 计；Encryption 的完整记录写出后才返回明文字节数。协议头、加密 tag、padding 不计入用户流量。UDP 报文只有完整发送成功才计数。这里的成功仍表示接口接受，不是对端应用确认。

默认每连接 4 MiB / 256 个 buffer、32 个 XUDP 会话和 32 个回复队列报文。回复队列满时丢弃完整且尚未计费的 UDP 报文。物理 buffer 统一计入进程 Budget，私有握手和记录缓冲也使用 BufferScope。用户/任务/票据等元数据另有数量上限，不属于 buffer 字节口径，不能把 `memory_bytes` 当作 RSS 上限。

现阶段使用操作系统 DNS，最多保留 16 个候选地址并限制解析并发。系统 resolver 使用最多 64 个受持有的 blocking 任务；请求取消不会提前释放其并发许可，关闭会等待实际调用返回，无法强制抢占操作系统调用。它和 HTTP/TLS 依赖内部资源不属于 Terraris 的 buffer 分配口径。自定义 DNS、路由和出站尚未编译接入；启用 VLESS 时遇到这些非空配置会保留旧代次并报告不支持。空协议列表或全部禁用时仍会关闭入站，不因无消费者的出站字段阻止停服。

Reports 仍是内存队列。正常退出会冲刷，但崩溃不保留；PPanel 现有接口的 ACK 歧义仍可能造成重复计费。主机状态 sampler 仍是可选 library 端口，CLI 暂不发送主机 CPU/内存/磁盘数据。

## 验证与复现

普通测试覆盖 wire golden bytes、地址与长度边界、取消后的半帧、空 UDP、XUDP 资源上限、共享带宽、计数预留、设备并发合并与 TTL、用户撤销、同端口切换、候选回滚，以及 CLI 启动和 SIGTERM 退出。

额外的本地交叉验证固定使用 [Xray commit a4a3dff](https://github.com/XTLS/Xray-core/commit/a4a3dff5b20c2faae567b742c172c7b95e75c083)：

- 独立 Encryption 客户端：3 种外观 × 3 种密钥组合 × 2 个 AEAD × 2 个 RTT 模式，共 36 组；每组双向传输，0-RTT 组另验证重放拒绝。
- 完整 Xray：经 SOCKS 入口连接 Terraris，验证 TCP 与 XUDP，覆盖明文 loopback 和三种 Encryption 外观；保留同一 Xray 进程跨 Terraris 代次切换测试恢复票据。
- Go 生成的 KDF/AEAD 固定向量验证二进制 context、BLAKE3 块/树边界与两种 AEAD，Rust 记录测试覆盖 nonce 换钥和篡改拒绝。

复现外部客户端验证需 Go；Rust 的正常构建不需要它：

```sh
cd tests/interop/encryption
go build -o /tmp/terraris-encryption-client .
go build -mod=mod -o /tmp/terraris-xray github.com/xtls/xray-core/main
cd ../../..
TERRARIS_ENCRYPTION_CLIENT=/tmp/terraris-encryption-client \
  cargo test --locked --test vless_encryption_interop -- --ignored
TERRARIS_XRAY=/tmp/terraris-xray \
  cargo test --locked --test vless_runtime official_xray -- --ignored
```

`go build -mod=mod` 可能为完整 Xray 增补测试模块的间接依赖；它不修改 Cargo 依赖。源代码和许可证说明见 [THIRD_PARTY.md](../THIRD_PARTY.md)。这些结果来自 macOS 本机回环及模拟面板，不等于生产后端或跨节点设备名额竞争的验证。
