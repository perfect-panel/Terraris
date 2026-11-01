# Terraris

Terraris 是参考 Polaris 架构设计的 PPanel Rust 节点端项目，负责代理协议接入、用户认证、限速与设备准入，以及节点状态、在线设备和流量上报。

当前已完成 B1–B4 基础设施与控制面、B5 的 VLESS TCP、UDP/XUDP 和 VLESS Encryption 接入，以及 Trojan、AnyTLS、TLS 入站、UoT、共享路由、DNS 和 SOCKS5/HTTP/VLESS 出站。`terraris run` 可运行实际 Rust 节点，包含用户撤销、共享限速、设备租约与计量。已通过本机 Xray 和官方 AnyTLS 客户端互通；持久化上报、其他传输/协议及生产部署验证仍待完成。

- [架构设计](docs/architecture.md)：模块边界、状态管理、协议规划、故障处理与实施阶段。
- [PPanel 接口契约](docs/ppanel-api.md)：当前 backend 的实际接口、身份与计量语义、兼容性要求。
- [基础设施顺序](docs/infrastructure.md)：先完成资源、任务、buffer 和基础 I/O，再接控制面运行时。
- [Buffer 系统设计](docs/buffer.md)：所有权、前后预留空间、共享切片、内存预算、池化和背压。
- [B4 控制面与运行时](docs/control-plane.md)：事务提交、准入、代次切换、维护调度、报告与退出。
- [B5 VLESS 接入](docs/vless.md)：当前协议组合、Encryption 参数、运行方式和 Xray 互通复现。
- [TLS、Trojan、AnyTLS 与 UoT](docs/tls-protocols.md)：本地 PEM、证书热重载、多流、UDP 和客户端互通。
- [协议与传输注册表](docs/registries.md)：工厂扩展、别名、内置实现与热重载生命周期。
- [路由、DNS 与代理出站](docs/routing-dns.md)：规则语义、GeoData、解析缓存、DoH/DoT、重载与验证。

设计沿用 Polaris 的 `panel → supervisor/controller → protocol` 分层，以 `runtimekit` 统一运行时生命周期、以 `flow` 统一数据面策略。采用单进程、多协议结构，优先面向 Linux x86_64 和 aarch64。Rust 负责节点控制与协议集成；候选协议库必须能接入统一的用户策略、连接管理和流量计量。

## 已实现能力

- 单 Cargo package，提供 `terraris` 二进制和 library；使用 Rust 2024、Tokio、reqwest/rustls。
- `Provider → Connection → ServerClient / ProtocolClient / StatusClient` 面板端口；PPanel DTO 与领域模型分开。
- v2 配置、用户、全局在线 IP 数、设备名额申请，以及在线、流量和状态上报，覆盖 7 个端点。
- JSON / HTTP Protobuf 自动协商，也可固定编码；固定 schema 和构建时生成的 prost 绑定。
- 调用方持有的 ETag / 内容指纹；区分 304、成功空列表、请求失败，隔离连接、协议和编码的缓存。
- API 路径前缀、请求超时、请求与响应大小限制；禁用自动重定向及 HTTP 自动重试；错误不保留 URL query、远端消息或响应体。
- 订阅 ID 保持 int64 精度，规范化 Hysteria 协议名和 IPv4-mapped 地址，按协议读取当前证书指纹。
- resource 支持进程/多级作用域的字节与分配数量上限、原子批量预留、Reserved/Resident 快照、RAII 归还及关闭语义。
- buffer 提供固定容量 BufferLease、SharedBuffer 共享切片和 Bytes 所有权适配；支持受限缓存池、混合批量预留，以及字节/消息双限额队列。
- task/time 提供有上限的任务组、取消传播、等待与 abort 后回收、单调截止时间和独立的 Unix 毫秒类型。
- network/dataplane 提供未解析地址元数据、TCP 连接与有预算的双向转发、UDP 收发和超限检测；codec 提供有界基本类型/地址读写及增量长度帧。
- telemetry 提供固定维度原子计数、RAII 活动指标、快照和 Prometheus 文本，不保存用户地址或 payload 标签。

- scheduler/users/runtimekit 提供有界维护调度、用户版本 CAS、会话撤销信号、准入门、任务和排空生命周期。
- Controller/Supervisor 提供配置与用户同步、候选回滚、跨代次共享状态、退役清理、可选主机状态采样与指纹发布。
- Reports 提供有上限的内存流量/在线状态、批次确认和最终冲刷；进程重启不保留，面板 ACK 丢失仍有重复计费风险。

- protocol/outbound/transport 提供不可变工厂注册表；启动时注册和验证别名，Node 经注册表装配，支持自定义协议与流载体。
- VLESS 实际驱动支持 UUID 多用户、TCP/UDP/XUDP、三种 VLESS Encryption 外观和 1-RTT/0-RTT；使用统一的限速、设备和计量策略。
- Trojan 支持 TLS/TCP 和 UDP；AnyTLS 支持 v1/v2 多流会话及 UoT。TLS 使用 rustls/aws-lc-rs，支持本地 PEM 校验、指纹上报和事务热重载。
- 同端口候选共享 accept loop，失败更新保留活跃服务；相同加密设置的重载保留恢复票据。

当前入站载体为 TCP/raw，可组合标准 TLS；REALITY、Vision 等组合会拒绝。代理出站支持标准 TLS 和可选 UoT。非零 GlobalID 现可跨承载连接及兼容配置代次迁移，保留 UDP 出口 socket；恢复仍需用户和设备准入。完整能力边界见 [VLESS 文档](docs/vless.md)。

## DNS、限速和路由现状

| 模块 | 已实现 | 尚未实现 |
| --- | --- | --- |
| DNS | 分域 UDP/TCP/DoH/DoT、正负 TTL 缓存、并发合并、地址族策略、系统解析与退出回收 | DNSSEC 本地验证、DoQ、独立公网 DNS 监听 |
| 限速 | 按协议和订阅共享的 TCP/UDP、上下行额度；等待取消与未使用额度退还 | 跨节点全局带宽限制 |
| 路由 | 域名/IP/CIDR/GeoSite/GeoIP、顺序分流、block、直连/DNS/SOCKS5/HTTP/VLESS 出站 | 本轮范围外的代理协议与传输；显式拒绝配置 |

## Resource 和 Buffer 使用约定

创建 `resource::Budget`，通过 `scope` / `child` 派生连接或子流配额，再将作用域交给 `buffer::BufferScope`。具体用法见两个模块的 Rustdoc 示例，可用 `cargo doc --no-deps` 查看。

- `Limits` 同时限制字节和分配名额；零长度 buffer 也占一个名额。子作用域上限不得大于父级，最大嵌套深度为 32。
- `try_reserve_many` 在同一作用域一次性预留所有请求，进程和每一级祖先都参与检查；它返回独立的 Reservation，消费 `commit()` 后成为 Permit。未提交或已提交许可都通过 Drop 自动归还。
- `try_lease_many` 在分配任何 payload 存储前取得整批预算，后续分配失败时回收已分配块和剩余预留，调用方不会得到半个批次。
- `BufferLayout` 定义 headroom + payload capacity + tailroom 的逻辑大小。普通 BufferScope 按精确大小分配，池化 Scope 可能选择更大类别；预算按完整 backing capacity 计量，多余容量不扩大可写范围。
- payload 不能占用 trailer 预留；添加 trailer 后 payload 封口。consume/truncate 后要先 clear 才能重新封包。clear 清空逻辑范围，不释放容量，也不承诺安全擦除。
- `read_from` 只提交成功读取的 filled 字节；空间耗尽是错误，不会冒充 EOF。取消持有 buffer 的任务后，等待其结束才能确认资源已经归还。
- close 阻止新的预留和子作用域，不撤销现有拥有者；关闭前取得的 Reservation 仍可提交。任务取消与等待回收通过 TaskGroup 管理。

当前预算约束的是受管理存储容量及分配名额，不能当作进程 RSS 上限。元数据、分配器开销和外部网络库内存不在字节口径内。批量预留只覆盖同一个作用域，跨分支组合预留尚未提供。

## B2 共享缓存与队列

- `BufferLease::freeze` 消费独占租约，`SharedBuffer::slice` 返回受检只读视图，`into_bytes` 转交拥有者；均不复制 payload。小视图仍保留整块容量和原作用域配额，最后一个拥有者消失才归还。
- `SharedBuffer::copy_to` 显式取得目标作用域预算并复制，可把大块上的短视图转为独立小块；新旧内存重叠期间都计量。没有原地解冻或隐式扩容。
- `BufferPool::new` 绑定进程 Budget，通过 `pool.scope` 选择池化分配。PoolConfig 控制尺寸类别、总闲置字节、总闲置块数和每类上限；standard 使用 4/16/32/64 KiB。超大块和无法满足本地单块/作用域上限的类别使用专用精确分配。
- 闲置缓存继续占进程预算，复用只取得新的作用域配额。缓存与新块可在同批原子预留；容量不足时淘汰本池未被当前批次选中的闲置块。失败批次不留下借用或预留，缓存内容可能因淘汰或回滚改变。
- 缓存块在锁外完整清零后再交给借用者。`trim` 释放闲置块并保留缓存能力；`close` 或最后一个 Pool 句柄释放后，不再接收新借用，活跃视图仍有效直至最终释放。Scope 和视图不强引用 Pool。
- `bounded_queue<T>` 返回 BufferSender 和唯一 BufferQueue 接收端。T 实现 QueueItem，队列长度按逻辑 payload 计；自定义项的长度在排队期间必须不变。BufferLease、SharedBuffer 和 Bytes 已适配。
- `try_send` 失败返回原对象；`reserve(bytes, deadline).await` 在字节和消息两个维度一次授予许可，`QueuePermit::send` 校验实际长度。等待者数量受限，采用 FIFO 授予，大请求可能挡住后面的小请求。
- 丢弃 reserve future 会撤销等待或归还已授予但未消费的许可；丢弃 send future 还会释放其携带的 item。close 拒绝后续发送并允许排空已入队项，接收端 Drop 则丢弃队列内容。close 后，先前授予的未提交 QueuePermit 也不能发送。

BufferScope 的物理容量申请仍是同步 try 操作；B2 的异步等待只针对队列容量，并要求 deadline。PoolSnapshot 提供闲置/准备中/借出容量与命中、未命中、淘汰计数；QueueSnapshot 区分排队、已预留和等待者。资源 Budget 是硬额度的依据，各层指标快照不构成跨锁事务。

Bytes 自己创建的空切片可能不保留原 owner，转为 BytesMut 或其他容器也可能产生预算外复制；不要把外部 Bytes 的全部行为当作 SharedBuffer 的预算契约。SharedBuffer 的 Debug 隐藏数据，Bytes 仍有原生 Debug 行为。Rustdoc 包含池和队列的可执行示例。

## B3 任务 时间 I/O 与 Codec

| API | 当前行为 |
| --- | --- |
| `TaskGroup` | 保留所有句柄，上限包含已完成但未 join 的任务；join/try_join 回收结果与名额 |
| `TaskGroup::shutdown` | 停止接入并取消子任务，截止时间后 abort，再等待全部 join；Drop 只作取消/abort 兜底 |
| `OperationContext` / `Deadline` | 单调时间、可选绝对截止时间、子取消域；子期限只能收紧，已停止时不 poll 工作 future |
| `UnixMillis` | 系统时间的 Unix 毫秒转换，检查纪元前时间及溢出，与单调时间分开 |
| `Address` / `FlowMetadata` | 保留 IP/域名目标、端口、源和网络类型；域名接受 ASCII/IDNA ASCII，不自动 DNS 查询 |
| `DataPlane` | 原子预留双向 buffer，处理短写、WriteZero、EOF、flush、半关闭、取消与共享空闲超时 |
| `DatagramEndpoint` | 收/发 poll 各自串行化，使用 payload limit + 1 接收窗口；超限包不发布，空包有效，部分发送不重发 |
| `Reader` / `Writer` | 有界整数读写与 RFC 1928 目的地址前缀；复合读取失败回退 cursor，写入失败不产生半个前缀 |
| `FrameDecoder` | u16/u32 大端长度帧，逐块输入，一次至多输出一个 SharedBuffer；失败释放部分帧并 poison 状态 |
| `Metrics` | 固定计数和活动 gauge、无动态标签的 Prometheus 文本；资源/池/队列仍使用各自快照 |

任务只支持可协作的异步 future。Tokio abort 无法抢占阻塞或不让出执行权的代码，shutdown 等待 join 确认回收，不承诺能在指定时间内终止这类代码。隐式 Drop 不确认异步回收；任务结果计数在 join 时更新。TaskReport 不保存 panic payload，宿主 panic hook 仍由宿主配置。

TCP 空闲时间由两个方向的读写进展共享，一侧安静不影响另一侧持续传输；绝对截止时间独立生效。失败返回已成功写入的前缀计数，TransferObserver 在每次成功写后、下一次 await 前收到通知。计数表示 AsyncWrite 接受的字节，不等于远端确认；观测计数饱和累加，不能代替持久化计费账本。借用/共享传输包装器的最终关闭由其拥有者负责。

UDP 的 local_addr 是绑定地址，通配绑定时不表示具体目的 IP。65535 是适配器配置上界，宿主发送限制可能更小；真实回环测试使用 8 KiB，完整边界用传输夹具验证。指标只将通过大小检查的接收包及完整发送计为成功；没有协议解析或 NAT 会话管理。

FrameDecoder 的 consumed 指明本次消费量，剩余输入由调用方保留。解码失败要求关闭流，或只在已知帧边界 reset，不能盲目重试。这些长度帧与地址组件不表示已实现 SOCKS 或其他代理协议。Rustdoc 提供可执行用法示例。

## B4 控制面与运行时

`Supervisor` 接收面板连接、真实协议 factory、进程 `BufferScope`、容量选项、指标、指纹 sink 与可选状态 sampler。`sync_config` 发布成功后启动代次维护；`run` 继续驱动配置、退役与报告，取消后执行关闭。单次同步的宿主需显式 `reap_retired` 和 `close`。

候选认证和监听器全部提交成功前，准入始终关闭。共享用户快照、报告和配置验证器在同一发布事务中切换；失败保留活跃代次，旧响应通过 revision/代次检查拒绝。旧会话继续看到当前限制和撤销。默认用户快照 15 分钟未确认后暂停，401/403 立即暂停。

协议驱动必须为每个连接或子流取得 `Core::admit` 许可，并将其 context 用于后续 I/O；连接任务交给 Core；共享 ingress 保留独立的有界任务组，并在最后一个路由释放时关闭和等待。关闭依次停止接入、限时排空、取消和 join，退役重试不延长原截止时间。B5 已通过 VLESS 驱动接入这些约定，并以真实回环 socket 和 Xray 客户端验证。完整上限、接入契约与边界见 [B4 文档](docs/control-plane.md) 和 [VLESS 文档](docs/vless.md)。

## 构建与本地检查

工具链固定在 `rust-toolchain.toml`，依赖固定在 `Cargo.lock`。需要 Rust 1.97.1 及平台 C 构建工具供 TLS 密码依赖使用；protoc 随构建依赖提供，无需单独安装，也不依赖旁边的 backend 仓库。

```sh
cargo build --locked --release
cargo run --locked -- capabilities
cargo run --locked -- check --config examples/terraris.toml
```

本地 `check` 校验 TOML、URL、ID、超时和大小限制，不读取密钥来源，也不访问面板。

## 运行代理节点

配置面板凭据和 `[node]` 资源限制，在 PPanel 下发协议参数后执行；TLS 证书配置见 [TLS 文档](docs/tls-protocols.md)：

```sh
./target/release/terraris run --config terraris.toml
```

`run` 会绑定面板端口、同步用户、执行设备准入并上报在线/流量；SIGINT/SIGTERM 执行排空、任务回收和最终冲刷。默认外部 VLESS 监听要求启用 TLS 或 VLESS Encryption；loopback 可用于受信任的外部承载。详细配置与可复现互通命令见 [B5 文档](docs/vless.md)。

## 面板联通检查

将 [示例配置](examples/terraris.toml) 复制为 `terraris.toml`，填写面板 URL 和服务器 ID。密钥只选择一种来源：`secret_env` 指定的环境变量，或 `secret_file` 指定的文件。相对文件路径以配置文件目录为基准，密钥文件建议限制为当前服务用户可读。

设置示例中的 `TERRARIS_PANEL_SECRET` 环境变量后运行：

```sh
./target/release/terraris check --config terraris.toml --panel
```

该命令依次读取配置及每个启用协议的用户和在线 IP 数，仅输出记录数量，不申请设备名额、不发送状态或流量。用户数量按协议累计，包含面板返回的占位记录，不等于去重订阅数。协议及复杂传输字段会被保留，但当前检查不验证代理运行时能否启动。

`wire_format = "auto"` 首先请求 Protobuf，接受面板返回的 JSON；配置和用户 GET 在收到明确的 406/415 时可以回退 JSON。POST 不自动重发或更换编码。固定为 `json` / `protobuf` 时要求响应格式一致。

## Library 使用约定

入口为 `panel::ppanel::PPanelProvider` / `PPanelConnection`。通过 Connection 获取服务器配置端口，以及绑定规范协议名的用户/报告端口和状态端口。共享 HTTP 连接池和证书指纹注册表，不把面板 DTO 传入后续协议引擎。

- 拉取返回 `Fetch::Changed { value, validator }` 或 `Fetch::Unchanged { validator }`。只在应用数据成功后保存候选 validator；客户端不会代替 Controller 提交。
- Validator 不能跨连接或资源使用；重建 Connection 后从无验证器拉取。空用户数组是有效撤销快照。
- `report_online` 单批最多 10000 项；空在线、空流量批次跳过发送。调用方负责分批及确认管理。
- `report_traffic` 接收原始增量字节，不应用倍率；同订阅单次请求合计不超过 10 TiB。失败是否重试由后续 Reporter 决定，现有面板没有幂等键。
- `NodeStatus.updated_at_millis` 是 Unix 毫秒；CPU、内存、磁盘是 0–100 的百分比。
- `CertificateFingerprints::publish` 仅在证书生效后调用。已创建的 StatusClient 在发送时读取最新指纹，不同协议彼此隔离。
- 未识别的 JSON 配置字段保存在领域模型的 `extensions` 中，后续运行时需显式判断；Protobuf 仍受固定 schema 能力限制。

## 开发验证

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
cargo build --locked --release
```

测试使用本地 HTTP 模拟面板，覆盖全部端点、两种编码、条件请求、大小限制、取消、错误脱敏及报告不重试。另有[使用 backend Go 绑定生成的互操作样本](tests/fixtures/README.md)，正常 Rust 测试无需 Go。

资源和 buffer 测试覆盖作用域聚合、混合批次与缓存淘汰、共享/Bytes 生命周期、关闭和取消竞态、零长度名额、溢出、封包边界，以及分配失败和 unwind 回滚。队列使用可控时间验证 FIFO、超时和授予/取消交错；Rustdoc 验证 BufferLease、QueuePermit 无法 Clone，SharedBuffer 不可写。

B3 测试包含可控时钟下的任务关停/超时、短写和失败前缀计数、真实 IPv4 回环 TCP 半关闭与 UDP 包边界、超限夹具、分段 codec 输入及指标并发。B4 增加多协议提交回滚、旧响应/用户更新竞争、跨代次会话、调度、报告 ACK 和关闭测试。B5 增加协议边界、设备 TTL、共享限速、实际 TCP/UDP/XUDP、同端口重载、GlobalID 迁移/隔离/过期和 CLI 退出测试；另有固定版本 Xray 外部测试。性能和生产部署仍需后续验证。

[CI 配置](.github/workflows/ci.yml) 在 Linux 和 macOS 上执行格式、Clippy、测试及 release 构建。当前本地验证不等于生产面板、Redis/PostgreSQL 或 Linux 部署联调。

上游 Protobuf schema 的来源和许可证见 [proto/ppanel](proto/ppanel/README.md)。

## 许可证

Terraris 使用 GNU General Public License v3.0（SPDX：`GPL-3.0-only`），完整条款见 [LICENSE](LICENSE)。第三方文件保留各自的来源与许可证声明，详见 [THIRD_PARTY.md](THIRD_PARTY.md)。
