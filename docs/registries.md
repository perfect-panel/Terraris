# 协议与传输注册表

Node 使用 `Supervisor<protocol::Registry>`。新增协议或流传输时，实现相应工厂并在启动阶段注册；Node、Supervisor 和路由引擎不需要增加协议名称分支。注册表构建后不可变，配置热重载只创建新的运行时实例。

| 注册表 | 扩展接口 | 当前内置实现 |
| --- | --- | --- |
| `protocol::Registry` | `protocol::InboundFactory` → `ProtocolDriver` | VLESS、Trojan、AnyTLS |
| `outbound::Registry` | `outbound::registry::Factory` → `Connector` | direct/freedom、block/blackhole/reject、dns、socks5/socks、http、vless |
| `transport::Registry` | `transport::Factory` → `Inbound` / `Outbound` | tcp/raw；TCP 客户端和服务端可组合标准 TLS |

TLS 是 TCP 工厂根据 `security` 配置准备的包装层。客户端保留证书链、服务器名和 ALPN 校验，以及显式的 `allow_insecure` 设置；服务端通过 `certificate::Settings` 加载本地 PEM，明确使用 rustls/aws-lc-rs。WS、gRPC、REALITY 和 QUIC 尚未实现。UDP 载荷仍通过现有 `PacketPort` / `DatagramTransport` 接口传递；本次传输注册表提供字节流载体。

## 启动装配

默认 `Node::new` / `Node::with_network` 使用内置工厂；需要 PEM 时使用 `Node::with_tls`，CLI 从 `[tls]` 装配。自定义装配可使用 `Node::with_registry`，其闭包获得节点使用的面板连接和指标，再返回协议注册表。也可将注册表直接交给 `Supervisor::new`。

下面的装配函数以 VLESS 与 TCP 为基础，同时接入调用者提供的三个新工厂。名称仅为扩展示例，需要实际传入对应实现。

```rust,no_run
use std::sync::Arc;
use terraris::{dns, egress, outbound, panel::Connection, protocol, route, telemetry::Metrics, transport};

fn assemble(
    connection: Arc<dyn Connection>,
    custom_protocol: Arc<dyn protocol::InboundFactory>,
    custom_outbound: Arc<dyn outbound::registry::Factory>,
    custom_transport: Arc<dyn transport::Factory>,
) -> Result<protocol::Registry, Box<dyn std::error::Error>> {
    let metrics = Metrics::default();
    let mut transports = transport::Registry::builtin_builder();
    transports.register("custom-stream", &["stream-alias"], custom_transport)?;
    let transports = Arc::new(transports.build());
    let mut outbounds = outbound::Registry::builtin_builder();
    outbounds.register("custom-proxy", &[], custom_outbound)?;
    let egress = egress::Registry::with_providers(
        dns::Settings::default(), route::Settings::default(), 4096,
        Arc::new(outbounds.build()), transports.clone(),
    )?;
    let vless = Arc::new(protocol::vless::Factory::with_services(
        connection, protocol::vless::Options::default(), protocol::flow::Options::default(),
        egress.clone(), transports, metrics.clone(),
    )?);
    let mut protocols = protocol::Registry::builder(egress, metrics);
    protocols.register(protocol::vless::NAME, &[], vless)?;
    protocols.register("custom-protocol", &["protocol-alias"], custom_protocol)?;
    Ok(protocols.build()?)
}
```

名称会去除首尾空白并转为小写，只接受 1–64 字节的字母、数字、连字符与下划线；协议名另遵循面板模型的 Hysteria 规范化。每个注册表最多 64 个工厂、256 个名称（含别名）。重复名称、别名冲突或非法名称会使整次注册失败，不留下部分别名，也不覆盖旧工厂。`names()` 返回注册顺序中的主名称。

入站保留配置里的面板协议名，即使它是注册别名，用户、报告和认证作用域也仍对应原端点。出站工厂收到规范化后的主名称；路由规则通过注册工厂的 `Kind` 编译，TCP/UDP 能力由 `Connector::supports` 判定。未注册的出站、传输和不支持的选项会拒绝候选配置，不回退直连。沿用 Supervisor 的入站选择规则：混合配置中的未注册入站不启动；若配置启用了入站却没有任何已注册实现可运行，整个配置失败。全部禁用仍可正常发布并撤销旧会话。

## 生命周期与热重载

`InboundFactory::prepare` 创建私有驱动，不能修改活跃认证或监听路由。所有协议候选准备完成后，Supervisor 仍通过同一个发布事务切换认证、监听准入、报告和代次。配置准备失败或取消时，旧代次保持可用。

协议注册表持有统一的 egress 服务，`prepare_shared` 只向它传入已支持的协议。非 VLESS 工厂同样使用路由、DNS、出站策略及策略变更时的撤销逻辑。协议的 `published` 钩子在发布之后执行；关闭时先同步取消全部工厂和共享服务，再逐一等待关闭。某个工厂返回错误不会跳过其余工厂的关闭。钩子必须支持重复调用，准备 future 被取消时必须释放私有资源。

`transport::Inbound::bind` 仅建立物理监听，`Listener::accept` 尽快交付原始流。TLS 握手和未来 WS 等实现放在 `Inbound::handshake`，由各协议的连接任务、握手并发许可和截止时间约束。工厂准备方法不得执行网络 I/O 或启动后台任务；I/O 方法必须遵守 `OperationContext`，载荷分配使用传入的 `BufferScope`。工厂必须验证自己负责的配置字段，不能静默忽略安全选项。

VLESS 与共用 stream 运行时均通过 `protocol::ingress` 对兼容代次的同地址使用一个 accept loop。`Inbound::binding_key` 相同表示物理监听可互换，允许重用；每个新驱动仍持有自己的握手配置。键必须包括所有绑定期差异。不兼容的键在旧监听存活时导致候选失败，旧服务继续工作；更换端口或先停用旧监听后可切换。已建立连接不重新执行新代次的握手。

`protocol::Registry`、`outbound::Registry`、`transport::Registry` 是扩展目录；`egress::Registry`、公共 ingress / VLESS XUDP registry 是服务复用和会话索引，两类用途不同。独立使用 `vless::Factory` 的既有 RuntimeFactory 入口仍保留。

## 验证范围

专项测试覆盖名称与别名的原子注册、容量上限、两个自定义协议与别名分派、后续协议提交失败的整体回滚、准备取消、非 VLESS 的共享策略校验、关闭失败后的清理，以及自定义出站的路由和 TCP/UDP 能力判定。

真实回环测试通过自定义传输在 VLESS 头之前读写额外字节，验证工厂参与了实际监听和握手、兼容重载重用监听、不兼容绑定回滚、关闭取消未完成握手；另验证 HTTP CONNECT 使用自定义出站传输。既有 VLESS 集成测试已改为经过协议注册表运行，继续覆盖 TCP/UDP/XUDP、GlobalID、用户撤销、路由策略切换和退出。

TLS 身份通过 `Inbound::reload_required` → `ProtocolDriver::reload_required` → Supervisor 的配置同步检测变化，304 仍可触发新代次准备。指纹在完整发布后更新。Trojan / AnyTLS 共用 `protocol::stream` 的准入、认证快照和有界连接任务；各自 Engine 只处理协议认证和帧语义。详见 [TLS 协议文档](tls-protocols.md)。
