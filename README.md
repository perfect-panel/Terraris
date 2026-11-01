# Terraris

Terraris 是参考 Polaris 架构设计的 PPanel Rust 节点端项目，负责代理协议接入、用户认证、限速与设备准入，以及节点状态、在线设备和流量上报。

当前已完成 Rust 基础工程、PPanel 面板客户端，以及 B1 的 resource/buffer 底层模块。代理协议、Supervisor/Controller 运行循环、限速执行及持久化上报尚未实现；当前二进制用于配置与只读联通检查，不监听代理端口或自动上报在线状态。

- [架构设计](docs/architecture.md)：模块边界、状态管理、协议规划、故障处理与实施阶段。
- [PPanel 接口契约](docs/ppanel-api.md)：当前 backend 的实际接口、身份与计量语义、兼容性要求。
- [基础设施顺序](docs/infrastructure.md)：先完成资源、任务、buffer 和基础 I/O，再接控制面运行时。
- [Buffer 系统设计](docs/buffer.md)：所有权、前后预留空间、共享切片、内存预算、池化和背压。

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
- buffer 提供受检 BufferLayout、独占 BufferLease、固定容量封包、清零 padding、受限读取及批量分配失败回滚。当前没有缓存池、共享切片或异步额度等待。

设备租约、用户限制和流量接口目前由 library 暴露；这不代表已经有数据面执行这些策略。

## Resource 和 Buffer 使用约定

创建 `resource::Budget`，通过 `scope` / `child` 派生连接或子流配额，再将作用域交给 `buffer::BufferScope`。具体用法见两个模块的 Rustdoc 示例，可用 `cargo doc --no-deps` 查看。

- `Limits` 同时限制字节和分配名额；零长度 buffer 也占一个名额。子作用域上限不得大于父级，最大嵌套深度为 32。
- `try_reserve_many` 在同一作用域一次性预留所有请求，进程和每一级祖先都参与检查；它返回独立的 Reservation，消费 `commit()` 后成为 Permit。未提交或已提交许可都通过 Drop 自动归还。
- `try_lease_many` 在分配任何 payload 存储前取得整批预算，后续分配失败时回收已分配块和剩余预留，调用方不会得到半个批次。
- `BufferLayout` 为 headroom + payload capacity + tailroom 的精确大小，B1 不向上取整到缓存类别。预算按完整分配计量，不随 readable length 缩小。
- payload 不能占用 trailer 预留；添加 trailer 后 payload 封口。consume/truncate 后要先 clear 才能重新封包。clear 清空逻辑范围，不释放容量，也不承诺安全擦除。
- `read_from` 只提交成功读取的 filled 字节；空间耗尽是错误，不会冒充 EOF。取消持有 buffer 的任务后，等待其结束才能确认资源已经归还。
- close 阻止新的预留和子作用域，不撤销现有拥有者；关闭前取得的 Reservation 仍可提交。取消任务与强制结束由后续 TaskGroup 层负责。

当前预算约束的是受管理存储容量及分配名额，不能当作进程 RSS 上限。元数据、分配器开销和外部网络库内存不在字节口径内。批量预留只覆盖同一个作用域，跨分支组合预留尚未提供。

## 构建与本地检查

工具链固定在 `rust-toolchain.toml`，依赖固定在 `Cargo.lock`。需要 Rust 1.97.1 及平台 C 构建工具供 TLS 密码依赖使用；protoc 随构建依赖提供，无需单独安装，也不依赖旁边的 backend 仓库。

```sh
cargo build --locked --release
cargo run --locked -- capabilities
cargo run --locked -- check --config examples/terraris.toml
```

本地 `check` 校验 TOML、URL、ID、超时和大小限制，不读取密钥来源，也不访问面板。

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

资源和 buffer 测试覆盖作用域聚合、并发批次争用、close/申请竞态、取消回收、零长度名额、溢出、封包边界，以及后续分配失败和 unwind 时的整批回滚。Rustdoc 还验证 BufferLease 无法 Clone。

[CI 配置](.github/workflows/ci.yml) 在 Linux 和 macOS 上执行格式、Clippy、测试及 release 构建。当前本地验证不等于生产面板、Redis/PostgreSQL 或 Linux 部署联调。

上游 Protobuf schema 的来源和许可证见 [proto/ppanel](proto/ppanel/README.md)。

## 许可证

Terraris 使用 GNU General Public License v3.0（SPDX：`GPL-3.0-only`），完整条款见 [LICENSE](LICENSE)。第三方文件保留各自的来源与许可证声明。
