# Terraris 对接 PPanel 的接口契约

核对日期：2026-11-01。基线：相邻 backend 仓库 `764e937c`。本文件记录现有节点 API 及 Terraris 的消费规则。对应 Rust 客户端位于 `src/panel/ppanel`；代理运行时和后台维护调度尚未实现。

架构沿用 Polaris 的面板适配边界：以下 endpoint、DTO、鉴权和 envelope 规则只由 `panel::ppanel` 解释，再显式转换为面板中立模型。`ServerClient` 向 Supervisor 提供配置，绑定协议的 `ProtocolClient` 向 Controller 提供用户、设备和报告接口，`StatusClient` 供服务器级状态任务使用。共享 HTTP 层只处理传输机制，协议引擎不接触面板 DTO。

## 1 鉴权和传输

`/v2/server/{server_id}` 使用路径中的服务器 ID 和 query 中的 `secret_key`。`/v1/server/*` 使用 query 中的 `server_id`、`protocol`、`secret_key`；body 不能替代这些身份字段。

GET 请求用 `Accept: application/protobuf` 协商 Protobuf，否则默认 JSON。POST 的 `Content-Type` 决定请求体编码，`Accept` 决定响应编码；两者是独立机制。这里使用普通 HTTP body，不是 gRPC。

Terraris 先协商配置格式，按响应 `Content-Type` 解码并记录模式。JSON 回退只针对确实返回的 JSON 或明确的不支持协商响应；认证失败、解码错误和业务失败不能伪装成格式降级成功。配置/用户 GET 可以重新协商，已经发出的流量 POST 不能因为解码失败就自动换格式再次发送。

当前面板的 JSON 成功响应不统一：有的端点返回裸数据，有的使用 `{code,msg,data}`。所有 Protobuf 成功响应均有 `code=200`，错误可能以 HTTP 200 加非 200 业务码返回。每个端点必须明确解码其结构，不能只看 HTTP 状态。

## 2 端点矩阵

| 方法和路径 | 成功 JSON | 成功 Protobuf | 条件请求 |
| --- | --- | --- | --- |
| `GET /v2/server/{server_id}` | `{code,msg,data:{protocols,…}}` | `QueryServerProtocolConfigResponse` | ETag / 304 |
| `GET /v1/server/user` | `{users:[{id,uuid,speed_limit,device_limit}]}` | `GetServerUserListResponse` | ETag / 304 |
| `GET /v1/server/alivelist` | `{alive:{订阅ID:数量}}` | `GetServerAliveListResponse` | 无 ETag，不缓存 |
| `POST /v1/server/device` | `{allowed,ttl_seconds}` | `ClaimServerDeviceResponse` | 不缓存 |
| `POST /v1/server/online` | `{code,msg}` | `Result` | 不适用 |
| `POST /v1/server/push` | `{code,msg}` | `Result` | 不适用 |
| `POST /v1/server/status` | `{code,msg}` | `Result` | 不适用 |

旧接口 `GET /v1/server/config` 存在，但无法表达全部新协议，Terraris 首版使用 v2 完整配置，不维护旧配置转换层。

上述成功形状来自[配置 handler](../../backend/internal/module/network/transport/http/server/query_server_protocol_config_handler.go)、[用户 handler](../../backend/internal/module/network/transport/http/server/get_server_user_list_handler.go)、[设备 handlers](../../backend/internal/module/network/transport/http/server/devices_handler.go)及[通用响应处理](../../backend/internal/module/network/transport/http/server/helpers.go)。

## 3 配置语义

v2 返回启用的协议列表，以及实际生效的 `dns`、`block`、`outbound`、`ip_strategy`、`pull_interval`、`push_interval`、`traffic_report_threshold`。服务器覆盖配置已由 backend 合并；节点不用重新猜测全局与服务器覆盖规则。

当前 backend 的空协议切片可能序列化为 JSON `protocols: null`，也可能为 `[]`；成功信封中这两种形状都应按无启用协议处理，不能因期待数组而保留已撤销的入站。缺少整个 data 或 protocols 字段仍是无效 JSON 配置。Protobuf 的空 repeated 字段天然表示空列表。

拉取与上报间隔按秒解释。现有 ppanel-node 对非正间隔回退为 60 秒；Terraris 可沿用该默认值，同时施加本地请求频率下限，避免错误配置触发忙循环。

该接口也支持 `protocols` 或 `protocols[]` 查询过滤。Terraris 初期拉取完整列表，以便报告不支持的能力，并正确区分协议移除和过滤结果。

`protocols` 是扁平对象数组，`type` 决定其余字段的意义。JSON 的 Shadowsocks 插件配置名为 `plugin_opts`，Protobuf 对应字段为 `plugin_options`，允许对象和字符串两种形状，不能直接使用同一个序列化模型。

面板规范协议名将 `hysteria2` 归一为 `hysteria`。运行时可以使用 Hysteria2 枚举，但用户请求及报告需要沿用面板规范名称，不能仅改变展示名就改变 query。

全局 DNS、路由或出站中的不支持功能必须在候选校验时报告。客户端专用字段可以在适配边界按明确规则忽略；安全层、认证、插件或传输功能不能作为普通未知字段静默丢弃。

JSON 和 Protobuf 的 ETag 按各自表示计算。缓存键至少包含端点、服务器、协议、过滤条件及编码；切换表示时重新拉取。服务端不提供配置与用户列表的跨接口事务版本，节点只能保证本地发布一致，不能声称获得了面板的同一事务快照。

Terraris 保存当前已提交状态的 ETag。收到新内容后，只有运行时应用成功才推进它；若 200 响应不再提供 ETag，则清除旧验证器。304 必须有对应的本地快照，否则重试无条件 GET。

依据：[配置服务](../../backend/internal/module/network/internal/serverapi/query_server_protocol_config.go)、[协议归一化](../../backend/internal/module/network/entity/node/protocol_normalize.go)、[DTO](../../backend/internal/module/network/contract/server.go)及 [Protobuf schema](../../backend/api/server/v1/server.proto)。

## 4 用户和凭据

`id` 是订阅 ID，不是账号 ID；JSON 报告字段 `uid` 和 Protobuf 字段 `user_id` 均引用该值。保持正 `int64`，避免经过浮点数或较窄整数。

`uuid` 是由协议适配层解释的主凭据，不能假定所有协议都把它作为相同的原始字节使用。`speed_limit` 使用十进制 Mbps，0 为不限速；`device_limit` 的 0 为不限设备。

拉取结果必须区分：

| 结果 | Terraris 行为 |
| --- | --- |
| HTTP 304 | 保留用户快照并更新最近确认时间 |
| 成功且 `users: []` | 发布空快照，撤销全部用户 |
| 缺少 users、类型错误、非法记录 | 不发布候选，保留旧快照并报告错误 |
| 网络、认证、业务错误 | 按故障策略处理，不能当作空列表 |

上表中的“缺少 users”针对 JSON 必需字段；Protobuf 在有效 data 中省略空 repeated users 是正常编码，应视为成功空列表，不能把它当作缺少 data。

当前 backend 在实际没有服务订阅时可能返回 `id=1`、随机 UUID 的占位用户；这个 ID 本身也可能是真实订阅，因此节点不能按 `id=1` 删除记录，也不能把一个用户等同于空列表。沿用返回的认证数据，面板负责在上报时排除占位记录。后续若要可靠识别空集合，需要 backend 明确表达。

现有 ppanel-node 对 Shadowsocks 的转换为：传统 AEAD 用 UUID 文本作为密码；SS2022 AES-128 使用 UUID 文本前 16 字节，AES-256 使用前 32 字节，再编码为 Base64；服务器密钥也从面板原始文本字节转为 Base64。Rust 适配需检查字节长度，不能直接把 UUID 解析成 16 字节二进制后当成等价密钥，也不能对已经转换的数据重复编码。

上述凭据规则来自现有节点，仍需使用面板实际生成的订阅与目标客户端做互通验收；它不代表所有 SS2022 算法都能用 EIH 多用户运行。

依据：[用户列表服务](../../backend/internal/module/network/internal/serverapi/get_server_user_list.go)、[ppanel-node 凭据转换](../../ppanel-node/core/user.go)、[SS 入站构造](../../ppanel-node/core/inbound/shadowsocks.go)及[速度换算](../../ppanel-node/limiter/devices.go)。

## 5 在线设备

| 操作 | JSON 请求体 | Protobuf 请求体 |
| --- | --- | --- |
| 申请或续期名额 | `{uid,ip}` | `ClaimServerDeviceRequest {user_id,ip}` |
| 上报在线 IP | `{users:[{uid,ip}]}` | `PushOnlineUsersRequest {users:[{user_id,ip}]}` |

设备按订阅 ID + 来源 IP 全局去重，包括跨节点、跨协议；IPv4-mapped IPv6 转为 IPv4。NAT 后共享公网 IP 的设备合计一个名额。当前租约为 300 秒，节点应消费响应的 `ttl_seconds`，而非把常量写进所有逻辑。

`/device` 使用 Redis 原子检查，有限额的新 IP 必须获准后才能转发；已存在的 IP 可以续期。`/alivelist` 只返回当前可服务订阅的全局有效 IP 数，读取人数后本地判断不能代替原子申请。

`/online` 按批次中的 IP 合并并续期，不用新批次覆盖旧批次；每次最多 10000 条。空 users 请求会被拒绝，无在线设备时跳过空上报。短连接需要保留待上报记录，活跃无流量连接也需要心跳。

接口失败不能解释为人数为零；也不能用未经准入的新 IP 在线上报来绕过 `/device`。没有显式释放接口，节点只能停止本地续期。

依据：[设备服务](../../backend/internal/module/network/internal/serverapi/devices.go)、[在线上报](../../backend/internal/module/network/internal/serverapi/push_online_users.go)和[后端接口说明](../../backend/api/server/v1/README.md)。

## 6 流量

JSON 请求为 `{traffic:[{uid,upload,download}]}`；Protobuf 使用 `PushUserTrafficRequest` 与 `UserTraffic.user_id`。数值是增量字节，不能发送从启动开始的累计值。

upload 表示客户端到目标的负载，download 为反向负载。Terraris 在共享明文转发层计数，防止 TLS/QUIC 开销或重传重复计量。节点只报原始值，backend 再应用协议 ratio 和时间倍率。

`traffic_report_threshold` 是节点攒批的字节阈值，不是费率，也不是可丢弃的小流量。现有节点在用户上下行合计大于阈值时收集；Terraris 保留未达阈值的数据，并在退出或撤销时收集余量。

backend 对每次请求中每个订阅的 upload + download 总和限制为 10 TiB，重复出现的该订阅也合并检查。负数、非法 ID、超限和不在当前服务范围内的条目可能被丢弃，成功响应没有逐项回执。

现有协议没有 `batch_id`、去重键或采集时间字段。HTTP 200 且业务 code=200 只表明请求处理成功；不保证逐项落账，也不保证响应丢失后重试不会重复。存储和重试设计见[架构设计](architecture.md)中的流量章节。

依据：[流量 handler](../../backend/internal/module/network/transport/http/server/server_push_user_traffic_handler.go)、[流量聚合](../../backend/internal/module/network/internal/trafficagg/aggregator.go)、[节点计数器](../../ppanel-node/core/user.go)和[现有重试队列](../../ppanel-node/node/traffic.go)。

## 7 状态与证书

状态请求字段为 `cpu`、`mem`、`disk`、`updated_at`。前 3 项沿用现有节点的百分比语义，`updated_at` 使用 Unix 毫秒，不是秒。

自签证书的 `X-Node-Certificate-SHA256` 为证书 DER 的 SHA-256 小写十六进制指纹，不是 PEM 文本或公钥哈希。状态请求绑定具体 protocol，backend 据此更新该协议的证书元数据。多协议分别上报正确的指纹，不在整个客户端上安装一个混用指纹。

证书轮换导致指纹变化时，面板元数据更新和客户端订阅刷新并非原子过程；不能承诺旧订阅在轮换后无需更新。自签证书应持久化以避免每次启动触发这一过程。

依据：[状态服务](../../backend/internal/module/network/internal/serverapi/server_push_status.go)、[节点状态请求](../../ppanel-node/api/panel/node.go)和[状态采样](../../ppanel-node/common/serverstatus/serverstatus.go)。

## 8 契约维护

已在 [proto/ppanel](../proto/ppanel/README.md) 引入 backend `server.proto` 的固定版本副本，记录源 commit、SHA-256 和许可证。`build.rs` 使用锁定的 prost-build 和随依赖提供的 protoc 生成私有绑定；构建不读取相邻 backend 仓库。

端点级 JSON/Protobuf 测试覆盖成功、业务失败、304、空数组、缺少数据、超限及不同 Content-Type。模拟面板检查 URL 编码、API 前缀、鉴权 query、缓存隔离和请求体差异；另用 backend 的 Go 绑定生成固定二进制样本验证双向 wire 兼容。真实 backend、Redis 和 PostgreSQL 联调仍待运行时阶段进行。

Protobuf 接受未知字段不代表旧客户端理解新协议语义。升级 schema 时需同步审阅能力矩阵和规范化逻辑；新增安全或传输能力必须有显式支持决策及互通测试。
