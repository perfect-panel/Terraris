# WebSocket、gRPC 与 HTTP Upgrade

XHTTP / SplitHTTP 的 HTTP/1.1/2/3 配置另见 [XHTTP 文档](xhttp.md)。

三种传输均已注册到 `transport::Registry`，可用于入站和代理出站，并复用 rustls/aws-lc-rs TLS、本地 PEM、证书热重载和连接预算。协议层继续负责认证、路由、设备准入、限速和 payload 计量。

| 传输 | 配置名称 | 载荷形式 | TLS ALPN |
| --- | --- | --- | --- |
| WebSocket | `ws` / `websocket` | HTTP/1.1 Upgrade 后的 RFC 6455 二进制帧 | `http/1.1` |
| HTTP Upgrade | `httpupgrade` / `http-upgrade` | HTTP/1.1 Upgrade 后直接传输字节 | `http/1.1` |
| gRPC | `grpc` | HTTP/2 双向流中的 gRPC Hunk / MultiHunk | `h2` |

WebSocket 和 HTTP Upgrade 的后续编码不同，客户端与服务端必须选择相同传输。未启用 TLS 时，gRPC 使用 HTTP/2 prior knowledge（h2c），不执行 HTTP/1.1 的 h2c Upgrade。明文传输不满足 Trojan / AnyTLS 的 TLS 要求；VLESS 的外部明文监听仍需操作者显式允许。

## 面板配置

入站在协议项的 `network` 或 `transport` 选择传输。两项同时非空时必须指向同一注册项，别名也可匹配。以下是 PPanel 配置中一个入站协议项的示例：

```json
{
  "type": "vless",
  "enable": true,
  "port": 443,
  "network": "ws",
  "security": "tls",
  "cert_mode": "file",
  "sni": "node.example.com",
  "host": "node.example.com",
  "path": "/relay"
}
```

证书与私钥仍在本地 `[tls]` 配置，见 [TLS 文档](tls-protocols.md)。`security="tls"` 时自动设置上表的 ALPN；显式 `alpn` 只能包含该传输要求的值，冲突配置会拒绝发布。

- `host`：入站非空时校验 HTTP Host / HTTP/2 authority；域名大小写不敏感，配置未指定端口时接受请求中的端口。为空时不限制具体名称；HTTP/1 仍要求有效 Host，gRPC 允许省略 authority。出站优先使用该字段，其次是 SNI，最后是代理服务器地址和端口。
- `path`：WS / HTTP Upgrade 的路径，默认 `/`；缺少开头的 `/` 时自动补齐。入站比较路径部分，忽略查询参数，与 Xray 的行为一致；出站保留配置中的查询参数。长度最多 2048 字节，禁止控制字符、空白和片段。
- `service_name`：gRPC 的服务名，例如 `terraris`。常规请求路径为 `/terraris/Tun`，多 Hunk 请求为 `/terraris/TunMulti`。接受最多 128 字节的 ASCII 字母、数字、点、下划线和连字符；空名称保留上游的 `//Tun` 形式。gRPC 不接受非空 `path`，也不支持把任意自定义 RPC 路径写进 `service_name`。

将上述例子的 `network` 改为 `httpupgrade` 即可使用 HTTP Upgrade。使用 gRPC 时改为 `network="grpc"`，删除 `path` 并添加 `service_name="terraris"`。

代理出站通过 `transport` 选择同样的名称，字段含义一致。例如：

```json
{
  "name": "remote-vless",
  "protocol": "vless",
  "address": "node.example.com",
  "port": 443,
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "security": "tls",
  "sni": "node.example.com",
  "transport": "grpc",
  "host": "node.example.com",
  "service_name": "terraris",
  "rules": ["domain:example.net"]
}
```

出站仍使用共享 DNS 解析出来的候选地址，不通过 HTTP 库重新解析 Host；Host 和 SNI 不会改变实际拨号目标。TLS 证书验证、附加 CA 与显式 `allow_insecure` 的语义保持不变。HTTP CONNECT、SOCKS5、VLESS 等协议可使用这些字节流；出站协议和远端是否接受某一组合需相符。

## 流行为和生命周期

WebSocket 支持客户端掩码、二进制分片、Ping/Pong、关闭握手，以及 Xray 的 `Sec-WebSocket-Protocol` 早期数据接收。早期数据字段最多 4096 字节，解码后先交给协议层，再读取普通帧。出站可通过路径中的 `?ed=N` 启用早期数据，N 为 1–3072 字节（0 禁用）。该控制参数从请求路径中移除，其余查询参数保留原编码。首次写入时最多 N 字节放入升级头，剩余部分进入普通 WS 帧；先读取或 flush 时使用普通握手。失败不会自动重放首包，握手继续遵守调用方的取消与截止时间，并最多等待 10 秒。未实现文本数据、压缩扩展、浏览器拨号或自定义请求头。

HTTP Upgrade 在 101 响应后直接转发原始流。HTTP 解析保留首包中跟在头部之后的数据；客户端可以把升级请求与协议首包一起发送。两种 HTTP/1 传输均限制头部为 16 KiB、最多 64 个字段，拒绝重复字段、请求体及 Transfer-Encoding，不跟随重定向。

gRPC 入站在同一 HTTP/2 连接上接受多个独立 RPC，每个 RPC 单独完成协议握手、用户准入、限速与计量。支持未压缩的 protobuf `Hunk`（`Tun`）和 `MultiHunk`（`TunMulti`）；未知方法和不支持的内容编码会拒绝。坏帧或用户撤销只结束相应逻辑流，HTTP/2 连接错误才影响整个载体。流控制窗口不足时异步等待，并在消费 DATA 后归还接收额度。

gRPC 出站使用 `Tun`，同一不可变出站实例的请求复用有界 HTTP/2 连接池，最多 4 条物理连接、每条最多 32 个正在打开或活跃的 RPC。只有实际对端仍在当前解析候选中时才复用；不同出站配置不共享池。空闲 60 秒回收，连接使用 30 分钟后停止接收新请求并在存量 RPC 结束后回收。GOAWAY 或连接关闭后重新建连，仅在 HTTP 流尚未创建时重试，不重放 payload。允许在响应头到达前发送请求数据，兼容延迟发送响应头的服务端；读取响应前校验 HTTP 状态、Content-Type 和 gRPC 编码，结束时校验 `grpc-status`。连接驱动由池的有界 TaskGroup 持有，单个 RPC 关闭不影响其他 RPC。出站注册表退出时取消并等待全部连接任务；丢弃整个池也会取消任务。

配置切换仍复用兼容的物理 TCP 监听器。已有 WS / HTTP Upgrade 流继续使用原代次握手参数。gRPC 退役连接停止接收新 RPC，发送 GOAWAY，并允许已有流排空；空连接随后释放。认证及路由策略不兼容时，现有会话按共享控制面的规则撤销。证书更新只改变新 TLS 握手。

未信任客户端提供的 X-Forwarded-For，也不启用 PROXY protocol；设备准入使用实际连接的对端地址。反向代理后的源地址信任配置需要单独实现。

## 资源边界

- 每条 gRPC 入站载体最多 32 个运行中的逻辑流，完成但尚未回收的 future 也占名额；逻辑流共用该物理连接的 BufferScope。每个逻辑流的协议握手仍受节点握手并发许可和截止时间约束。
- HTTP/2 头部上限 16 KiB，初始连接接收窗口 1 MiB、流接收窗口 65535 字节、流发送缓存上限 64 KiB，并限制待处理 reset 的数量。
- WS 消息和 gRPC 消息上限为 `min(1 MiB, BufferScope 单次分配上限)`。gRPC 单消息最多解析 1024 个 protobuf 字段；发送方向将数据拆为最多 16 KiB 的 payload。
- WS 与 gRPC 的应用载荷和等待发送的数据使用受预算管理的 buffer。TLS、HTTP/2、WebSocket 库内部缓存分别受其自身限制，不属于 payload buffer 的字节统计；`memory_bytes` 仍不等于进程 RSS 上限。
- 空闲且尚未收到 RPC 的 gRPC 载体使用握手超时，使用过的空闲载体使用连接空闲超时；活动流各自遵循协议层的超时与取消规则。所有传输任务都由连接、出站池或共享服务持有并在退出时回收。

WS 的 Close 结束整个 WebSocket，不提供独立的 TCP 半关闭。HTTP Upgrade 保留 TCP 半关闭；gRPC 使用 HTTP/2 END_STREAM 和响应 trailers 结束相应方向。

## 验证

```sh
cargo test --locked --lib transport::
cargo test --locked --test proxy_protocols web_transports_carry
cargo test --locked --test proxy_protocols grpc_multiplexes
TERRARIS_XRAY=/tmp/terraris-xray \
  cargo test --locked --test proxy_protocols official_xray_web -- --ignored
TERRARIS_XRAY=/tmp/terraris-xray \
  cargo test --locked --test proxy_protocols native_web_outbounds -- --ignored
```

Xray 固定版本及构建方法见 [VLESS 验证](vless.md)。外部测试覆盖 Xray 客户端到 Terraris 的三种传输、VLESS/Trojan、gRPC Tun/TunMulti，以及 Terraris 三种传输出站到 Xray 服务端，均使用 TLS 身份验证。普通测试覆盖明文/TLS、跨窗口双向传输、分片与控制帧、升级首包保留、早期数据、坏帧隔离、多流、用户撤销、退役排空和资源回收。验证为本机与模拟面板，不代表真实反向代理/CDN、Linux 部署或长期负载验证。
