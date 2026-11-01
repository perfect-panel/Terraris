# XHTTP / SplitHTTP

`transport = "xhttp"` 与别名 `splithttp` 提供原生 Rust 入站和出站。移植基线是 Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2` 的 `internal/transport/xhttp`，保留 MPL-2.0 标注；运行时不链接或启动 Go。HTTP/1.1、HTTP/2 使用 Hyper，HTTP/3 使用 h3 + Quinn，TLS 复用 rustls/aws-lc-rs。

## 模式和承载

| 模式 | 上传 | 下载 | 半关闭 |
| --- | --- | --- | --- |
| `auto` | 出站选择 `packet-up`；入站接受三种模式 | 按实际请求 | 同实际模式 |
| `packet-up` | 带序号的多个有限请求，乱序重组 | 独立 GET 响应流 | 没有线上 EOF 标记；关闭会话结束下载 |
| `stream-up` | 单个流式请求 | 独立 GET 响应流 | 请求体结束表示上传 EOF |
| `stream-one` | 单个流式请求 | 同一请求的响应流 | 请求体结束表示上传 EOF |

未配置 TLS 时出站使用 HTTP/1.1，入站也接受 h2c prior knowledge。TLS 入站默认支持 `h2` 和 `http/1.1`；TLS 出站默认选择 `h2`，显式 `alpn=["http/1.1"]` 切换 HTTP/1.1。HTTP/3 要求 `security="tls"`、`alpn=["h3"]`，监听 UDP 端口，不能在同一监听器同时混合 TCP 与 QUIC。TLS 证书和 SNI 校验仍生效，不开启 QUIC 0-RTT。

HTTP/1.1 的流式请求使用 `Connection: close`，符合 Polaris 的全双工行为；分片上传可复用 HTTP/1.1 keep-alive。HTTP/2、HTTP/3 支持同一物理连接上的并发请求。

## 面板字段

入站协议项示例，TLS PEM 路径在本地 `[tls]` 中配置：

```json
{
  "type": "vless",
  "enable": true,
  "port": 443,
  "network": "xhttp",
  "security": "tls",
  "cert_mode": "file",
  "sni": "node.example.com",
  "alpn": ["h2", "http/1.1"],
  "host": "node.example.com",
  "path": "/relay",
  "xhttp_mode": "auto",
  "xhttp_extra": "{\"scMaxEachPostBytes\":1000000,\"scMaxBufferedBytes\":4194304}"
}
```

代理出站使用相同 `host`、`path`、`xhttp_mode`、`xhttp_extra`，以 `transport="xhttp"` 选择载体，另配代理协议、服务器 `address` / `port`、用户和 TLS 字段。VLESS、SOCKS5、HTTP CONNECT 的代理握手均可通过该字节流；远端需接受对应组合。Trojan、AnyTLS 入站也可组合 XHTTP/TLS。

`xhttp_extra` 是 JSON 字符串，最多 64 KiB，接受 Polaris 的 camelCase 字段。顶层 `host/path/mode` 由面板对应字段覆盖；存在嵌套 `extra` 时使用其配置并保留上述三个字段。未知字段、递归 `extra`、递归 `downloadSettings`、非法组合均报错。`serverBackend` 接受空值和兼容名称 `net/http`，实际实现始终为 Rust。

范围可以写成数字、`"100-1000"`、`{"from":100,"to":1000}`，反向范围会归一化。只接受非负 i32 范围，零值按对应字段的上游默认语义处理。

| 字段 | 默认 / 行为 |
| --- | --- |
| `headers` | 自定义请求/响应头，最多 64 项；禁止用它设置 Host |
| `xPaddingBytes` | `100-1000`，合法范围 1–16384 |
| `xPaddingObfsMode` | false：使用 Referer 查询参数 `x_padding` |
| `xPaddingPlacement` | `queryInHeader`；也支持 `header/query/cookie` |
| `xPaddingKey` / `xPaddingHeader` | `x_padding` / `X-Padding`，用于混淆模式 |
| `xPaddingMethod` | `repeat-x` 或 `tokenish`；校验 HPACK Huffman 编码长度 |
| `sessionIDPlacement` / `seqPlacement` | `path`，也支持 `query/header/cookie` |
| `sessionIDKey` / `seqKey` | header 默认 `X-Session/X-Seq`，其他为 `x_session/x_seq` |
| `sessionIDTable` / `sessionIDLength` | 空表使用 UUID；支持 Polaris 命名字母表及自定义 URL 安全 ASCII 表，长度最多 4096，组合空间至少 2³¹ |
| `uplinkHTTPMethod` | `POST`；支持自定义 HTTP method，GET 仅用于 `packet-up` |
| `uplinkDataPlacement` | `auto/body/header/cookie`；header/cookie 仅用于 `packet-up` |
| `uplinkDataKey` / `uplinkChunkSize` | header 默认 `X-Data` / `3000-4000`；cookie 默认 `x_data` / `2048-3072`，使用 Base64URL 分块 |
| `noGRPCHeader` / `noSSEHeader` | false；可关闭对应 Content-Type |
| `scMaxEachPostBytes` / `scMinPostsIntervalMs` | 1000000 字节 / 30 毫秒；单次上传最多 16 MiB |
| `scMaxBufferedPosts` | 30，最大 65536 |
| `scMaxBufferedBytes` / `scMaxTotalBufferedBytes` | 每会话 4 MiB / 共享服务 256 MiB；最大 1 GiB / 16 GiB，自动保持 total ≥ session ≥ maxPost |
| `scMaxActiveSessions` / `scMaxConcurrentRequests` | 各 16384，最大各 1048576；分片/流式上传和单请求双向流占请求名额 |
| `scStreamUpServerSecs` | `20-80` 秒的 stream-up 响应保活间隔 |
| `serverMaxHeaderBytes` | 8192，配置范围 1024–1048576；HTTP/1 解析缓冲最低 8192，业务校验仍遵守配置值 |

header/cookie 上传还受头部预算限制，出站会缩小实际分片，入站会拒绝超限头部。字段名、头部值、路径、会话标识均有独立长度检查。

## XMUX 与上下行分离

`xmux` 支持 `maxConcurrency`、`maxConnections`、`cMaxReuseTimes`、`hMaxRequestTimes`、`hMaxReusableSecs`、`hKeepAlivePeriod`。全部为零时采用 Polaris 默认：3 个连接组、每组 600–900 次 HTTP 请求、1800–3000 秒可复用时间。`maxConnections` 与 `maxConcurrency` 不能同时非零；上限分别为 128 和 1024。

池按不可变出站配置隔离，逻辑连接组可以包含多条 HTTP/1.1 socket；每组最多 64 条物理连接，每条 HTTP/2/3 连接最多 64 个活跃请求。复用次数、请求数或时间耗尽后轮换；旧请求保留各自租约。连接组选择与请求名额扣减在同一临界区内完成，避免并发轮换误判为连接关闭。只复用当前 DNS 候选仍包含实际对端的连接，空闲物理连接 300 秒后回收。失败不重放已发送的请求体。HTTP/3 对最多 64 个解析候选进行最多 4 路错峰尝试，每次握手最多 3 秒，总过程仍受调用方截止时间约束。

出站 `downloadSettings` 可以指定独立地址、端口、TLS 和 XHTTP 参数。例如 `xhttp_extra` 解码后的内容：

```json
{
  "xmux": {"maxConnections": 2},
  "downloadSettings": {
    "address": "download.example.com",
    "port": 443,
    "network": "splithttp",
    "security": "tls",
    "tlsSettings": {"serverName": "download.example.com", "alpn": ["http/1.1"]},
    "splithttpSettings": {"host": "node.example.com", "path": "/relay", "mode": "packet-up"}
  }
}
```

接受 `xhttpSettings` 或 `splithttpSettings`，以及 Polaris 的 `method` 网络名称覆盖。下载域名使用有界系统 bootstrap DNS；上下行最终必须到达共享同一会话表的服务。它不自动跨进程同步会话，不支持与 `stream-one` 合用；服务端禁止配置该客户端字段。

## 生命周期与资源

上传请求按最多 64 KiB 的块合并 HTTP DATA / QUIC 小片段，使用 BufferScope 存储，并计入会话/共享服务队列额度。当前序号的数据块可在整个 POST 结束前交给协议层，消费后立即归还缓冲；后续序号仍按序排队。默认 1 MB 上传最多需要 16 个合并后的块，不再为每个网络片段单独占用分配名额。

每条物理载体的上传块最多占用其一半缓冲字节和分配名额，另一半供协议转发和下载使用。默认连接额度保持 4 MiB / 256 个名额，上传最多占 2 MiB（32 个 64 KiB 块）；后续序号还需给当前序号保留至少一个块。会话及共享队列另保留首片额度。临时额度不足时停止读取请求体，等待消费、预算释放或取消信号，通过 HTTP/QUIC 流控向上游施加背压，不因瞬时耗尽立即返回 503。关闭、永久不合法的资源需求和请求/会话数超限仍会失败。

HTTP 发送方向直接转交管道中已有的 BufferLease，出站分片也通过共享字节视图保留跨片尾部；不再为发送每一块额外分配并复制缓冲。HTTP/QUIC 持有数据直到写出或确认期间，这些租约始终计入预算。管道写入遇到临时额度不足会等待释放；取消、对端关闭或预算关闭会结束等待。

重复片不重复交付，空片推进序号但不表示 EOF。上传读取及额度等待合计最多 30 秒；未建立下载的孤立会话在 30 秒后回收。若请求中断、截断或超过声明/配置长度，关闭整个会话，避免已经交付的前缀与下一片拼接。出站等待当前请求体被 HTTP 驱动接收后再提交下一片，同时允许响应流水线并发，避免大量后续请求体堵住当前片的共享接收窗口。

同一协议、端口和等价 XHTTP 参数的配置代次共享会话表，所以换用户快照、路由/报告配置或证书后，新建上传连接仍能找到旧会话。XHTTP 参数变化会产生新表，旧流按代次排空规则退出。每个逻辑流仍执行认证、当前用户撤销、限速、设备准入和 payload 计量。已有连接继续使用旧 TLS 身份，新 QUIC 握手在协议准入后使用当前代次身份。

请求驱动、分片上传、连接池和孤立会话回收均有任务数量上限；正常关闭取消并等待辅助任务，Drop 提供取消兜底。QUIC Endpoint 显式关闭并等待空闲，突然消失的 UDP 对端可能需要排空截止时间触发强制关闭。传输内部任务使用独立 Metrics 实例，目前不汇总到节点的任务 gauge。

Quinn 使用固定接收窗口，**未复制 quic-go 的自动窗口增长**：实际流/连接窗口使用 `h3InitialStreamReceiveWindow` / `h3InitialConnectionReceiveWindow`，默认 512 KiB / 1 MiB。`h3MaxStreamReceiveWindow` / `h3MaxConnectionReceiveWindow` 默认 4 MiB / 16 MiB，用作配置上界检查，不会使运行窗口自动扩张；四个字段上限均为 1 GiB，连接窗口不得小于流窗口。需较大窗口时直接调高 initial 值。

HTTP/TLS/QUIC 库另外分配的内部缓冲和元数据遵守库与连接数量限制，不计入 payload BufferScope；节点字节预算不是进程 RSS 上限。自定义会话字母表比 Polaris 更严格，只接受字母、数字及 `-_.~`，避免路径/查询/Cookie 分隔符冲突。生产反向代理/CDN、跨地域丢包及长期运行仍需独立验证；本机短时压力结果不能代替这些验证。

## 可复现验证

```sh
cargo test --locked --lib transport::
cargo test --locked --test proxy_protocols xhttp_
./tests/interop/xhttp/build.sh /path/to/Polaris /tmp/terraris-polaris-xhttp
TERRARIS_POLARIS_XHTTP=/tmp/terraris-polaris-xhttp \
TERRARIS_XRAY=/tmp/terraris-xray \
  cargo test --locked --test proxy_protocols xhttp_clients_interoperate -- --ignored
```

Polaris helper 从指定提交的独立临时 archive 构建，不修改源码 checkout。Xray 固定版本及构建方法见 [VLESS 文档](vless.md)。双向外部测试覆盖 `auto` 和三种模式，HTTP/1.1/2/3；Polaris 另覆盖明文 HTTP/1.1、自定义 header/cookie 上传、GET、元数据位置和 tokenish padding。普通测试覆盖分流下载、配置代次、撤销、地址回退、乱序、1 MB 小片段上传、额度等待与取消、默认配置的 16 流传输和额度回收。所有互通均为本地真实网络进程配合模拟面板。

### 默认配置持续压测

可选脚本使用真实 release 节点、模拟面板、固定版本 Polaris 客户端及独立 TCP echo 进程。节点保持默认 64 MiB / 16384 名额、每连接 4 MiB / 256 名额，XHTTP extra 为 `{}`；仅缩短测试退出排空时间。默认各跑两轮 HTTP/2 和 HTTP/3：单连接 15 秒，16 并发 60 秒，另有 1 秒预热。每条流检查数据内容和每秒进展，任何异常 I/O、内容错误或连续 5 秒停顿都会使该轮失败。RSS 为节点进程每 200 ms 的采样值，吞吐仅统计收到的应用载荷，不叠加上下行。

```sh
cargo build --locked --release
./tests/interop/xhttp/build.sh /path/to/Polaris /tmp/terraris-polaris-xhttp
python3 tests/interop/xhttp/benchmark.py \
  --node target/release/terraris \
  --polaris /tmp/terraris-polaris-xhttp \
  --output /tmp/terraris-xhttp-benchmark
```

输出目录必须为空；脚本写入结果/条件 JSON、节点日志及临时测试证书。也可用 `--alpn h3 --rounds 1` 单独复测。该同机回环测试不隔离后台负载，不代表跨地域、CDN 或生产容量。

固定 Xray 测试版本 `a4a3dff5b20c` 在默认 HTTP/3 XMUX 轮换时，替换后的上传连接未持有相应 running/request 租约，可能主动关闭仍在传输的 QUIC 连接。此现象也在 Xray 客户端到同版本 Xray 服务端的 16 并发持续对照中复现。Polaris `56d52fb` 持有上传、下载和请求租约，因此持续压力脚本使用该客户端；现有固定 Xray 测试继续用于线协议互通，不能将它的短测结果作为默认配置长时间稳定性的证明。
