# Shadowsocks AEAD 与 Shadowsocks 2022

`shadowsocks`（别名 `ss`）已注册为入站和代理出站。实现使用 RustCrypto/BLAKE3 与 Terraris 的预算、用户策略及生命周期，不链接或启动 Go。线协议对照 [AEAD/SIP004/007](https://shadowsocks.org/doc/aead.html)、[SIP022](https://shadowsocks.org/doc/sip022.html)、[SIP023](https://shadowsocks.org/doc/sip023.html)，面板凭据兼容 Polaris `56d52fb44958ef3cc2a7fb841cd240f8206234b2`。

| 类别 | 方法 | TCP / 原生 UDP | 用户选择 |
| --- | --- | --- | --- |
| AEAD 2017 | `aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm` | 入站、出站 | 验证首块/数据报认证标签 |
| AEAD 2017 | `chacha20-ietf-poly1305`、`xchacha20-ietf-poly1305` | 入站、出站 | 同上 |
| AEAD 2022 | `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` | 入站、出站 | 支持单 PSK，或 EIH 多用户索引 |
| AEAD 2022 | `2022-blake3-chacha20-poly1305` | 入站、出站 | 单层 PSK；多用户入站逐项认证，不使用 EIH |

兼容 `aead_aes_128_gcm`、`aead_aes_256_gcm`、`chacha20-poly1305`、`aead_chacha20_poly1305` 别名。流密码、ShadowsocksR、SIP003 插件和 Shadowsocks 专用 multiplex 配置尚未实现，相关字段会拒绝。

## 面板入站

示例协议项中的密钥字符串仅用于展示字段格式：

```json
{
  "type": "shadowsocks",
  "enable": true,
  "port": 8388,
  "network": "tcp,udp",
  "cipher": "2022-blake3-aes-128-gcm",
  "server_key": "server-key-16byt",
  "uot": true
}
```

`network` 为空时启用 TCP + UDP；`tcp` / `raw` 仅 TCP，`udp` 仅 UDP，`tcp,udp` / `udp,tcp` 同时启用。可通过 `transport` 为 TCP 部分选择现有载体，或将 `network` 设置为 `ws/grpc/httpupgrade/xhttp` 以选择仅 TCP 的载体。TLS、Host、路径、service_name、XHTTP 参数由相应传输验证。原生 SS UDP 不经过这些流包装器；与 HTTP/3 同端口同时启用原生 UDP 会拒绝绑定。

`uot=true` 允许 TCP 连接使用 SagerNet UoT v1/v2；它与原生 UDP 可同时存在。未启用时拒绝 UoT 控制目的地址。UDP-only 配置不接受流传输或 TLS 设置。SS 自身提供认证加密，因此原始 TCP 不需要启用 VLESS 的 `allow_plaintext` 开关。

面板用户凭据使用现有的统一 credential 字段（由 PPanel 用户响应映射）。与 Polaris 一致：

- 2017：完整 credential 作为密码，按 EVP_BytesToKey/MD5 得到主密钥，再按连接/数据报的盐进行 HKDF-SHA1。
- 2022：取 credential UTF-8 字节的前 16 或 32 字节作为用户 PSK，长度不足会拒绝用户快照。修改这些字节之后的后缀不会改变线协议密钥；不同用户的派生密钥重复会拒绝整个候选快照。
- AES-2022 的非空 `server_key` 是 **16/32 个原始 UTF-8 字节**，不是 Base64 文本，表示 EIH 身份 PSK；客户端密码为 `Base64(server_key):Base64(user_psk)`。
- AES-2022 的 `server_key` 为空时使用标准单 PSK 格式，客户端密码仅为 `Base64(user_psk)`。2022 ChaCha20 也使用此格式，不接受 `server_key`。
- 2017 不接受非空 `server_key`，避免把未参与协议的配置当作额外安全层。

无 EIH 的多用户认证最多接受 1024 个用户，限制每次认证的试钥工作；超过会返回 `TooManyUsers`，不会部分安装用户。EIH AES-2022 使用 128 位身份哈希索引，服从节点统一的用户数量上限。所有模式共享握手并发及超时限制。

## 代理出站

```json
{
  "name": "ss-edge",
  "protocol": "shadowsocks",
  "address": "edge.example.com",
  "port": 8388,
  "cipher": "2022-blake3-aes-128-gcm",
  "password": "BASE64_SERVER_PSK:BASE64_USER_PSK",
  "rules": ["domain:example.net"]
}
```

2017 的 `password` 是原始密码；2022 必须为长度正确的标准 Base64 PSK（也接受省略末尾 `=`）。AES-2022 接受 1–8 个用冒号分隔的 PSK，最后一项用于端到端内容加密，前面各项生成 SIP023 身份头。服务端实现最终身份终点，不实现中间 EIH relay 角色。2022 ChaCha20 只接受一个 PSK。

`transport` 可选择现有 TCP 流载体；标准 TLS 的证书、SNI 和 ALPN 校验不变。原生 UDP 出站使用连接到代理端点的 UDP socket，校验响应认证、地址和重放状态；非 raw/TCP 载体若需要 UDP，设置 `uot=true`。`uot_version=1/2`，默认 2。SOCKS/HTTP 的用户名字段、VLESS UUID/Encryption、插件和专用 mux 字段不能混入 SS 出站。

## UDP 会话与用户策略

2017 按认证身份及客户端 IP/端口关联 UDP；2022 按认证身份、内容密钥及客户端 session ID 关联。通过认证与设备准入后，2022 更新客户端回包地址，支持同 IP 的端口重绑定；更换 IP 会重新执行设备准入，不能借 session ID 绕过设备限制。

每个关联拥有有界输入队列和按路由/地址族复用的 UDP 出口。回复只接受已请求的目标，远端代理解析域名的情况沿用公共 UDP 路由规则。协议、凭据与路由兼容的配置重载可以迁移关联的准入所有者并保留出口 socket；凭据撤销、策略变化、排空截止时间或空闲会关闭关联。密码相同但属于另一个用户作用域的会话不会混用。

加密、时间戳及重放校验先于用户准入，用户准入先于目标解析/拨号。TCP 和 UDP 都复用现有的用户撤销、共享限速、设备租约、路由、DNS 与计量；流量只统计成功转发的应用 payload，不计盐、地址、padding、EIH 和认证标签。

## 重放、I/O 与资源边界

- 2022 TCP 检查方向、±30 秒时间窗、服务端响应的精确 request-salt 绑定；使用精确盐集合，至少保留 61 秒，覆盖整秒时间戳边界，不使用 Bloom filter。
- 2022 UDP 在完整认证、类型、时间戳、地址及 client-session 绑定验证成功后才更新 1024 包滑动窗口。不同用户即使使用相同 session ID 也隔离；客户端最多跟踪两个仍在保留期内的服务端 session。
- TCP 盐缓存各自最多 65536 项，2017 保留 300 秒，2022 保留 61 秒；满额时拒绝新增而不提前驱逐。2017 UDP 是最多 65536 项、最长 60 秒的滚动盐历史，不提供 2022 的会话序号保证。2022 UDP 状态最多 65536 项，活跃引用不会被驱逐，闲置状态至少保留 61 秒。
- 重放状态位于进程内，在配置代次之间共享，不持久化到磁盘。2022 UDP 配置要求空闲时间至少 60 秒。
- TCP 接收记录上限分别为 16383 / 65535 字节；发送拆为最多 16383 字节的记录。读取保留部分记录及 nonce 状态，取消后可继续；写入只在整个认证记录发送完成后确认 payload。同一个未完成写入必须用相同前缀恢复，换数据或在其完成前 flush/shutdown 会终止流，避免重放或错计字节。
- 2022 首次读取必须包含盐、可选身份头和完整固定头；不完整或未知密钥的服务端请求统一关闭写方向并有界排空，受握手截止时间约束。
- 原生 UDP 的加密报文最多 65507 字节，实际 payload 上限还要扣除密码方法及地址等开销；超限拒绝，不自动分片。空 UDP payload 有效。
- 每关联最多 `queue_packets` 个排队包、32 个路由端口，每端口最多 256 个允许回复的目标。关联数量由 `max_connections` 约束，TCP/UDP 认证共享 `max_handshakes`。
- payload、待发送密文、解密块及排队数据使用 BufferScope；密钥、哈希索引、重放表等元数据另有数量上限，节点内存预算不等同于 RSS 上限。原始密钥、派生材料和支持的密码状态进行尽力清理，不承诺擦除编译器或系统的所有副本。

## 验证

```sh
cargo test --locked --lib protocol::shadowsocks
cargo test --locked --test shadowsocks
./tests/interop/shadowsocks/build.sh /path/to/Polaris /tmp/terraris-ss-peer
TERRARIS_SS_PEER=/tmp/terraris-ss-peer \
  cargo test --locked --test shadowsocks -- --ignored
```

Go peer 从上述固定提交的独立 archive 构建，不修改 Polaris checkout。正常 Cargo 测试不需要 Go；提交的 `vectors.json` 提供 Go 密码实现和固定版本 KDF 的已知答案，可用 `/tmp/terraris-ss-peer -role vectors` 重建。

覆盖八种方法的双向 TCP/UDP、EIH 多用户、UoT、空数据报、派生密钥冲突、重放和篡改、时间戳/响应绑定、读写取消、NAT 重绑定、用户撤销、设备拒绝、绑定回滚与关闭资源回收。结果来自本机真实 socket 和模拟面板；公网部署、持续高负载及针对性安全审计仍需独立验证。
