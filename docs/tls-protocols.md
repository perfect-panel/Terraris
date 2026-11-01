# TLS、Trojan、AnyTLS 与 UoT

Terraris 的节点入站现包含 VLESS、Trojan 和 AnyTLS。三者共用路由、DNS、用户撤销、设备准入、限速、计量和配置发布流程。新增的 Trojan / AnyTLS 是入站实现；代理出站仍为 SOCKS5、HTTP CONNECT 和 VLESS。

## 协议组合

| 入站 | TCP | UDP | 安全层与扩展 |
| --- | --- | --- | --- |
| VLESS | 原生 command 1 | 原生 UDP、XUDP、可选 UoT v1/v2 | TCP/raw，可选 TLS、VLESS Encryption |
| Trojan | SHA-224 密码认证、CONNECT | 原生 UDP ASSOCIATE、可选 UoT v1/v2 | 必须启用 TLS |
| AnyTLS | SHA-256 密码认证、v1/v2 会话复用与多流 | 每个逻辑流使用 UoT v1/v2 | 必须启用 TLS；支持 settings、padding 策略协商、v2 SYNACK 与心跳 |

Trojan / AnyTLS 使用面板用户的 `uuid` 字段作为密码，不要求它符合 UUID 格式。VLESS 继续校验 UUID。未认证、格式错误和已撤销用户的连接会关闭。Trojan 未提供 HTTP fallback；TLS 未提供 REALITY、Vision 或客户端指纹模拟。[XHTTP](xhttp.md)、WebSocket、gRPC 和 HTTP Upgrade 已作为公共载体接入，见 [流传输文档](stream-transports.md)。

AnyTLS 服务端校验并下发 `padding_scheme`，为空时使用上游默认策略。MD5 仅识别公开的 padding 配置，认证使用 SHA-256。与上游服务端一致，padding 由客户端在发送方向应用，服务端接收并忽略 WASTE 帧。v2 成功 SYNACK 在目标 TCP 连接建立后发送；UoT 在其请求头完成后确认。

## 本地 PEM 配置

在本地 TOML 中指定证书链和私钥。路径相对于 TOML 所在目录：

```toml
[tls]
cert_file = "tls/fullchain.pem"
key_file = "tls/privkey.pem"

# 可选：按面板协议名覆盖默认身份。
[tls.protocols.anytls]
cert_file = "tls/anytls-fullchain.pem"
key_file = "tls/anytls-privkey.pem"
```

面板对应协议项需设置 `network="tcp"`（或其他已注册的流传输）、`security="tls"`、`cert_mode="file"`，并指定端口；可设置 `sni` 和 `alpn`。`cert_mode="self"` 也读取上述本地 PEM，用于操作者自行生成并持久保存的证书，不会自动生成或续签。`http` / `dns` 自动签发模式会拒绝。面板密码和证书私钥分别由各自的配置来源提供。

TLS 服务端显式使用 rustls 0.23 的 **aws-lc-rs** provider，启用 TLS 1.2/1.3，禁用 0-RTT 应用数据。证书链按叶证书在前排列，最多 16 张；证书文件和私钥文件分别限制 1 MiB。私钥支持未加密的 PKCS#1、PKCS#8 和 SEC1 PEM，必须仅含一个受支持的私钥，并与叶证书匹配。

`sni` 非空时，准备阶段校验证书名称，并只接受该名称的握手；为空时使用单个默认证书，客户端仍应验证服务端身份。`alpn` 最多 16 项，每项 1–255 字节。入站不接受 `allow_insecure` / `disable_sni`。

本地 `terraris check` 只校验配置形状，不打开 PEM 或访问面板。`run` 在面板配置准备阶段读取、校验 PEM；无效配置无法发布。

## 证书更新与连接生命周期

替换 PEM 后，下一次成功的面板配置同步会检查文件元数据，包括面板返回 304 或内容未变化的情况。没有独立文件监视器；仅修改本地 TOML 中的路径仍需重启。建议准备好整对文件后再替换，避免中间状态导致一次更新失败。

新的证书链、密钥、SNI、ALPN 全部校验通过后才发布。缺失、损坏、密钥不匹配或准备期间文件变化时保留旧代次和旧指纹，下次同步再尝试。新 TLS 握手使用新身份，已建立的连接继续排空，直到完成或到达配置的排空期限。状态上报按协议发送当前叶证书 DER 的 SHA-256 指纹。

AnyTLS 退役载体继续处理已建立的逻辑流，拒绝新的 SYN；待流和控制帧排空后关闭载体，客户端可建立新会话。用户撤销和不兼容路由策略更新仍立即取消相应会话。

## UoT 与资源约束

- UoT v1 使用 `sp.udp-over-tcp.arpa`；v2 使用 `sp.v2.udp-over-tcp.arpa`，支持固定目标的连接模式与逐包地址模式。
- Trojan / VLESS 入站需设置 `uot=true` 才解释 UoT 的特殊目标；启用后识别两种版本，`uot_version` 接受 0/1/2。AnyTLS 内建 UoT，不需要另行启用。
- SOCKS5、HTTP CONNECT 和 VLESS 出站可设置 `uot=true`，通过该协议的 TCP 连接承载 UDP；`uot_version=1/2`，省略或 0 默认 v2。远端必须支持对应 UoT。未启用时保留原有 UDP 行为；HTTP 出站会拒绝 UDP。
- 包长上限为 65507 字节，空 UDP 包有效。入站对实际 UDP 目标逐包执行路由、限速和流量计量；封装头、TLS、padding 和控制帧不计为代理 payload。
- `[node].max_streams` 默认 32，范围 1–1024，限制每条 AnyTLS TLS 会话的逻辑流数。连接、握手、队列、用户会话和 buffer 总额还受已有节点配置约束。慢流队列满时关闭该流，不能无限排队。
- UDP 关联最多持有 32 个出站端口，每个端口记录最多 256 个授权回复目标。达到限制会结束关联。AnyTLS 子流共享载体的 buffer 预算，TLS 内部内存不计入该预算。

增量读取保留未完成的包/帧状态，取消读等待不会错位。写入中途取消时关闭 UoT 连接或整个 AnyTLS TLS 载体，避免部分帧污染后续流；应用层应重新建连。AnyTLS FIN 表示整个逻辑流结束，不提供独立的 TCP 半关闭语义。

## 可复现验证

常规回环测试：

```sh
cargo test --locked --test proxy_protocols
cargo test --locked --test egress uot_v1_v2
```

官方 AnyTLS 客户端固定为 [fd6167a](https://github.com/anytls/anytls-go/commit/fd6167acd6d73b9fa3e607659951847fbc9e6c50)，测试驱动同时使用 SagerNet/sing v0.5.1 的 UoT 实现：

```sh
(cd tests/interop/proxy && go build -mod=readonly -o /tmp/terraris-proxy-client .)
TERRARIS_PROXY_CLIENT=/tmp/terraris-proxy-client \
  cargo test --locked --test proxy_protocols official_anytls -- --ignored
TERRARIS_XRAY=/tmp/terraris-xray \
  cargo test --locked --test proxy_protocols official_xray_trojan -- --ignored
```

Xray 的固定版本和构建方式见 [VLESS 文档](vless.md)。外部测试使用本地信任证书或证书指纹校验。AnyTLS 测试包含连续 TCP 请求复用一条 TLS 会话、UoT v1/v2 与连接模式；Xray 测试包含 Trojan TCP 和 UDP。Rust 回环另覆盖两种 AnyTLS 版本、多流、撤销、容量恢复、代次排空、多目标 UDP、证书更新与回滚。

以上为 macOS 本机和模拟面板验证；不代表 Linux 部署、真实面板、长期负载或跨节点设备名额竞争已验证。
