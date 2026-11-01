# 路由、DNS 与代理出站

`route` 编译 PPanel 规则，`dns` 提供解析和缓存，`outbound` 实现出站协议，`egress` 统一执行策略。VLESS、Trojan、AnyTLS 的 TCP/UDP、XUDP 和 UoT 共用此路径；认证、设备准入、用户限速及计量继续由原有 flow 层承担。

## 规则语义

首先匹配服务器 `block`，然后依照 `outbound` 数组顺序匹配每项的 `rules`，首个命中决定动作；同一项内的选择器为 OR。没有命中时直连。空 `rules` 不代表全匹配，可用 IP `0.0.0.0/0`、`::/0` 或域名 `regexp:.*` 明确表达范围。

| 选择器 | 含义 |
| --- | --- |
| `full:example.com`、`example.com` | 精确域名 |
| `domain:example.com`、`suffix:example.com` | 本域名与任意子域名，按标签边界匹配 |
| `keyword:example`、`plain:example` | 域名子串 |
| `regexp:^api[0-9]+[.]example[.]com$`、`regex:…` | Rust regex 支持的正则；不支持反向引用/前后向断言 |
| IP、CIDR、`ip:…`、`cidr:…` | IPv4/IPv6；IPv4-mapped 地址与对应 IPv4 统一处理 |
| `geosite:category`、`geosite:category@attribute` | GeoSite 类别；多个属性必须全部存在 |
| `geoip:category`、`geoip:private` | GeoIP 前缀；支持数据文件中的 reverse 标志；private 内置 |

域名大小写不敏感，忽略末尾的点；使用 ASCII/IDNA ASCII 名称。未知前缀、无效正则、缺少类别、未知协议和不支持的代理字段使整个候选失败。空白条目被忽略，带前缀的空值则拒绝。

精确/后缀域名用哈希集合匹配，关键字用 Aho-Corasick，IP 用合并后的有序区间和二分查询；GeoData 类别在一个引擎中共享，避免每条规则重复展开。规则总数、编译后的选择器总数/字节数、正则总数及单个正则内存都有上限。

直连、存在 IP 规则或配置自定义 DNS 时，域名先在本地解析，再使用原始域名与实际 IP 共同决策。TCP 连接回退只使用同一动作允许的解析地址，UDP 固定使用该计划中的目标地址。阻断、解析错误或代理错误均不会触发直连回退。未配置自定义 DNS 且没有 IP 规则时，代理目标域名可交由远端代理解析。

## DNS

PPanel `dns` 项使用 `proto`、`address`、`server_name`、`domains`：

| `proto` | `address` 示例 | 行为 |
| --- | --- | --- |
| `udp` | `resolver.example.com:53`、`udp://resolver.example.com:53` | 校验对端、随机 ID、问题名/类型/类别；TC 响应改用 TCP |
| `tcp` | `tcp://resolver.example.com:53` | 两字节 DNS 长度帧 |
| `tls` / `dot` | `tls://resolver.example.com:853` | DoT，强制证书与服务器名称验证 |
| `https` / `doh` | `https://resolver.example.com/dns-query` | DoH POST，强制 TLS；检查状态码、媒体类型、响应大小与 HTTP Age |

`domains` 使用域名选择器和 GeoSite；第一个匹配的分域服务器生效，最后一个空 `domains` 项是默认服务器。没有匹配项且没有默认服务器时返回错误。已选服务器失败时不改用另一服务器或系统解析。

`server_name` 可指定证书验证名称/SNI。DoH 保留原始 URL 的 Host 与连接目标，同时使用指定的 DNS 名称验证证书；IP 形式的 `server_name` 必须等于 URL 中的目标 IP，避免改变实际连接目标。DoH 不跟随重定向，也不继承环境代理。

解析服务器的域名通过 `[dns.bootstrap]` 中的固定 IP 或操作系统解析启动，避免递归依赖。代理服务器自己的域名也使用系统启动解析。目标域名的自定义解析失败不会因此回退到系统。没有自定义 DNS 时，普通地址解析使用操作系统；显式 DNS 出站可使用 `/etc/resolv.conf` 的服务器。

正缓存按响应的最短 TTL 过期，负缓存依据 NXDOMAIN/NODATA 的 SOA TTL 与 minimum；本地保留时间受 `max_ttl_seconds` / `negative_ttl_seconds` 限制。缓存回复重新填入请求 ID，并递减 TTL。HTTP Age 同样扣减 TTL。SERVFAIL、截断、不匹配及无效响应不进入缓存。缓存键保留查询类型、DNSSEC 标志、EDNS 参数和服务器身份。CNAME 只沿问题名的链跟进，拒绝循环与过长链；无关记录不会成为连接候选地址。

缓存同时限制条数和 wire 字节数，并使用 LRU 淘汰。相同查询合并为一项受持有的工作；单个等待者取消不影响其他等待者，最后一个等待者退出才取消查询。工作数、等待者数、响应大小、候选地址数及超时各自有限额。关闭时唤醒等待者并等待任务清理。

配置了自定义 DNS 且 `dns.intercept=true` 时，没有显式出站规则命中的 TCP/UDP 53 会进入本地 DNS 服务；也可用 `protocol=dns` 的出站规则选择该服务。服务检查查询域名与答复地址的阻断规则，返回 REFUSED/SERVFAIL 等 DNS 响应。UDP 回包保留原请求目的地址为来源；超出客户端 EDNS 大小的结果返回 TC。此功能经代理连接提供，不额外开启公网 DNS 端口。

DNSSEC 标志可以转发，但当前不进行本地 DNSSEC 验证。没有 DoQ、ECS 自动生成、DNS64 或多上游竞速。

## 代理出站

| 协议 | TCP | UDP | 安全层 |
| --- | --- | --- | --- |
| direct / freedom | 直连 | 原生报文 | — |
| block / reject / blackhole | 拒绝 | 拒绝 | — |
| dns | 本地 DNS 长度帧服务 | 本地 DNS 报文服务 | 上游可选 DoH/DoT |
| socks / socks5 | CONNECT，支持用户名/密码 | UDP ASSOCIATE，保留控制连接；可选 UoT | 可选标准 TLS |
| http | HTTP/1.1 CONNECT，支持 Basic 凭据 | 可选 UoT；未启用时拒绝 | 可选标准 TLS |
| vless | 原生 VLESS | XUDP 或 UoT | 可选标准 TLS、VLESS Encryption |

标准 TLS 校验证书与 SNI，支持附加 CA。只有面板明确设置 `allow_insecure=true` 才跳过证书链/名称验证。HTTP 出站只协商 HTTP/1.1。VLESS 出站支持 `native/xorpub/random`、1-RTT/0-RTT、公钥链与 padding；恢复失败使票据失效，应用数据不会自动重放。加密客户端当前使用 AES-256-GCM；入站仍接受两种已实现的 AEAD。

SOCKS5 UDP 仅接收已连接中继的报文；未指定的中继地址绑定到实际 TCP 代理对端。控制连接结束即结束关联。不支持 SOCKS UDP 分片。XUDP 部分写入被取消后会关闭该载体，防止下一条报文接在半帧之后。

代理出站不含 SOCKS4、Shadowsocks、VMess、Trojan、AnyTLS，也不含 REALITY、Vision、uTLS 指纹、WebSocket、gRPC、XHTTP 或外层多路复用。相关字段不会被静默忽略。SOCKS5/HTTP/VLESS 出站的 UoT 配置见 [TLS 与 UoT](tls-protocols.md)。

## 配置与重载

完整本地配置见 [terraris.toml](../examples/terraris.toml)。面板决定上游与规则，本地 `[dns]` 控制资源/超时/信任根，`[routing]` 指定 `geosite`、`geoip`、`outbound_ca_file`，`[routing.limits]` 控制编译上限。相对路径以 TOML 文件所在目录为基准。`check` 校验本地设置；文件读取及面板策略编译发生在节点候选准备阶段。

GeoData 必须由操作者提供，不自动下载。使用 Xray/V2Ray protobuf `.dat` 格式，文件大小和重复对象数在解码前检查。推荐以临时文件加原子 rename 更新。配置拉取返回 304 或相同内容时仍检查资产的文件身份、大小和修改时间；变化后重新读取并计算内容指纹。不要保留原 inode/大小/mtime 来原地覆盖资产，这种修改无法被元数据检查发现。

所有规则、DNS、代理及资源文件先编译为候选，成功后统一发布。失败保留原代次、缓存及服务。策略指纹相同时复用 DNS 缓存、出站对象和 GlobalID 映射；策略或资产内容变化时撤销所有不兼容的旧代次连接和 UDP 映射。删除坏文件后，也可通过面板移除相应规则来恢复有效配置。

引擎注册表最多同时持有 8 个策略版本；旧版本在会话、任务结束后回收。节点退出取消并 join 受持有的 DNS/本地服务工作。系统 getaddrinfo 无法被强制抢占，关闭依赖操作系统调用返回。DNS wire 缓存、报文和本地服务管道使用 BufferScope；规则索引、TLS/HTTP 内部资源等有独立限制，不纳入 payload buffer 口径，`memory_bytes` 不等于 RSS 上限。

## 验证

普通测试覆盖选择器、范围合并、GeoData/属性/reverse、资源上限、缓存 TTL/LRU/负缓存、查询合并/取消、分域失败、CNAME、DoH/DoT 验证、TCP/UDP DNS 服务、SOCKS5/HTTP 代理、TLS 信任、策略失败不直连、兼容重载和坏资产回滚。

固定 Xray 版本的外部互通还覆盖 Terraris → Xray 的 TCP/XUDP、三种 Encryption 外观、混合密钥链和两种 RTT。每组连续建立连接检验恢复。测试只使用本机回环；该 Xray 版本默认阻断私网，因此测试配置只为回环目标添加 allow 规则。其 XUDP 路径不保留零长度 UDP，外部用例使用非空报文；Terraris 原生收发测试单独覆盖零长度报文。

```sh
cargo test --locked --all-targets
cargo test --locked --doc
cargo clippy --locked --all-targets --all-features -- -D warnings
TERRARIS_XRAY=/tmp/terraris-xray \
  cargo test --locked --test egress native_vless_outbound -- --ignored
```

Xray 构建与版本固定方式见 [VLESS 验证](vless.md)。这些测试不代表生产面板、真实公网解析服务或 Linux 双架构运行验证。
