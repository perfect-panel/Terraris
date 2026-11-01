# Third-party sources

Terraris application code is GPL-3.0-only. Files with other SPDX identifiers retain their source licenses. Cargo dependency versions and checksums are pinned in `Cargo.lock`.

## Xray VLESS / XUDP / VLESS Encryption

The wire implementation in the following files follows [XTLS/Xray-core](https://github.com/XTLS/Xray-core/tree/a4a3dff5b20c2faae567b742c172c7b95e75c083), commit `a4a3dff5b20c2faae567b742c172c7b95e75c083` (the locally tested client identifies itself as 26.10.31):

- `src/protocol/vless/wire.rs`
- `src/protocol/vless/xudp.rs`
- `src/protocol/vless/encryption/`, except `blake3_reference.rs` and Terraris test files

These files carry MPL-2.0 identifiers; the complete license is in [LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt). Their asynchronous I/O, resource accounting, lifecycle integration and error handling are adapted for Terraris. The primary protocol references are Xray's `proxy/vless/encoding`, `common/mux/frame.go`, `common/xudp`, and `proxy/vless/encryption` directories at the pinned commit.

The existing Polaris integration was consulted for PPanel field mapping and resource/lifecycle expectations; no Go core is linked into or launched by Terraris. Rust VLESS implementations in [rust-xhttp](https://github.com/jacek4yang/rust-xhttp/tree/8de99be3ed1b9446a23763d1b6c36976177eb124) and [xray-rust](https://github.com/aimalygin/xray-rust/tree/fbc0e49f02200351dc17754f6d1b1ac3113b54c8) were inspected during API evaluation. Their runtime or cryptographic source is not vendored here.

Cryptographic primitives use `ml-kem`, `x25519-dalek`, `aes-gcm`, `chacha20poly1305`, `aes`, and `ctr`, with fallible OS randomness from `getrandom`. No cryptographic primitive from Xray's Go code is embedded.

## BLAKE3 reference implementation

[src/protocol/vless/encryption/blake3_reference.rs](src/protocol/vless/encryption/blake3_reference.rs) is the BLAKE3 team's [reference implementation](https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs), source blob `bc6138350c5e1d56f2addc21f6da8d20dbe674fc`, used under CC0-1.0. The complete license is in [LICENSES/CC0-1.0.txt](LICENSES/CC0-1.0.txt).

VLESS Encryption uses arbitrary binary contexts for BLAKE3 derivation; the standard Rust API accepts UTF-8 strings. This local reference copy accepts `&[u8]` instead, without using unchecked UTF-8 or unsafe code. The compression algorithm is unchanged. Retained material-bearing hasher state receives best-effort zeroization on drop; module documentation and lints are adjusted for inclusion. Independent Go fixtures cover binary contexts across block/chunk boundaries, record rekey context lengths, and both AEAD choices.

## Test-only Xray peers

[tests/interop/encryption](tests/interop/encryption) is a separate Go module pinned to the same Xray commit. It is an optional interoperability test driver, not a Rust build dependency or a production process. The full Xray binary used by the end-to-end test is built from that same module version. Normal `cargo test` uses committed deterministic vectors and loopback Rust tests; the external-peer tests are explicitly ignored until their binary paths are provided.

## Routing and DNS

The GeoSite/GeoIP protobuf field definitions follow the Xray `app/router` data format. The built-in private-address prefix list retains Polaris's routing semantics. Runtime selectors, range indexes, resource limits and transactional asset loading are implemented in Rust. DNS wire messages are encoded/decoded by `hickory-proto`; the resolver lifecycle, scoped selection, cache and transports are managed by Terraris. DoH follows RFC 8484 and DoT follows RFC 7858, with certificate verification supplied by rustls.

## Trojan, AnyTLS and UoT

Trojan framing follows the [official protocol](https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md). AnyTLS v1/v2 framing, settings and the public default padding policy follow [anytls-go at fd6167acd6d73b9fa3e607659951847fbc9e6c50](https://github.com/anytls/anytls-go/tree/fd6167acd6d73b9fa3e607659951847fbc9e6c50). UDP over TCP follows the [SagerNet specification](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/) and `github.com/sagernet/sing/common/uot` v0.5.1 (GPL-3.0-or-later). Rust codecs and runtime integration are implemented here; no Go runtime is embedded.

[tests/interop/proxy](tests/interop/proxy) is an optional Go peer pinned to those upstream modules. It uses the actual upstream AnyTLS session client and UoT implementation to exercise the Rust server. The pinned Xray binary also exercises Trojan TCP/UDP. These helpers are not production dependencies.

TLS identities use rustls with its explicit aws-lc-rs provider. The Rust `md-5` dependency identifies the public AnyTLS padding policy only; it is not used for authentication, signing or encryption. User authentication uses SHA-224 (Trojan) or SHA-256 (AnyTLS) as required by their wire formats.

## Web stream transports

WebSocket framing uses `tokio-tungstenite` / `tungstenite`, following [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html). HTTP/1 parsing uses `httparse`; HTTP/2 framing and flow control use `h2`. TLS is still provided by the existing rustls/aws-lc-rs configuration, not a second TLS stack.

gRPC framing follows the [gRPC HTTP/2 protocol](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md). Hunk/MultiHunk field definitions, RPC method names, WebSocket early-data metadata and HTTP Upgrade behavior were checked against Xray's `transport/internet` at the pinned `a4a3dff5b20c2faae567b742c172c7b95e75c083` commit. The Rust adapters, scoped buffering and lifecycle integration are implemented here. No Xray Go transport source is vendored. The optional pinned Xray peer verifies both inbound and outbound interoperability.

## XHTTP / SplitHTTP

`src/transport/xhttp/` is a Rust port of [perfect-panel/Polaris at 56d52fb44958ef3cc2a7fb841cd240f8206234b2](https://github.com/perfect-panel/Polaris/tree/56d52fb44958ef3cc2a7fb841cd240f8206234b2/internal/transport/xhttp). Polaris identifies its source as XTLS/Xray-core SplitHTTP commit `b17a88f9b46d`. Ported files retain MPL-2.0 identifiers and [the full license](LICENSES/MPL-2.0.txt). I/O, flow control, resource budgets, TLS, task ownership and shutdown are adapted to Terraris. HTTP framing uses Hyper/h3 and QUIC uses Quinn; there is no Go production dependency.

The HPACK Huffman code-length table in `src/transport/xhttp/wire.rs` comes from `golang.org/x/net/http2/hpack/tables.go` (Go Authors), implementing RFC 7541 Appendix B. Its BSD-3-Clause notice is retained in [LICENSES/Go-BSD-3-Clause.txt](LICENSES/Go-BSD-3-Clause.txt).

[tests/interop/xhttp](tests/interop/xhttp) is an optional Go test peer compiled from an isolated archive of the pinned Polaris commit. It validates actual upstream client/server interoperability and is not part of normal Rust builds or deployment.
