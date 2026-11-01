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

[tests/interop/encryption](tests/interop/encryption) is a separate Go module pinned to the same Xray commit. It is an optional interoperability test driver, not a Rust build dependency or a production process. The full Xray binary used by the end-to-end test is built from that same module version. Normal `cargo test` uses committed deterministic vectors and loopback Rust tests; the three external-peer tests are explicitly ignored until their binary paths are provided.

## Routing and DNS

The GeoSite/GeoIP protobuf field definitions follow the Xray `app/router` data format. The built-in private-address prefix list retains Polaris's routing semantics. Runtime selectors, range indexes, resource limits and transactional asset loading are implemented in Rust. DNS wire messages are encoded/decoded by `hickory-proto`; the resolver lifecycle, scoped selection, cache and transports are managed by Terraris. DoH follows RFC 8484 and DoT follows RFC 7858, with certificate verification supplied by rustls.
