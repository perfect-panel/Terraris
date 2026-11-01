# Go Protobuf interoperability fixtures

These synthetic payloads are encoded using PPanel backend commit `764e937c` and its actual generated Go bindings, independently of Terraris's prost encoder. They contain no real users or credentials.

Regenerate from the adjacent backend checkout:

```sh
cd ../backend
go run ../Terraris/tests/fixtures/generate.go ../Terraris/tests/fixtures
```

Go is needed only to regenerate these checked-in fixtures. Normal Rust builds and tests do not require Go or a backend checkout. This verifies wire compatibility; it does not exercise a running backend, Redis, or PostgreSQL.

## VLESS Encryption vectors

`vless-crypto.json` contains deterministic BLAKE3 binary-context KDF and AES-GCM/ChaCha20-Poly1305 outputs generated using Xray commit `a4a3dff5b20c2faae567b742c172c7b95e75c083`. They are verified without Go by the Rust encryption unit tests. Regenerate from `tests/interop/encryption` with:

```sh
go run ../../fixtures/generate_vless_crypto.go > ../../fixtures/vless-crypto.json
```

The fixed bytes are test material, not deployment keys. External peer tests are documented in [docs/vless.md](../../docs/vless.md).
