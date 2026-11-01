# Go Protobuf interoperability fixtures

These synthetic payloads are encoded using PPanel backend commit `764e937c` and its actual generated Go bindings, independently of Terraris's prost encoder. They contain no real users or credentials.

Regenerate from the adjacent backend checkout:

```sh
cd ../backend
go run ../Terraris/tests/fixtures/generate.go ../Terraris/tests/fixtures
```

Go is needed only to regenerate these checked-in fixtures. Normal Rust builds and tests do not require Go or a backend checkout. This verifies wire compatibility; it does not exercise a running backend, Redis, or PostgreSQL.
