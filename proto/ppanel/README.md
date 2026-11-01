# PPanel node schema

Unmodified copy of `api/server/v1/server.proto` from the adjacent PPanel backend.

- Source commit: `764e937c658a62c0b562a11c7c0619261b01c882`
- SHA-256: `ea9b6ef027ebfff74d36e2442d3d726e4e91604f606c78e86739849bbe3b9a33`
- Transport: HTTP with `application/protobuf`, not gRPC.

`build.rs` uses locked prost-build and vendored protoc dependencies. Generated Rust stays in Cargo's output directory; no system protoc or sibling repository is required to build.

When updating the schema, update this provenance, review both JSON and Protobuf adapters, and run the wire contract tests.
