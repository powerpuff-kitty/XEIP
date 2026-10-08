# xeip-core

Transport-neutral Rust reference models for the experimental XEIP 0.1 specification.

```sh
cargo test -p xeip-core --all-targets --locked
```

Exposes `Entity`, `Capability`, `Endpoint`, `Session`, `Envelope`, `Body`, `MessageKind`, and `validate()` helpers on entities, capabilities, sessions, and envelopes. Validation enforces URI syntax, UTC calendar/time fields, schema string lengths, allowed transports, and unique kinds/members. Enums deserialize only from strings. Optional string fields may be absent, but explicit JSON null is rejected. It deliberately has no network or AI dependency and supports Rust 1.81+.

The shared vectors in `conformance/vectors.json` run against Rust, TypeScript, and a JSON Schema engine. **This crate does not provide identity proof, signing, encryption or authorization, and it is not a general JSON Schema validator.** It is not yet published or production-ready. See `spec/security.md` and conformance work in ROADMAP.md.

`examples/local_relay_peer.rs` is a separate, development-only HTTP/SSE participant for the cross-language harness. It uses `ureq` as a dev-dependency with TLS/compression disabled; the library's dependencies remain `serde` and `serde_json`. It validates incoming envelopes and echoes their content to the fixture's human participant with a new ID and `replyTo`. It never executes commands. Run `npm run test:interop` from the repository root to build the example, start an ephemeral loopback relay and exercise it with the TypeScript SDK.
