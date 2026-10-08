# xeip-core

Transport-neutral Rust reference models for the experimental XEIP 0.1 specification.

```sh
cargo test -p xeip-core
```

Exposes `Entity`, `Capability`, `Endpoint`, `Session`, `Envelope`, `Body`, `MessageKind`, and basic `validate()` helpers. It deliberately has no network or AI dependency.

**This crate does not provide identity proof, signing, encryption, authorization, RFC 3339 strict parsing or complete JSON Schema validation.** It is not yet published or production-ready. See `spec/security.md` and conformance work in ROADMAP.md.
