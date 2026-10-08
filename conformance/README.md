# XEIP 0.1 conformance checks

`npm run validate:fixtures` checks JSON Schemas and the shared structural validation vectors. Rust and TypeScript run the same vectors in their own tests.

For a real HTTP/SSE exchange between the TypeScript SDK and a separately implemented Rust example:

```sh
npm ci --ignore-scripts
npm run test:interop
```

This requires Node 22+ and Rust 1.81+. The harness builds the TypeScript SDK and the Rust `local_relay_peer` example using the checked-in lockfiles, chooses free loopback ports, generates temporary credentials, and cleans up all streams and processes. It runs the bidirectional exchange in shared-token, local-admission and local-replay modes. No separately running relay is needed. CI runs it on both supported Rust toolchains.

The TypeScript client subscribes as `message.valid.json`'s sender; Rust subscribes as its recipient. TypeScript sends the public fixture, then a command envelope containing nested JSON, null, booleans, numbers, a newline, accented text, emoji and a namespaced extension. Rust validates each envelope using `xeip-core`, preserves its content, kind, timestamp and extensions, swaps sender/recipient, appends `-reply` to the ID and sets `replyTo` to the original ID. TypeScript validates and compares the complete reply. These are transport echoes, not command execution or delivery receipts. The `delivered` response reports writes to active streams only.

The Rust example independently parses SSE, with fragmented UTF-8, LF/CRLF/CR endings, multiline data, comments, an initial BOM and bounded unfinished frames covered by Rust tests. It rejects invalid UTF-8. Its limit is 128 KiB of frame content including field/comment lines (CRLF counts as one line ending). It rejects non-SSE HTTP responses and unauthorized connections before declaring readiness. Connections use a fixed loopback host, disable proxies/redirects, and have a 30-second total request timeout. The peer is deliberately a short-lived example, not a reusable Rust networking SDK.

The admission exchange gives TypeScript and Rust separate credentials bound to the fixture's sender and recipient and provisions a direct session containing those two entities. TypeScript spoofed-sender and unknown-session sends fail 403; Rust cannot subscribe as the other entity using its valid credential. Native relay HTTP tests additionally cover membership removal, revocation, rotation, authorization changing during a POST body read, and subscription quotas.

The replay exchange adds a bounded retry ledger to that same admission setup. Each new send reports `duplicate: false`; a TypeScript retry of the identical envelope reports true/zero writes, and a changed-body retry fails 409. Rust accepts the optional false flag on its reply acceptance; its short-lived echo example still requires a new write to a subscriber and rejects duplicate replies. Both adapters reject malformed duplicate flags. Native HTTP tests verify simultaneous retries, lost HTTP responses, conflicts, expiry, capacity refusal, sender/session isolation, authorization changes, and reconnects without offline delivery.

These checks prove interoperability and local credential/membership enforcement between the current in-repository implementations. They do not establish independent authorship, production security, durable replay/reconnect, portable cryptographic identities, or interoperability with third-party clients. Those remain roadmap work.
