# Entity-bound signing implementation plan

Use the existing inline executing-plans workflow with a final fresh-context reviewer.

**Goal:** Implement the accepted 0.2 profile in JS/TS/Rust and the local relay, including persistent rollback checks.
**Spec:** [entity-signed-envelopes.md](../entity-signed-envelopes.md).
**Architecture:** independent crypto adapters reuse the existing canonicalization and key/trust primitives; a separate relay trust policy owns durable checkpoints. No old-profile changes or new dependencies. Keep Rust >=1.81 and Node >=22.

- [x] Shared vectors and Node runtime: `packages/identity/entity-envelope.mjs`, `tools/entity-envelope.test.mjs`, `conformance/fixtures/entity-envelope/vectors.json`. Test parent/device success; altered extension/proof; unknown critical extension; unrelated/removed/revoked keys; stale/future status; unanchored chain; downgrade; malformed wire JSON. Observe failing tests before implementation.
- [x] TypeScript browser API: `sdks/typescript/src/entity-envelope.ts`, export from index, consume identical vectors and reproduce signing bytes with WebCrypto. Verify strict types and legacy tests.
- [x] Rust module: `crates/xeip-identity/src/entity_envelope.rs`, export through lib, shared-vector integration tests. Verify stable/MSRV, Clippy and legacy vectors.
- [x] Relay/checkpoints: `services/relay/entity-trust.mjs`, `trust-checkpoint.mjs`, explicit `entitySignatures` in core/server; enforce admission, anchors, freshness and persistent counters. Test HTTP/WS acceptance, mutation denial, restart rollback, fork, corruption, exclusive lock, initialization/write failure cleanup and no fallback.
- [x] Document APIs/configuration/migration and update production/audit truth. Run schema/static/full coverage/SDK/Rust/interop suites, local demos, review entire feature and fix findings with regressions.

Review focus: authenticated metadata not accidentally excluded; exact carrier/parser agreement; cross-language time/number boundaries; failure before checkpoint persistence never serves; stale/missing checkpoint and old provisioning never reset trust.

Rollback: remove explicit profile selection and its source/API changes together; preserve checkpoint backups. Never downgrade an individual failed request. Keep the old profile untouched. Existing uncommitted audit work is retained on `audit/production-hardening`.

## Execution record

The fixture-first tests were observed failing before implementing each adapter. The original 28 shared vectors plus byte/signature and duplicate-wire tests passed in Node and TypeScript; Rust reproduced the same shared results and bytes on 1.81 and 1.94. HTTP/WS acceptance and restart/failure tests passed before final review.

Ruling: preserve the legacy signing contract and expose 0.2 only through explicit selection — existing callers retain their bytes and binding rules — cost: applications must migrate deliberately.

Ruling: status refresh uses trusted provisioning and restart in this experimental slice — no unauthenticated refresh surface or implicit operational policy is introduced — cost: stale status blocks sending until an operator refreshes it; this is not production lifecycle completion.

Ruling: retain the existing uncommitted audit branch and record execution here — user work and earlier batches remain reviewable together — cost: integration still needs a deliberate commit/release decision.

Final review found that comparing only a newer chain's tip allowed an earlier accepted generation to change. A failing relay restart regression now proves that higher generations must extend the exact checkpointed document. The stored schema is unchanged; verified per-generation digests are transient comparison inputs. Caller-mutation regressions also failed for Node signing metadata and asynchronous TypeScript signing/trust inputs; these inputs are now snapshotted before crypto work. Final suite results follow below.

## Final verification — 10 October 2026

- Relay/tools coverage suite: **340 passed**, zero failures; **94.32% lines, 88.69% branches, 96.49% functions**, above existing gates.
- Browser/Node TypeScript SDK: **240 passed**. Existing Rust/TypeScript transport interoperability: **32 passed**.
- Rust workspace: **80 passed, one intentionally ignored**, on both 1.81.0 and 1.94.1; Clippy with warnings denied and rustfmt passed. This includes the 28 new shared vectors and golden signing bytes/signature.
- SDK typecheck/build, focused relay strict types, fixture/schema validation (including 28 new entity vectors), syntax checks of all 75 tracked/new JS files, changed Markdown links and whitespace: passed.
- Legacy signing, trusted-key/status, durable and receipts demos passed. Entity-profile HTTP and WebSocket behavior is exercised by integration tests.
- All four review regressions were observed failing before their fixes, then the focused suite passed **75/75** and the full suites above passed. The fresh-context reviewer identified chain continuity and signing aliasing; trust-option snapshot consistency was additionally repaired by the implementer. No reported findings were intentionally deferred.
- Review limits: reviewer inspected the three adapters but did not execute Rust/TypeScript tests or complete an adversarial cross-language review. Those test results above are implementer evidence, not independent security certification. Live refresh, whole-disk rollback resistance and production filesystem certification remain explicitly outside this slice.
- Environment: macOS x86_64, Node **26.8.1**. Supported Node 22/Linux validation remains CI evidence to obtain before release. Logs: `/tmp/xeip-entity-final-*.log`, `/tmp/xeip-entity-rust.log`, `/tmp/xeip-entity-msrv.log`, `/tmp/xeip-entity-clippy.log`.

This experimental batch is complete and remains uncommitted on `audit/production-hardening`. No deployment, publication or merge was performed. Next: define and implement live status refresh/revocation plus trust recovery, then organization authentication and action authorization (G1/G2). The remaining backend, operations, real integration, distribution and pilot gates remain in the production-readiness document.
