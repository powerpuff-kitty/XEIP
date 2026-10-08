# Local replay implementation checkpoints

Scope: implement ADR 0002 as an opt-in extension of local admission. Preserve both existing relay modes and the base 0.1 wire schemas. The ongoing implementation request authorizes reversible local code/docs/tests; no publication, public deployment or issue closure is part of this slice.

1. Specify scope, parsed-value comparison, monotonic expiry, no early eviction, HTTP responses and delivery-state limitations. Verify compatibility with the existing acceptance parsers.
2. Write failing unit tests for scope/content equality, conflict handling, fixed expiry, capacity refusal, bounded option validation and caller mutation. Implement a private bounded digest ledger. Keep elapsed time explicit at its native boundary for deterministic expiry tests.
3. Write failing real HTTP tests, then integrate after admission/expiry/frame checks and before any SSE writes. Cover simultaneous retries, changed IDs/content, full ledgers, reconnect loss, authorization changes and disabled-profile regression behavior.
4. Extend TypeScript acceptance typing/validation and the Rust example's strict acceptance parser through failing tests. Add bidirectional replay-profile interoperability with an explicit duplicate attempt. Add a runnable simulated retry/disconnect demo and CI invocation.
5. Review the slice for race/authorization/storage/lifecycle defects, fix important findings, update roadmap/security/transport/client truth, and verify Node 22 plus both supported Rust toolchains.

Done: identical admitted retries cause no new frames within the fixed window; conflicting or over-capacity new scopes cause no writes; invalid/unauthorized inputs cannot reserve records; relisten/credential changes do not clear the window; tests and demo establish the limited behavior without claiming durable delivery or exactly-once execution.

Rollback: omit the replay option and retain explicit admission-only behavior. This disables suppression and restores forwarding of repeats; it is never an automatic fallback after a 409/503. No persistent data or migration is introduced. Issue 4 remains incomplete until its receipt/ordering/resume/persistence criteria are met.

Execution result, 2026-10-09: all five checkpoints implemented locally. Node 22 passes 180 combined relay/schema/SDK tests, including 21 replay tests and 127 SDK tests. Rust 1.81.0 and 1.94.1 each pass 14 core/example tests and 21 real HTTP/SSE interoperability cases across all three modes. Schema validation passes five fixtures/100 vectors. TypeScript typecheck/build, Rust formatting/Clippy with warnings denied, all three simulated demos and relative documentation links pass. CI includes the replay demo and replay-profile exchange.

Read-only review found one wording ambiguity about simultaneous requests: the no-repeat guarantee is confined to the same active replay window; requests processed after expiry may be accepted again. The contract is corrected. Final review reports no remaining findings; no authorization bypass, live-record eviction, repeat-write race or lifecycle defect was found. Work remains uncommitted and experimental, with no release, deployment or issue closure implied.
