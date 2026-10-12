# Cloudflare transport implementation plan

Spec: [cloudflare-transport.md](../cloudflare-transport.md). Execute inline, preserve the current branch, use real-runtime regressions and one final fresh-context review.

## Tasks

1. [x] Exercise the existing MCP connector in actual workerd against the official SDK server. Add failing native success/redirect tests first, make the smallest compatibility correction, and retain no-retry/credential/late-guard semantics. Expand conformance to cancellation, malformed/oversize results, denial before send and target substitution. Expected: one exact authorized tools/call, no credentials/effect redirected, ambiguous effects never retried; Node organization tests stay green.
2. [x] Implement bounded Fetch ingress with real-workerd tests for origin/headers/routes, streamed size/UTF-8, body and operation deadlines, cancellation, fixed redacted errors and slots retained for unfinished work. Expose only /live, /ready and signed /v1/actions. Expected: invalid input never reaches the controller, liveness survives overload, late completion cannot release capacity early.
3. [x] Compose the ingress with existing authority/trust/ledger/controller and actual MCP transport in a private fixture. Verify signed lifecycle, revocation during OAuth/pre-send, uncertain effects, durable result inspection and restart without replay. Keep private SQL/setup inaccessible through public routing. Add reproducible script/types/CI coverage and verify Node 22/Linux and rebuilt Linux artifact if shared MCP code changes.
4. [x] Update guides/readiness/evidence, perform one scoped fresh review and fix accepted findings with failing-then-passing regressions in one pass. Retain deployment bootstrap/refresh/operations and hosted acceptance gates.

## Interfaces and files

- Existing `services/organization/mcp.mjs`: preserved EffectConnector interface, only runtime compatibility changes justified by a failing workerd test.
- New `services/organization/cloudflare/http.mjs`: `createWorkerHttp` returns `(request, {waitUntil}?) => Promise<Response>`; accepts controller.handle and owner-provided ready callback, no storage/admin ownership.
- `conformance/organization-cloudflare-transport{,-worker}.mjs` and fixture helpers: actual Fetch/SQLite/crypto/SDK network tests, private setup only.
- Cloudflare strict types, root scripts/CI, transport operator guide and readiness records.

## Review focus

- Header normalization, origin ambiguity or malformed UTF-8 must not bypass the signed-controller boundary.
- A deadline/cancellation must not free the concurrency slot while underlying work remains live.
- MCP redirects at discovery, token or effect endpoints must never send credentials or duplicate a tool call elsewhere.
- Revocation while OAuth discovery/grant work awaits must stop the actual tool request at the final guard.
- Runtime restart or lost response after an effect must preserve consumed claims and never re-execute them.

## Rulings and evidence

Ruling: continue the already-authorized Cloudflare exploration inline without new permission ceremonies — reversible transport work is within the production-readiness goal — cost if wrong: experimental changes can be discarded; deployment/adoption remains unapproved.
Ruling: use the existing canonical specs/plans and uncommitted branch — preserves prior work and avoids duplicate workspaces — cost if wrong: review needs exact baseline paths.
Ruling: prove transport before introducing the production object/bootstrap control plane — the current signed state machine is tested, but native network compatibility and Fetch cancellation still need evidence — cost if wrong: this transport batch must not be advertised as a deployable service.
Ruling: retain the shared MCP adapter and official SDK, with explicit redirect refusal — avoids diverging authorization/retry rules — cost if wrong: verify both Node and workerd after any shared correction.
Pre-flight: Fetch ingress consumes the unchanged controller API and must retain in-flight work; executor consumes the unchanged connector API and records outcomes through the ledger. Request-specific guards use shared ledger facades so fault quarantine persists across requests. The final live authority guard must run after OAuth awaits and immediately before the tool request.

Task 1: complete (uncommitted; tests: actual workerd MCP 12/12, Node organization 199/199). Success and late-guard cases failed before the fix. Temporary diagnostic confirmed workerd rejects redirect:error, then was removed. Shared connector now uses manual redirects and refuses every 3xx response. Bundler uses browser export conditions for the SDK's PKCE dependency; no dependency substitution.

Task 2: complete (uncommitted; native transport 42/42). Fetch ingress tests preceded implementation (missing module), then passed with real workerd streams, aborts, timers and retained slots; strict types included. Readiness uses the same admission budget; liveness bypasses it.

Verification in progress: the first 50 native transport scenarios passed, including composed signed actions against real MCP/OAuth, revocation during OAuth, uncertain effects and runtime restart. The expanded public-ingress scenario exposed Miniflare's synthesized loopback Host header; the harness now supplies the simulated edge Host explicitly rather than weakening the production origin check. The earlier Linux run copied that pre-correction fixture; any failure of that stale run is fixture evidence, not final verification.
Ruling: keep public origin checks strict and model Host explicitly in Miniflare dispatch — local proxy plumbing is not a production trust exception — cost if wrong: hosted raw-header behavior still needs acceptance.

Harness correction: explicit Host through dispatchFetch and getWorker still became loopback; direct Node HTTP to the local bridge reset the connection. None of these attempts changed product code. The final fixture constructs the Request inside workerd through private control, then calls the same public routing function and real Durable Object binding. The public-routing regression passes; hosted raw HTTP/header handling remains unverified. Two earlier full local/Linux runs each passed 149/150 and failed only this fixture routing case; final corrected full runs are pending.
Ruling: test native routing with internally constructed Requests rather than patching Miniflare or accepting a loopback Host in production — verifies actual workerd routing/controller/ledger behavior while preserving strict origin enforcement — cost if wrong: raw hosted ingress semantics are not covered by this local test.

A combined local run passed 149/150 but its 100 ms MCP guard-stall case expired during OAuth setup under host contention, before the guard ran (checks=0). Increased only the fixture's whole-call deadline/stall to 1000/1500 ms and the composed lost-response fixture deadline to 1000 ms; production limits unchanged. The tests still require the guard to run, no effect to be sent after deadline and consumed claims to remain non-replayable.
Ruling: the standard review-package script rejects BASE=HEAD because all authorized work is uncommitted — use an explicit scoped package plus the saved shared-MCP baseline; do not create commits or include unrelated earlier batches — cost if wrong: the reviewer must inspect the named live files and exact baseline, not a misleading empty Git diff.

Task 3: complete (uncommitted). Local Node 26/macOS passes 150/150 combined Cloudflare tests and strict types (`/tmp/xeip-cloudflare-transport-all-verified.log`). Pinned Node 22.23.3/Linux also passes 150/150 plus strict Cloudflare types and 199/199 organization tests/types (`/tmp/xeip-cloudflare-transport-node22-verified.log`); that copied fixture retains the shorter pre-contention-adjustment deadlines, while product code is identical. Final Node 26 organization 199/199/types pass. The rebuilt immutable Linux image `xeip-organization:local-cloudflare-transport-review` is sha256:5bc184fcd8f996b4bfbab490105018cc2f0beaa998330b71cf99eb1627e8613a (67,328,984 bytes); isolated artifact smoke passes. Root test:cloudflare includes the new cases and the existing Linux CI job runs it.
Final review requested against `/tmp/xeip-cloudflare-transport-review-scope.md`; no implementation changes during review.

Final review: `cloudflare_transport_review` found no Critical, Important or Minor issues. The reviewer independently passed 52/52 native transport tests, strict Cloudflare types and git diff --check. No fixes or second review were needed.
Final: Ruling: hosted raw-header normalization and edge routing were excluded — native constructed-Request routing is conformance evidence only; preserve hosted ingress acceptance — cost if wrong: platform normalization could reject valid callers or weaken ambiguity handling.
Final: Ruling: hosted eviction, replication, recovery, capacity and latency guarantees were excluded — local tests cannot certify these; retain the agreed hosted workload/recovery gates — cost if wrong: acknowledged work or service objectives could fail during an outage.
Final: Ruling: production bootstrap, protected administration, trust refresh, retention and deployment packaging were excluded — this is a transport dependency of the still-open service task, never a deployable fixture — cost if wrong: exposing fixture controls or resetting missing trust would compromise authority.
Final: Ruling: real private MCP networking and human PKCE were excluded — controlled local OAuth/MCP and prior real Keycloak protocol checks do not prove those operator environments — cost if wrong: real network access or human enrollment could fail.
Final: Ruling: previously reviewed authority/trust/ledger internals were composition context — retain their separate evidence and whole-product security acceptance — cost if wrong: this scoped review does not certify inherited implementation.
Final: Ruling: cancellation cannot undo an already-sent remote effect — preserve consumed claims and indeterminate outcomes, with no automatic replay; remote reconciliation is an operator responsibility — cost if wrong: retrying uncertain work could duplicate effects.
Final: Ruling: preserve the uncommitted branch and leave deployment/adoption unapproved — the broader production-readiness goal continues — cost if wrong: a clean reviewed release boundary is still required before publication.
Task 4: complete. No deferred findings. Source/image MCP SHA-256 match: 3babc8500fd2225234a0ff32ad12f2fdfd8305ec70384b17575f6f476c1d61ff. Final evidence remains 150/150 combined Cloudflare and 199/199 organization on Node 26/macOS and pinned Node 22/Linux, strict types, rebuilt isolated artifact smoke, and independent 52/52 transport review verification. No shared code changed after those checks. Next: explicitly initialized production object lifecycle, protected owner/trust refresh and deployment packaging; actual private route and hosted recovery/capacity/security/human acceptance remain open.
