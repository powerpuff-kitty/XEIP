# XEIP — eXtensible Entity Interaction Protocol

Experimental protocol + reference implementation for human/agent/machine/service interaction.
The map below is ordered by dependency, not by how far along each part is.

## Define the wire protocol {#spec}

tech: normative profile specs, JSON Schemas and ADRs under spec/ and schemas/
files: [spec/**, schemas/**]
links: [identity, relay]

- [x] Draft entity, endpoint, capability, session and message schemas {#spec-schemas}
      tech: schemas/entity.schema.json, schemas/session.schema.json, schemas/capability.schema.json, schemas/message.schema.json, spec/core.md
- [x] Pin version negotiation and migration notes {#spec-version}
      tech: spec/versioning.md, spec/core.md
- [x] Write the local profile specs (admission, replay, delivery, receipts, durable, limits, transports) {#spec-profiles}
      tech: spec/local-\*.md, spec/transports/http-sse.md, spec/transports/websocket.md
- [x] Record the identity designs (keys, entity signing, live trust) {#spec-identity}
      tech: spec/identity.md, spec/identity-keys.md, spec/entity-signed-envelopes.md, spec/live-entity-trust.md
- [x] Record ADRs 0001–0014 {#spec-adrs}
      tech: spec/decisions/README.md
- [x] Write the threat model and security policy {#spec-security}
      tech: spec/threat-model.md, spec/security.md, SECURITY.md
- [x] Prepare the Cloudflare staging setup for the existing account {#spec-cloudflare-staging}
      by: codex
      from: agent
      tech: Reviewable private smoke and full acceptance stages, account access evidence, prerequisites and cost boundaries; no deployment authorization inferred.
- [ ] Define scoped grants and their enforcement for v0.2 {#spec-grants}
      from: roadmap
- [ ] Define capability discovery manifests and transport negotiation {#spec-discovery}
      from: roadmap

## Model and validate data {#models}

tech: Rust wire models plus one schema/validation vector set shared by Rust, TypeScript and the relay
files: [crates/xeip-core/**, sdks/typescript/src/validation.js, tools/validate-fixtures.mjs, tools/schema.test.mjs]
needs: [spec]
links: [identity, sdk, relay]

- [x] Model entity, endpoint, capability, session and envelope types in Rust {#models-rust}
      tech: crates/xeip-core/src/lib.rs
- [x] Enforce strict field, format and URI validation {#models-strict}
      tech: crates/xeip-core/src/validation.rs
- [x] Drive JSON Schema, Rust, TypeScript and relay validation from one vector file {#models-vectors}
      tech: tools/validate-fixtures.mjs, conformance/vectors.json
- [x] Property-test parsing against malformed input {#models-property}
      tech: crates/xeip-core/tests/property_parsing.rs

## Prove who an entity is {#identity}

tech: Ed25519 key IDs, detached signatures, key/status/rotation documents and entity-bound 0.2 signing
files: [crates/xeip-identity/**, tools/key-document*, tools/signed-envelope*, tools/identity-*, tools/derive-keyid.mjs, tools/keyid.test.mjs, packages/identity/**, sdks/typescript/src/identity.ts, sdks/typescript/src/keydoc.ts, sdks/typescript/src/entity-envelope.ts, sdks/typescript/identity.test.mjs, sdks/typescript/keydoc.test.mjs, sdks/typescript/entity-envelope.test.mjs]
needs: [spec]
links: [models, relay, sdk]

- [x] Derive and verify self-certifying key IDs {#identity-keyid}
      tech: crates/xeip-identity/src/lib.rs, tools/derive-keyid.mjs
- [x] Sign and verify detached Ed25519 envelopes {#identity-signed}
      tech: tools/signed-envelope.mjs, crates/xeip-identity/src/lib.rs
- [x] Verify signed key documents with chain, rollback, fork and fail-closed anchors {#identity-keydoc}
      tech: tools/key-document.mjs, crates/xeip-identity/tests/keydoc_vectors.rs
- [x] Reject a forged genesis that is not self-signed {#identity-genesis-self-cert}
      by: coordinator
      from: agent
      tech: verifyKeyDocument/Rust/TS now require a genesis document to list its own genesis key in roots AND be signed by it; new stable reason "genesis not self-signed" with negative vectors in JS/TS/Rust and a demonstration that a victim-entity/attacker-root forgery is refused.
- [x] Verify signed status/revocation documents with monotonic serial and staleness {#identity-status}
      tech: tools/identity-status.mjs, crates/xeip-identity/tests/status_vectors.rs
- [x] Verify bounded device-rotation and root-rotation statements {#identity-rotation}
      tech: tools/identity-device-rotation.mjs, crates/xeip-identity/tests/rotation_vectors.rs
- [x] Sign and verify entity-bound 0.2 envelopes with protected extensions {#identity-entity}
      tech: crates/xeip-identity/src/entity_envelope.rs, packages/identity/entity-envelope.mjs, sdks/typescript/src/entity-envelope.ts
- [x] Reproduce identical bytes and signatures across JS, TS and Rust {#identity-crosslang}
      tech: crates/xeip-identity/tests/\*\_vectors.rs, sdks/typescript/keydoc.test.mjs
- [x] Share verified trust preparation and rollback rules across storage backends {#identity-trust-state}
      by: codex
      from: agent
      tech: packages/identity/trust-state.mjs; preserve existing filesystem-backed trust behavior while enabling the Durable Object adapter
- [x] Validate trust reloads without blocking the request thread {#identity-async-refresh}
  by: codex
  from: agent
  tech: Measure the 700-identity reload, isolate signature preparation in a bounded Node worker, preserve checkpoint/revocation ordering and drain behavior.
- [ ] Automate status distribution and operational rotation/recovery {#identity-distribution}
      from: roadmap
- [ ] Get an independent cryptographic review {#identity-review}
      from: roadmap

- [x] Parse large signed JSON without per-character string allocation {#identity-json-throughput}
  by: codex
  from: agent
  tech: Structural-token scan and ordinary-string runs preserve strict JSON/Unicode checks; parser review and compatibility evidence complete, current full macOS/Linux527/527 and types pass. Historical deadline failures remain documented; hosted timing is not certified.

- [x] Load identity runtime without command-line modules {#identity-runtime-boundary}
  by: codex
  from: agent
  tech: Extract four Node identity modules into packages/identity, retain CLI/import compatibility, verify vectors and the runtime image; spec/plans/identity-runtime.md.

- [x] Type-check Node key encoding and signed-envelope implementation {#identity-node-static}
  by: codex
  from: agent
  tech: Added strict/noUncheckedIndexedAccess checking for key-id.mjs and signed-envelope.mjs plus compile-only key/input contracts, local command and Node CI step. Baseline45 diagnostics resolved without runtime AST changes or suppressions. Root385, organization211, SDK241, fixtures, interoperability36 and existing semantic gates pass. Temporary fault probes show both source files are checked. Review's diagnostic-message/JWK type findings fixed, JWK consumer RED→GREEN, no remaining findings. Other identity implementations and hosted CI remain unverified by this increment; spec/plans/identity-static-analysis.md.

- [x] Split Rust identity verification into focused modules {#identity-rust-modules}
  by: codex
  from: agent
  tech: Extracted the2949-line identity root into focused private modules with82-line root and53 explicit unchanged public exports. Mechanical source comparison preserves all implementation/test bodies and constants. Rust1.94.1 and1.81 each pass80 tests with the existing live-relay smoke ignored; formatting, Clippy, rustdoc and36 interoperability cases pass. Scoped review reports no findings; plan spec/plans/rust-identity-modules.md. Independent crypto and production acceptance remain open.

- [x] Reduce temporary allocations when parsing signed identity data {#identity-reference-json-runs}
  by: codex
  from: agent
  tech: Allocation profile identifies reference parseString as33.20% of large export self-allocation estimates (including reopen). Port the existing SDK ordinary-run scan to the shared Node parser with unchanged strict rejection semantics. Five long-string/strict preservation cases pass before/after;143110 differential inputs match values or error class/message exactly; review finds no issues. Root385/385, SDK241/241, organization211/211 and interoperability36/36 pass; Fixture vectors, relay/organization/Cloudflare types and full native Cloudflare721/721 pass. Unprofiled large export completes, profiled repeat returns unavailable; reported parser allocations including regex descendants fall~88% within sampled capture branches, with explicit profiler and incomplete-transfer caveats. Expanded frozen-source Linux stopped at root383/385: two console routes returned500. Controlled Linux reproduction confirms the missing examples/local-relay assets:0/2 before,2/2 after adding only three static files. Asset-corrected Linux passes root385/385 and SDK241/241 but organization207/211: configuration tests reject the uid1000/world-writable temporary ancestor. Controlled permission check confirms15/19 under uid1000/mode1777 and19/19 after restricting only /tmp to0700. Corrected expanded Linux completes root385/385, SDK241/241, organization211/211, fixtures, all three types and full Cloudflare721/721 in658.03s, combined exit0. Source fingerprints unchanged; application checks unchanged. Parser increment complete locally. Resource/latency acceptance remains open. No canonical wire or input limit changes.

## Move messages between entities {#relay}

tech: authenticated loopback HTTP/SSE and WebSocket relay with opt-in admission, replay, delivery, receipts, durable, limits and trust profiles
files: [services/relay/**]
needs: [models, identity]
links: [sdk, demos]

- [x] Broadcast typed messages over authenticated HTTP+SSE {#relay-http}
      tech: services/relay/server.mjs, services/relay/relay-core.mjs
- [x] Bind credentials to entities and closed session membership {#relay-admission}
      tech: services/relay/admission.mjs
- [x] Suppress identical authenticated retries in a bounded window {#relay-replay}
      tech: services/relay/replay.mjs
- [x] Sequence sessions, resume by cursor and signal gaps {#relay-delivery}
      tech: services/relay/delivery.mjs
- [x] Record bounded per-principal recipient receipts {#relay-receipts}
      tech: services/relay/receipts.mjs
- [x] Persist accepted messages across restart with compaction and a single-writer lock {#relay-durable}
      tech: services/relay/durable.mjs
- [x] Enforce request-rate and connection/subscription limits {#relay-limits}
      tech: services/relay/limits.mjs
- [x] Serve WebSocket with bounded queues and cursor resume {#relay-websocket}
      tech: services/relay/websocket.mjs
- [x] Resolve signed-envelope kids through trusted key documents and enforce revocation {#relay-keydoc}
      tech: services/relay/relay-core.mjs, services/relay/status-http.test.mjs
- [x] Enforce entity-bound signing with persisted trust checkpoints and live refresh {#relay-entity-trust}
      tech: services/relay/entity-trust.mjs, services/relay/trust-checkpoint.mjs, services/relay/entity-refresh.test.mjs
- [x] Commit replay and durable acceptance only after storage succeeds {#relay-acceptance}
      tech: services/relay/acceptance.test.mjs, services/relay/recovery-failures.test.mjs
- [ ] Certify a production durable backend against process-kill, disk-full and corruption {#relay-durable-cert}
      from: roadmap
- [ ] Add operations controls: TLS ingress, readiness/liveness, drain, logs and metrics {#relay-ops}
      from: roadmap

## Call the protocol from an app {#sdk}

tech: TypeScript SDK for models, HTTP/SSE streaming, signing, key documents and entity envelopes
files: [sdks/typescript/**]
needs: [models]
links: [identity, relay]

- [x] Type and validate messages, entities, sessions and capabilities {#sdk-models}
      tech: sdks/typescript/src/index.ts, sdks/typescript/src/validation.js
- [x] Stream messages over HTTP/SSE with typed delivery events and gaps {#sdk-delivery}
      tech: sdks/typescript/src/index.ts, sdks/typescript/delivery-http.test.mjs
- [x] Sign and verify envelopes and key documents in Node and the browser {#sdk-signing}
      tech: sdks/typescript/src/identity.ts, sdks/typescript/src/keydoc.ts
- [x] Sign and verify entity-bound 0.2 envelopes with WebCrypto {#sdk-entity}
      tech: sdks/typescript/src/entity-envelope.ts, sdks/typescript/entity-envelope.test.mjs
- [ ] Publish versioned SDK artifacts with a supported-platform matrix {#sdk-publish}
      from: roadmap

## Operate an organization's identities and approvals {#organization}

tech: Keycloak authentication, a signed operation controller, deny-by-default action policy, PostgreSQL ledger and MCP execution
files: [services/organization/**, deploy/**]
needs: [identity, sdk]
links: [relay, conformance]

- [x] Verify Keycloak JWTs plus live introspection against a pinned realm {#org-auth}
      tech: services/organization/auth.mjs, conformance/keycloak.mjs
- [x] Map provider subjects to entities and signing keys explicitly {#org-mapping}
      tech: services/organization/auth.mjs
- [x] Enforce deny-by-default exact-action policy with content digests {#org-policy}
      tech: services/organization/actions.mjs
- [x] Refuse acknowledgements when PostgreSQL replication is uncertain {#org-replication-ack}
      by: codex
      from: agent
      tech: Reproduced cancelled synchronous COMMIT returning success; reject commit notices and fence every result including inspection/idempotent retries with a transactional WAL marker.
- [x] Persist actions and audit events in PostgreSQL with single-use claims {#org-ledger}
      tech: services/organization/store.mjs, services/organization/migrations/001-actions.sql
- [x] Compose current provider and trust checks before every claim and effect {#org-authorize}
      tech: services/organization/authorization.mjs, services/organization/execution.mjs
- [~] Preserve authorization state alongside recovered actions {#org-postgres-control-recovery}
      by: codex
      from: agent
      tech: A12 reproduced twice with real disposable PostgreSQL: old signed trust plus old checkpoint reactivates a revoked device; current DB unchanged, one synthetic unconsumed effect. Evidence/fingerprints retained in spec/audits/2026-10-12-linux-control-recovery.md. ADR0018 and spec/plans/postgres-control-recovery.md define PostgreSQL control history, owner enrollment and action/dispatch fencing. Design-review ordering/revision/re-addition/startup findings addressed; model, SQL storage, runtime trust, action/dispatch fencing and owner workflows implemented locally; SQL retained-history correction and combined physical recovery pending. Real Keycloak, secrets, independent storage and operator acceptance remain separate gates.
- [x] Reproduce and specify the Linux authorization restore boundary {#org-postgres-control-audit}
      by: codex
      from: agent
      tech: Two isolated actual-PG probes reproduce A12, with protected temporary files cleaned. Durable probe/result/source hashes, ADR0018, contract and implementation plan added. Scoped review reports no remaining important design contradictions after dispatch/revision/removal/startup corrections. This completes investigation/design, not the runtime fix or production acceptance.
- [x] Validate immutable public authority and trust control snapshots {#org-postgres-control-state}
      by: codex
      from: agent
      tech: Canonical public projection, signed trust transitions and historical validation implemented with frozen JSON and no stored credentials. Removed identities/target revisions retained; owner changes distinguished from trust-only reload. Review's operation-coercion finding and explicit-null default issue fixed RED→GREEN; combined-size fault probe demonstrates refusal. Native15 focused,231 organization,385 root, strict types and vectors pass. SQL/runtime integration remains next; A12 remains open. See spec/plans/postgres-control-recovery.md.
- [~] Persist control history with PostgreSQL durability and restricted grants {#org-postgres-control-store}
      by: codex
      from: agent
      tech: Implemented shared transaction extraction, immutable events/atomic head, owner-only enrollment/authority changes, runtime trust updates and expected-head locks. Actual SQL, cancelled synchronous commits, historical upgrade, native249 organization/385 root, strict types and Node22/Linux52 focused checks pass. Null-counter and signed alternate-chain SQL regressions fixed RED→GREEN. Scoped review identified a P2 retained-history integrity gap: raw SQL could forge records that inactive snapshots accept and later owner re-addition trusts. Forward migration004 now binds retained metadata to accepted signed provisioning (inactive records frozen, invented identities refused, active counters bound to documents) and the bounded read path verifies the head/predecessor transition; actual-PG removal/counter/invented-identity regressions fixed RED→GREEN. See spec/plans/postgres-control-recovery.md.
- [x] Activate runtime trust only from committed PostgreSQL control state {#org-postgres-trust}
      by: codex
      from: agent
      tech: Actual launcher opens exact enrolled inputs, validates fresh trust off-thread, and activates only certain durable publication. Lifecycle review blocking-crypto finding fixed with bounded control worker. Native267 organization/385 root, Linux235 top-level tests, strict types, actual PG approved-action/stale-startup regression, replication and image smoke passed. Task3 evidence in spec/plans/postgres-control-recovery.md; A12 remains open.
- [x] Fence action transactions and tool dispatch against control changes {#org-postgres-action-fence}
      by: codex
      from: agent
      tech: Implemented head-before-action locks, request-scoped tokens and synchronous MCP dispatch guard. Four-action actual-PG race, stale cache, consumed claims and post-revocation completion pass. Scoped review found no Important/Critical issues; native285/root385, strict types, real Keycloak/HTTPS/MCP integration, replication and rebuilt artifact pass. Full pinned Node22/Linux285-case suite passes after correcting test-only executable temporary storage; evidence in spec/audits/evidence/2026-10-12-postgres-action-fence-results.json. Task5 ownership lease still required.
- [x] Coordinate runtime ownership with explicit owner control changes {#org-postgres-maintenance}
      by: codex
      from: roadmap
      tech: Task5 locally verified: dedicated runtime/maintenance ownership, protected owner enrollment/change/inspect, complete legacy checkpoint import and fail-closed lease loss. Native322/Linux322, strict types, actual-PG CLI over verified TLS and rebuilt artifact pass; scoped owner review has no important findings. Broader SQL retained-history finding, combined recovery and infrastructure fencing remain open. Evidence: spec/audits/evidence/2026-10-12-postgres-owner-command-results.json.
- [x] Settle cancelled ownership acquisition during database authentication {#org-postgres-lease-cancel}
      by: codex
      from: agent
      tech: Real pg/TCP regression reproduced a connect promise left pending after intentional close. Connection and lock acquisition now race the lease failure notification and preserve late-activation refusal. Regression and focused tests pass; independent follow-up closes the finding. Evidence: /tmp/xeip-control-lease-connect-red.log and /tmp/xeip-control-lease-connect-green.log.
- [x] Keep schema maintenance on the connection that owns the database lock {#org-postgres-owner-session}
      by: codex
      from: agent
      tech: Dedicated runtime lease and same-session owner adapter exclude competing startup/maintenance without consuming a work-pool slot. Actual PostgreSQL verifies interrupted owner mutation rollback before replacement runtime ownership. Native300/Linux300, strict types, launcher/lease drills and rebuilt artifact pass; scoped review has no important findings and its fluent-handle issue is fixed. Evidence: spec/audits/evidence/2026-10-12-postgres-owner-session-results.json. Owner enrollment/change CLI and combined recovery remain pending.
- [x] Validate signed operations at a bounded HTTP boundary {#org-http}
      tech: services/organization/controller.mjs, services/organization/http.mjs, services/organization/http.test.mjs
- [x] Execute approved actions once through a bounded MCP connector {#org-mcp}
      tech: services/organization/mcp.mjs, services/organization/mcp.test.mjs
- [x] Ship a production launcher with TLS, Host/Origin allowlists and a least-privilege DB role {#org-launcher}
      by: codex
      from: agent
      tech: services/organization/main.mjs and runtime.mjs; review blockers fixed, real PostgreSQL 166/166 and Node 22/Linux 165/165 pass; deployment certification remains open
- [x] Restrict database credentials and reject privilege drift at startup {#org-db-role}
      by: codex
      tech: services/organization/database.mjs, conformance/organization-database.mjs; real PostgreSQL 18 lifecycle and denial tests pass
- [x] Validate protected configuration before exposing the organization service {#org-config}
      by: codex
      tech: services/organization/configuration.mjs; exact schema, secret permissions, verified TLS and policy matching
- [x] Drain accepted actions and expose redacted operational health and metrics {#org-operations}
      by: codex
      tech: services/organization/lifecycle.mjs, runtime.mjs, telemetry.mjs, management.mjs; runtime review blockers fixed; operational acceptance remains open
- [x] Package the organization service for a reserved Linux staging host {#org-artifact}
      by: codex
      from: agent
      tech: pinned Node 22 container, production dependencies, compiled SDK, checksums, SBOM and isolated smoke verification
- [x] Assess vulnerabilities in the actual Linux organization image {#org-artifact-vulnerabilities}
      by: codex
      from: agent
      tech: digest-pinned Grype and same validated database; baseline/intermediate/final offline scans complete, structured finding inventory retained; BusyBox and bundled OpenSSL remediation remain open
- [x] Patch the Linux image's vulnerable zlib package {#org-artifact-zlib}
      by: codex
      from: agent
      tech: Alpine CVE-2026-85091 fix in 1.3.2-r1; old image fails installed-package regression, rebuilt image passes isolated artifact checks, scoped review clear; broader vulnerability assessment separate
- [x] Patch shared TLS libraries and remove unused runtime package tools {#org-artifact-runtime-packages}
      by: codex
      from: agent
      tech: OpenSSL shared libraries 3.5.9-r0; runtime package managers removed; final isolated smoke passes, same-database scan falls from 51 matches (20 High) to 3 Medium, scoped review clear
- [ ] Resolve remaining runtime library and BusyBox security findings {#org-artifact-residual-security}
      from: roadmap
      tech: BusyBox CVE-2025-60876 request injection reproduced locally; Node statically bundles OpenSSL 3.5.8; vendor remediation/applicability review and fresh artifact assessment required, no risk acceptance inferred
- [x] Reject High-severity image findings and failed scans in CI {#org-artifact-scan-gate}
      by: codex
      from: agent
      tech: 6/6 policy tests and root384/384; native old-image rejection, current-image acceptance, fresh-cache lifecycle and sanitized report retention verified; CI wired with pinned uploader, hosted execution still open
- [x] Run one real Keycloak → PostgreSQL → MCP approval-policy action end to end {#org-e2e}
      by: codex
      tech: conformance/organization.mjs passed; original simulated human service account; separate real-provider browser fixture now passes, organizational acceptance remains open

- [x] Recover post-backup action history from archived PostgreSQL WAL {#org-postgres-archive-recovery}
  by: codex
  from: agent
  tech: Native pg_basebackup/pg_verifybackup plus actual archived-WAL restoration pass after source destruction:9 actions/23 audit events,8 post-base actions,4 consumed claims and0 repeated effects. Missing-segment recovery fails its required target; full candidate compares exact state while paused/read-only. Lost-create-response cleanup finding fixed and fault-tested with container/volume removal; coordinator3/3 and scoped re-review pass. CI wired, hosted execution unverified. Not independent storage, automatic zero-RPO or full organization recovery; spec/plans/postgres-archive-recovery.md.

- [x] Clean up the PostgreSQL primary fixture after an ambiguous create {#org-postgres-fixture-create-cleanup}
  by: codex
  from: agent
  tech: Actual daemon-side create followed by failed client response reproduced the leak; corrected primary ownership tracking/label verification removes its container and anonymous volume. Five process-level cases plus coordinator tests8/8, real ordinary PostgreSQL, archived-WAL restore and held-container WAL startup/cleanup pass; final organization216/216 and interoperability41/41 pass. Removal-failure review suggestion implemented; no remaining findings. spec/plans/postgres-fixture-cleanup.md.
      from: agent
- [x] Let people sign in and review exact actions before deciding {#org-console}
      by: codex
      from: roadmap
      tech: opt-in signed approval console; 199/199 Node 26 and Node 22/Linux tests, 17/17 browser tests, reviewed immutable artifact; synthetic real-provider browser follow-up passes; organizational rollout acceptance remains open
- [x] Verify real human login and browser approval through Keycloak {#org-console-keycloak}
      by: codex
      from: agent
      tech: synthetic real-provider browser workflow passes, including exact approval/single effect/replay/logout; 205 unit tests, types and rebuilt image pass; current controlled browser16/17 plus timed-out case1/1 isolated; spec/audits/2026-10-11-keycloak-browser.md
- [x] Keep approval orchestration independent of storage and connector implementations {#org-adapters}
      by: codex
      from: agent
      tech: shared errors and typed adapter contracts; 167/167 local and Node 22/Linux tests, rebuilt artifact smoke and final review pass; PostgreSQL semantics unchanged
- [x] Evaluate Cloudflare-native hosting without weakening approval or recovery guarantees {#org-cloudflare}
      by: codex
      from: agent
      tech: spec/audits/2026-10-11-cloudflare-feasibility.md and proposed ADR 0017; local workerd passes 28 signature vectors and sampled policy parity; backend adoption and production acceptance remain open
- [x] Prove Cloudflare ledger transitions and single-use claims locally {#org-cloudflare-ledger}
      by: codex
      from: agent
      tech: spec/cloudflare-ledger.md; 40/40 real workerd/SQLite tests on local Node 26 and Node 22/Linux, two review findings fixed, strict types and packaging checks pass; no deployed unsigned API or backend adoption
- [x] Persist verified trust and enforce real identity checks in the Cloudflare prototype {#org-cloudflare-authority}
      by: codex
      from: roadmap
      tech: signed trust, durable policy/bindings and real Keycloak compose with the signed controller; 98/98 workerd tests on macOS/Linux, real Keycloak lifecycle/revocation, strict types and packaging checks pass; two review findings corrected; public Worker ingress/private MCP remain open
- [x] Verify native signed requests and MCP effects with bounded transport {#org-cloudflare-transport}
      by: codex
      from: agent
      tech: 150/150 workerd tests and strict types on macOS/Linux; actual local OAuth MCP, revocation, deadlines, persistent claims and no replay; independent review found no issues; deployment lifecycle/private route remain open
- [x] Initialize organization state explicitly and refresh signed trust safely {#org-cloudflare-lifecycle}
      by: codex
      from: agent
      tech: explicit resumable setup, validated reopen, late health checks and signed refresh; 183/183 workerd tests and strict types on macOS/Linux; both Important review findings fixed; deployable private owner interface and hosted acceptance remain open
- [x] Package the Worker with private operator access and strict production configuration {#org-cloudflare-worker}
      by: codex
      from: agent
      tech: fixed organization object, named owner RPC, strict profiles and receipts, offline artifact/local operator path; 218/218 native tests and types on macOS and sequential Node 22/Linux; review finding fixed; hosted IAM/recovery acceptance stays open
- [x] Persist and privately export administrative changes and uncertain outcomes {#org-cloudflare-admin-audit}
      by: codex
      from: agent
      tech: schema v5 owner journal, private bounded export, durable attempt/result ordering and restart/fault checks; 246/246 native cases/types on macOS and Node 22/Linux; Important SQL replacement finding fixed; independent recovery/retention remain open
- [x] Refresh signed trust automatically without granting new identity authority {#org-cloudflare-refresh}
      by: codex
      from: agent
      tech: Pinned authenticated HTTPS feed, separate private Cron Worker, existing roster and monotonic signatures, audited changes;277 native cases/types pass on macOS/Linux.
- [x] Collect and verify complete administrative archives without deleting replay history {#org-cloudflare-archive}
      by: codex
      from: agent
      tech: Private fixed-head export, sealed local archives and prior witnesses;308/308 native cases/types pass on macOS/Linux, both Important review findings fixed; action recovery and retention remain open.
- [x] Reconcile stored actions with their complete transition history before recovery or use {#org-cloudflare-action-integrity}
      by: codex
      from: agent
      tech: Bounded startup/history validation and quarantine;323/323 native cases/types pass on macOS/Linux; both review findings fixed, recovery/export gates remain open.
- [x] Archive actions and consumed claims with verifiable recovery evidence {#org-cloudflare-action-archive}
      by: codex
      from: roadmap
      tech: Fixed-cut private action export, durable canonical archives and offline/prior-witness verification; 355/355 native cases/types pass on macOS/Linux, review defect fixed. Independent recovery and replay-safe retention remain open.
- [x] Store large signed trust bundles within Cloudflare row limits {#org-cloudflare-trust-chunks}
      by: codex
      from: agent
      tech: Schema 6 preserves the 8 MiB logical bound with bounded chunks, atomic replacement and legacy migration; 372/372 native cases/types pass on macOS/Linux. Both review evidence gaps resolved; recovery journaling remains open.
- [x] Persist an ordered recovery journal outside the action database {#org-cloudflare-recovery-journal}
      by: codex
      from: agent
      tech: Isolated immutable byte journal with durable receipts; 390/390 native cases/types pass on macOS/Linux, exact Worker packages and rebuilt Linux image smoke pass. Review clarification resolved. Configured source integration is complete below; complete restore and independent hosting remain open.
- [x] Require recovery receipts before acknowledging actions or releasing tool claims {#org-cloudflare-action-recovery}
      by: codex
      from: agent
      tech: Persisted binding, deterministic transition capture, startup reconciliation and receipt/effect gates; 413/413 native cases/types pass on macOS/Linux, exact Worker packages and Linux image smoke pass. Review concurrency defect fixed. Hosted recovery transport, full restore and acceptance remain open.
- [x] Authenticate recovery journal requests over a bounded HTTPS protocol {#org-cloudflare-recovery-transport}
      by: codex
      from: agent
      tech: Provider-neutral pinned client and authenticated handler; 447/447 Cloudflare tests and strict types pass on macOS/Linux. Review deadline and redaction findings fixed, including modeled deployed-clock behavior. Hosted wiring, independent recovery and acceptance remain open.
- [x] Configure authenticated recovery in the deployable Worker {#org-cloudflare-worker-recovery}
      by: codex
      from: agent
      tech: Immutable public endpoint/enrollment and separate credential;467/467 native cases/types pass on macOS/Linux, scoped review clear, exact recovery-enabled Worker flow and Wrangler dry-runs pass. Hosted journal, full restore and production acceptance remain open.
- [x] Collect and verify complete recovery-journal bundles offline {#org-cloudflare-recovery-archive}
      by: codex
      from: agent
      tech: Fixed-head complete journal export, durable private files and offline action/claim continuity.500 distinct checks verified on macOS/Linux (Linux498 full +2 closing), strict types/artifacts pass; scoped review clear. Full source restore and hosted acceptance remain open.
- [x] Prepare a private Cloudflare smoke candidate for review {#org-cloudflare-staging-candidate}
      by: codex
      from: agent
      tech: Exact account-pinned artifact, isolated resource names, no public routes or organization activation, bounded status-only checks; deployment requires separate approval.
- [x] Run the approved private Cloudflare status smoke {#org-cloudflare-staging-smoke}
      by: codex
      from: agent
      tech: Approved xeip-staging-20261011 deployed privately; one synthetic secret, one of five permitted status calls returned uninitialized/trust null/authority null. Final version4f93b791-03ca-4652-9df9-3a446eb9e62d; no production acceptance implied.
- [x] Rebuild action state into a durably fenced restore candidate {#org-cloudflare-action-restore}
  by: codex
  from: agent
  tech: Schema8 fence and exact resumable reconstruction verified; current macOS527/527 and Node22/Linux527/527 plus strict types, package checks and scoped review complete. Candidate cannot activate; full control-plane recovery and hosted acceptance remain open.
- [x] Preserve signed trust and removed-entity checkpoints for recovery {#org-cloudflare-trust-checkpoint}
  by: codex
  from: agent
  tech: Historical checkpoint validator and coherent capture preserve signatures, original acceptance time and retained rollback records. Cloudflare535/535 and root384/384 pass locally; affected trust48/48 and strict types pass on pinned Node22/Linux; scoped review clear. No activation or independent durability claim.
- [x] Preserve authority configuration and complete revision history for recovery {#org-cloudflare-authority-checkpoint}
  by: codex
  from: agent
  tech: Fixed current configuration checkpoint and complete bounded history pages; Cloudflare543/543 and root384/384 pass locally, affected authority42/42 on pinned Node22/Linux, strict types on both platforms and scoped review pass. No live activation or independent durability claim.
- [x] Preserve lifecycle intent and pinned public configuration for recovery {#org-cloudflare-lifecycle-checkpoint}
  by: codex
  from: agent
  tech: Secret-free initializing/initialized checkpoints, synchronized capture/recheck, exact target/identity/recovery validation and foreign-scope preflight. Cloudflare556/556 and root384/384 pass locally; affected lifecycle/authority102/102 on pinned Node22/Linux, strict types on both platforms and scoped review pass. Administrative capture, coordinated restoration and hosted acceptance remain open.
- [x] Preserve complete administrative history for recovery {#org-cloudflare-admin-checkpoint}
  by: codex
  from: agent
  tech: Scoped fixed-head capture and complete bounded history validation, cross-page attempt/result matching and unresolved attempts. Cloudflare569/569 and root384/384 pass locally; affected admin/archive/lifecycle/owner/package134/134 on pinned Node22/Linux, strict types on both platforms and scoped review pass. Coordinated receipt gating and restoration remain open.
- [x] Capture one consistent organization recovery cut {#org-cloudflare-organization-checkpoint}
  by: codex
  from: agent
  tech: Lifecycle/trust/authority/admin evidence and a fixed action cut are bound under the control guard with synchronization/recheck and bounded internal pages. Missing-cut corruption quarantines before effects; healthy invalid cuts still conflict. Cloudflare580/580 and root384/384 pass locally; affected ledger/lifecycle/action-recovery/transport/Worker/package234/234 pass on pinned Node22/Linux, with strict types on both platforms and scoped review cleared. The bundle task below supplies complete collection; independent receipts and full reconstruction remain required.
- [x] Collect and verify complete organization recovery bundles {#org-cloudflare-organization-bundle}
  by: codex
  from: agent
  tech: Complete fixed-cut action/control histories, protected synchronized files, exact offline inventory and optional independent digest pin; native capture preserves a consumed claim as the live action completes. Focused25/25 and full Cloudflare605/605 pass locally; affected bundle/lifecycle/admin-archive/action-archive/recovery-archive181/181 pass on pinned Node22/Linux; strict types on both platforms and scoped review pass. Operator transport, independent receipts, full fenced restore and activation remain required.
- [x] Reconstruct a complete organization bundle in a fenced database {#org-cloudflare-organization-restore}
  by: codex
  from: agent
  tech: Lifecycle, historical trust/rollback records, authority/admin histories and original action sequences/claims reconstruct with synchronized resumable progress and permanent runtime refusal. Native635/635, root384/384, strict Cloudflare types and scoped review pass. Full pinned Node22/Linux finished634/635 with one expiry-fixture timing failure; the corrected complete ledger file passes59/59 on both platforms, and Linux strict types pass. Frozen snapshot and failure/correction evidence are preserved. No activation or hosted recovery claim.
- [~] Fence restored databases against replay and lost acknowledged actions {#org-cloudflare-recovery}
  by: codex
  from: roadmap
  tech: Independent recovery journal/witness and reconciliation matched to the accepted failure boundary; operator restore drill ≤1 hour.
- [~] Export complete recovery bundles through the private owner interface {#org-cloudflare-organization-export}
  by: codex
  from: agent
  tech: Scoped readers, operator-bound export sessions, exact private RPC receipts and the Node collect/verify CLI are implemented. Prior internal regression207/207, boundary114/114 and root384/384 pass; new wire5/5, native RPC/collector2/2, cleanup/owner22/22 and strict types pass. Scoped reviews found and closed a cleanup-result defect. Prior root384/384 and full native Cloudflare691/691 pass; the newer serialization change passes55/55 focused cases,183/183 affected cases,384/384 root cases, types and review; pinned Node22/Linux boundary verification117/117 and types pass on the frozen serialization source. Local100000-record admin diagnostic is33.96s pages plus14.89s setup, excluding capture/network/files. The serialization-only100000-record run read300017 admin rows at begin and failed its30s expiry in56.88s elapsed/11.96CPU-seconds. Confirmed-capture readers now reduce that to200000 rows; the latest local run succeeds in12.95s elapsed/6.76CPU-seconds, without a deadline change. Alternating serialization-only10000-record runs show24.6% less process CPU. Actual private-RPC capture probes pass at all three sizes; complete private collection/verification pass at1000/10000 records but the100000 attempt hits the30s capture deadline before any bundle file. Maximum full-bundle completion, combined component memory and hosted acceptance remain. No deployment or activation.
- [x] Reuse validated audit encodings without changing stored records {#org-cloudflare-audit-encoding}
  by: codex
  tech: Byte-format and corruption guards pass55/55, affected native cases183/183, root384/384 and frozen pinned Linux boundary cases117/117, strict types and scoped review. Alternating local10000-record probes show24.6% lower process CPU; maximum-source export still fails its deadline, so this is not capacity acceptance.
- [x] Capture verified export readers without a third history scan {#org-cloudflare-confirmed-readers}
  by: codex
  from: agent
  tech: Store-owned checkpoint-and-reader factories in the confirmed synchronized pass; preserve exact manifest comparison, corruption checks, fixed cuts and reader cleanup. Focused6/6 and types pass; review has no remaining Critical/Important findings. First broader203/204 had one test fault-injection defect, corrected3/3. Local100000-record begin succeeds in12.95s with200000 admin row reads; Expanded native Worker verification found an admission regression (228/229); the correction preserves pre-init state while retaining reader cleanup and integrity quarantine. The correction passes6/6 focused cases, current affected native230/230, root384/384, strict types and re-review. Corrected-source pinned Node22/Linux verification passes230/230 and types, alongside native230/230, root384/384 and re-review. Workerd scale measurements are recorded in the completed task below; complete bundle and combined resource acceptance remain open.
- [x] Measure large export captures in local workerd {#org-cloudflare-workerd-export-cost}
  by: codex
  from: agent
  tech: Production-constructor/private-RPC probes complete1000/10000/100000 records, validating component, final page, unchanged head and close with eviction enabled and no outbound Worker calls. At100000, cold status5.90s and begin11.81s; this is local measurement only. Earlier manual-open fixture eviction failures are preserved. Full bundle/combined memory and hosted CPU/workload acceptance remain.
- [x] Measure complete private bundle collection at the administrative history cap {#org-cloudflare-full-bundle-cost}
  by: codex
  from: agent
  tech: Production collector/private RPC plus offline verification pass at1000/10000 records (69/631 files). The100000-record attempt fails awaiting begin at30.02s, before any bundle file; cold status29.79s. All outcomes retained in the performance audit. Default sample and11/11 collector regressions pass; scoped review has no findings. This closes measurement only; maximum full transfer, combined memory and hosted acceptance remain open. No cloud calls or deadline/eviction changes.
- [~] Measure Worker memory during large combined recovery capture {#org-cloudflare-export-memory}
  by: codex
  from: agent
  tech: Calibrated loopback-only isolate inspection. Small and large empty-provisioning controls pass; large uses95.84MB JS heap after capture/114.26MB uncollected after close, plus11.90MB backing. Valid16.72MB signed checkpoint opens but export begin returns unavailable after49.32s. Capture CPU profiling completed: serialization/Unicode checks account for50.86% of samples, snapshot traversal9.55% and GC8.81%; post-failure used heap225.36MB; complete combined resource/peak/hosted acceptance remain open. Reviewed temporary stage trace later completes small and signed-large controls, all checks and zero outbound; large begin12.94s on one instance, first/second checkpoint reads6.36s/6.08s, no reproduced rejection. Used heap247.68MB after cold open versus38.85MB after capture is not peak/live/hosted evidence. No production limits changed.
- [x] Release the first checkpoint before validating its synchronized copy {#org-cloudflare-capture-lifetime}
  by: codex
  from: agent
  tech: Source capture retains the complete first checkpoint across sync, although only its manifest action cut and digest are used afterward. Synthetic Node WeakRef/GC probe confirms baseline retains both objects and fails the release assertion; keeping only the immutable manifest makes both collectible and passes. Strict types and scoped review pass; affected native lifecycle/export/bundle/restore/Worker173/173 passes in206.01s, no skips/cancellations. Frozen-source Linux173/173 and types pass in200.27s; the sequential unprofiled signed-large transfer also completes all component/head/close checks on one instance, zero outbound. Source hashes remain unchanged. Reachability improvement is verified; peak/hosted limits remain open. Preserve both complete reads, synchronization, exact digest comparison, quarantine and readers. This is object reachability evidence, not a peak/hosted memory claim.
- [x] Reuse immutable validated trust checkpoints during export {#org-cloudflare-trust-capture-reuse}
  by: codex
  from: agent
  tech: Immutable validator-owned provenance and canonical encoding reuse implemented; historical10/10, export/bundle39/39 and strict types pass. Scoped review clears code and diagnostic attribution. One signed-large transfer completes, but the profiled repeat fails during source capture before downstream reuse; no memory or speedup claim. Full native Cloudflare718/718 and root384/384 pass on unchanged source; strict types pass; frozen-source pinned Node22/Linux passes223/223 affected cases and strict types, exit0. Archive d90db4b495cf6fb67d068abab9ebffff85b46fd02ebf1adb0bd1d2e6b0083d92 excludes the subsequent source-read split.
- [x] Identify allocations driving large export memory use {#org-cloudflare-export-allocation-profile}
  by: codex
  from: agent
  tech: Extend the existing loopback-only local diagnostic with optional allocation sampling for export begin. Preserve small/default/CPU modes, source capture checks, protected artifacts and primary failure evidence. Collected-object samples diagnose allocation churn; they are not live/peak memory or hosted acceptance. Small/large/default/CPU diagnostic runs pass; scoped review clears implementation. Raw profiles contain small sample/tree discrepancies, preserved explicitly. Large call tree attributes33.20% of self-allocation estimates to reference strict string parsing; source confirms per-character appends absent from the already optimized SDK. No production code or limits change.
- [x] Validate signed trust once per persisted capture read {#org-cloudflare-trust-source-validation}
  by: codex
  from: agent
  tech: The new profile localizes duplicated signature preparation in DurableEntityTrust.checkpoint: #read validates provisioning and validateTrustCheckpoint repeats it. Split persisted row/chunk/record integrity reads from live bundle preparation; historical capture still runs the complete historical validator once per read, with unchanged pre/post-sync reads, canonical bytes, accepted checksum and quarantine. Split implemented with explicit canonical provisioning equality retained. Four small Node/SQLite preservation probes pass before/after; review finds no blocking issue and distinguishes capture drift rejection from reopen canonicality rejection. Native historical13/13, affected226/226, root384/384 and strict types pass on unchanged fingerprints. Both signed-large local runs complete with all component checks and one instance (begin12.69s unprofiled/11.32s profiled); profile supports removal of duplicated preparation. Used-heap samples vary substantially, so no hosted fit or causal speedup claim. Frozen current-source pinned Node22/Linux passes226/226 affected cases and strict types, exit0; source-read validation increment complete locally.
- [x] Measure the complete service export capture cost {#org-cloudflare-export-cost-baseline}
  by: codex
  tech: Reproducible network-refusing Node SQLite diagnostic at1000/10000/100000 admin records; source-open/checkpoint/begin timings, SQL result-row counts, memory and CPU profile are recorded in spec/audits/2026-10-12-organization-export-performance.md. The100000-record run fails its existing deadline; this closes measurement only, not scale readiness.
- [ ] Retain bounded searchable history without forgetting consumed actions {#org-cloudflare-retention}
      from: roadmap
      tech: Accepted retention policy, verified archival and replay-preserving tombstones before any deletion; sustain120 actions/minute beyond the10000-action cap and preserve administrative integrity/unresolved attempts beyond its100000-record cap.
- [~] Serve signed actions through bounded Worker ingress and private MCP transport {#org-cloudflare-service}
  by: codex
  from: roadmap
  tech: build a deployable experimental Worker/object composition, preserve private owner administration, and test transport/authentication/failure limits before hosted acceptance
- [~] Measure and meet the 500-user / 200-agent / 120-action-per-minute workload {#org-load}
  by: codex
  from: roadmap

## Prove implementations agree {#conformance}

tech: cross-language fixture validation plus Rust/TypeScript/relay, Keycloak and PostgreSQL harnesses
files: [conformance/**]
needs: [spec, models]
links: [identity, relay, sdk, organization]

- [x] Ship public wire fixtures for entity, session, capability and message {#conf-fixtures}
      tech: conformance/fixtures/entity.valid.json, conformance/fixtures/session.valid.json, conformance/fixtures/capability.valid.json, conformance/fixtures/message.valid.json
- [x] Exchange the message fixture between the TypeScript SDK and a Rust example {#conf-interop}
      tech: conformance/http-sse.test.mjs, crates/xeip-core/examples/local_relay_peer.rs
- [x] Validate every wire fixture against JSON Schema with format checks {#conf-schema}
      tech: tools/validate-fixtures.mjs
- [x] Exercise the Keycloak adapter against a real pinned provider {#conf-keycloak}
      tech: conformance/keycloak.mjs
- [x] Exercise the PostgreSQL ledger with kill/restart and backup/restore {#conf-postgres}
      tech: conformance/postgres.mjs, services/organization/migrations/001-actions.sql
- [x] Clean up every owned test fixture when a run is interrupted {#conf-owned-cleanup}
      by: codex
      tech: shared SIGINT/SIGTERM coordinator for nested provider/database/browser fixtures; 3 subprocess/listener regressions pass and detect premature-exit mutation
- [x] Detect damaged PostgreSQL pages and recover acknowledged action history {#conf-postgres-corruption}
      by: codex
      from: agent
      tech: Check checksum protection and bypass settings, damage a selected disposable action page offline, reject reads/claims, and restore a fixed acknowledged cut into a new database without replay.
- [x] Recover acknowledged actions after PostgreSQL WAL storage fills {#conf-postgres-wal-full}
      by: codex
      from: agent
      tech: Bounded isolated WAL filesystem, real write failure/server exit, no connector after failed claim, capacity restoration and exact acknowledged-state comparison; not a durable storage deployment.
- [x] Refuse action acceptance when real PostgreSQL data storage is full {#conf-postgres-disk-full}
      by: codex
      from: agent
      tech: Disposable bounded tablespace ENOSPC drill; preserve acknowledged actions/audit and single-use claims; restore space and verify safe retry. WAL exhaustion and deployment disaster certification remain distinct.
- [x] Prove acknowledged ledger state survives synchronous PostgreSQL failover {#conf-postgres-replication}
      by: codex
      from: agent
      tech: Isolated primary/standby drill, lost-replica acknowledgement refusal, consumed-claim preservation and no replay; no hosted durability certification.
- [ ] Add an independently authored third-party client {#conf-external}
      from: roadmap
- [x] Give the complete recovery conformance suite enough CI job time {#conf-cloudflare-ci-budget}
      by: codex
      from: agent
      tech: current 527-case Linux job exceeded ten minutes without failures; increase only workflow wall-clock budget to 25 minutes, preserving all runtime and test deadlines
- [x] Gate per-file coverage of the trust crypto modules and repair the supply-chain gate {#conf-coverage-gate}
      by: coordinator
      from: agent
      tech: new tools/check-coverage.mjs enforces a per-file floor on 14 trust/crypto modules and fails closed on failing/cancelled/non-numeric reports; wired as npm run coverage:files and a CI step. deny.toml drops the deprecated version=2 keys that broke the pinned cargo-deny action so the supply-chain job (npm audit) can run.

## Show it working {#demos}

tech: dependency-free loopback demo scripts and a browser console that exercise every local profile
files: [examples/local-relay/**]
needs: [relay, sdk]

- [x] Run a human → agent → machine message exchange {#dem-demo}
      tech: examples/local-relay/demo.mjs
- [x] Demonstrate admission, replay, delivery, receipts, durable and limits {#dem-profiles}
      tech: examples/local-relay/admission-demo.mjs, examples/local-relay/delivery-demo.mjs, examples/local-relay/receipts-demo.mjs, examples/local-relay/durable-demo.mjs, examples/local-relay/limits-demo.mjs
- [x] Demonstrate signed envelopes and key documents {#dem-identity}
      tech: examples/local-relay/signed-demo.mjs, examples/local-relay/keydoc-demo.mjs
- [x] Provide a browser console for interactive use {#dem-console}
      tech: examples/local-relay/console.html, examples/local-relay/console.js, examples/local-relay/console.css

## decisions

- 2026-10-14 — Enforce key-document genesis self-certification to match spec/identity-keys.md §5.1. A genesis document (generation1, no previous) must list its own genesis key in roots and be signed by it; a genesis signed only by a non-genesis root is refused with the new stable reason "genesis not self-signed" in JS, Rust and TS alike. Successor documents keep the generic root rule and the chain retiry rule unchanged. Pinning genesisDigest remains recommended defence-in-depth but optional.

- 2026-10-14 — Add a per-file coverage gate for the trust/crypto modules (tools/check-coverage.mjs, npm run coverage:files, CI step) and repair the supply-chain gate by removing the deprecated version=2 keys from deny.toml that broke the pinned cargo-deny action. Thresholds sit just below observed values; the cloudflare surface and TypeScript SDK remain ungated and are recorded as follow-ups.

- 2026-10-14 — Correct the P2 retained-history integrity gap with a forward migration004 that replaces protect_control_event without rewriting applied migration bytes. An entity absent from the accepted key documents may only preserve its exact prior record and cannot be invented; every active record's generation/serial must equal its accepted signed key/status document. Add a bounded two-event transition check to the control worker so inactive records are verified against the predecessor, not only prepared.checkpoints. SQL guards remain structural, not cryptographic: signatures stay in the shared identity worker, and full ordered history verification, laundering behind an injected unsigned provisioning document plus an intervening post-removal event, combined physical control/action recovery and external old-writer fencing remain open.

- 2026-10-12 — Persist control snapshots in migration003 as append-only events plus a singleton head. Database triggers serialize publication, enforce predecessor/head continuity and advance the head atomically after event insertion. Runtime may insert trust events only; owner-only enrollment must observe empty action/audit tables under a conflicting table lock. All transitions retain high-water entries and target revision mappings, with immutable organization identity. The storage library shares the existing action synchronous-COMMIT/WAL-marker behavior; no normal startup migration or enrollment is introduced. Runtime wiring/fencing remains subsequent work.

- 2026-10-12 — Implement the control-state foundation as pure validated canonical snapshots. Non-enrollment transitions consume one complete previous canonical snapshot rather than independently supplied records/active sets/target maps; trust-only transitions must preserve its authority digest. Enrollment explicitly receives retained trust records. Historical snapshot verification proves internal signatures/shape only; SQL event-chain and independently retained head checks remain mandatory in subsequent layers. Reuse existing per-section bounded snapshot/cryptographic validators and return frozen JSON, never mutable Map/Set authorization objects.

- 2026-10-12 — Extend Linux recovery work to authorization state before treating database restore as service recovery. First reproduce a stale filesystem trust restore against an unchanged current action ledger using synthetic signed identities and an in-memory effect counter. Use that evidence to specify durable control history and stale-runtime refusal; do not change hosting, deployment, retention or external activation policy through this local investigation.

- 2026-10-12 — Reproduce and fix the common PostgreSQL fixture's ambiguous-create cleanup gap. Register the generated primary before requesting creation, label it uniquely, and verify ownership before removal or explicit primary destruction. Treat only the exact missing-object response as absent; preserve failure evidence on foreign ownership or unavailable inspection. Add process-level regression cases and an actual-Docker lost-response check, then verify ordinary and archive-recovery fixture paths. No application, schema, credential policy or operator resource changes.

- 2026-10-12 — Add a PostgreSQL physical archive-recovery conformance drill to close the gap between logical-backup and synchronous-replication checks. Capture a verified base backup, acknowledge later action transitions, archive through an explicit restore point and copy recovery inputs off the source before destroying only its disposable container. Require an incomplete archive to fail before reaching the target; restore the full archive paused for exact row/audit comparison, then test consumed-claim suppression. This is an explicitly archived fixed cut, not zero-RPO on asynchronous archiving, independent failure domains, whole-organization trust/configuration restoration or a production activation procedure. No operator credentials or endpoints, schema/application change or cloud deployment.

- 2026-10-12 — Extend strict JavaScript semantic analysis to the Node key-ID and legacy signed-envelope foundation as a bounded A5 increment. Add JSDoc input/result types and a dedicated strict/noUncheckedIndexedAccess gate using the existing compiler; retain runtime guards and exact executable AST. Use unknown at untrusted boundaries, no explicit any or diagnostic suppressions. Local, justified type assertions may describe existing bounds/Node API invariants. Verify compiler rejection of deliberate type faults plus existing runtime vectors and consumers. Remaining identity modules require separate checking; do not label the whole runtime type-safe.

- 2026-10-11 — Collect a complete initialized organization bundle from the coordinated checkpoint and bounded page reader. Reuse action and control history verifiers; preserve independent component byte/node budgets, fixed section cursors, exact file inventory and a final synchronized seal. Offline verification requires expected organization and optionally an independently retained checkpoint digest. This is a complete point-in-time content artifact, not a receipt for later acknowledgements, a continuous-history witness or activation authority. Keep live schemas, action-journal sequencing and cloud deployment unchanged; full source reconciliation, independent durable receipt gating and fenced restoration remain the required next integration.

- 2026-10-11 — Coordinate initialized organization capture under the existing control-operation guard. Capture control checkpoints and an action snapshot synchronously before storage sync; afterward recheck exact control state and the same historical action cut. Later actions may proceed and finish, because immutable audit projection preserves the captured cut; an active recovery transition may cause a retryable conflict. Bind every component in a small versioned manifest, including the complete trust artifact's organization, and validate cross-component configuration. Keep body records separate from bounded history pages. Do not mix control events into the existing action journal whose sequence equals the action audit sequence. This is source capture, not an independent receipt, restore activation or completed zero-loss recovery. Interrupted setup retains its separate lifecycle evidence and remains outside this initialized snapshot API.

- 2026-10-11 — Add fixed-head administrative checkpoints and bounded pages to the existing owner journal as the remaining control-capture dependency. Reuse unchanged audit record rules through a shared codec; verify genesis-to-head continuity, global time ordering, unique attempts and exactly one matching result per resolved attempt. Preserve unresolved attempts without executing them. Capture refuses active operations/pending synchronization and scope drift; stale checkpoints conflict without quarantining healthy current state. No schema, public RPC, deployment, retention or source action-journal format change. Existing local hardening authorization applies; independent journal receipts and coordinated restore remain separate required work.

- 2026-10-11 — Add historical lifecycle capture preserving both interrupted initialization and completed intent. Synchronize and recheck under the service's control-operation admission guard; include original runtime/initial-authority bytes, source checksum and a digest binding phase and organization. Share public authority validation with the existing authority checkpoint and validate public runtime without real credentials or network calls. Check injected recovery organization scope before bootstrap writes. No schema, private-owner protocol, deployed Worker, action-journal sequence or activation change is authorized by this local increment.

- 2026-10-11 — Preserve authority state through a current public-configuration checkpoint plus bounded revision-history pages. Authority event history has no small fixed count cap, so do not materialize it into one journal entry or silently truncate it. Pin pages to a digest of the organization, current configuration and head; verify contiguous events from genesis to that head. Concurrent changes require a fresh capture. Historical events contain configuration digests, not old command bodies; preserve their exact existing meaning. This local dependency does not change the action-only journal, source acknowledgements, lifecycle state, schema or deployed Worker.

- 2026-10-11 — Add a bounded trust checkpoint as the first complete-control-recovery dependency. Preserve resolved signed provisioning and every retained entity checkpoint, validate at the original acceptance time, and bind the artifact to the expected organization. Capture synchronously only from ready, internally consistent durable trust. Do not append control records to the action-only journal: its sequence currently equals the action audit sequence. Authority/lifecycle/owner capture, a coordinated source journal, acknowledgement gating and fenced restoration remain required; no schema migration, public route, cloud deployment or secret export is part of this change.

- 2026-10-11 — The current sequential Linux Cloudflare conformance job exceeds its historical ten-minute CI budget while still progressing without failures (over fourteen minutes including dependency setup on this shared host). Set that job's wall-clock limit to 25 minutes, matching other integration jobs. This accommodates the expanded 527-case suite; it does not change any runtime deadline, per-test limit or production latency target, and it is not hosted timing certification.

- 2026-10-11 — Automate the reviewed Linux image scan in the existing artifact CI job. Preserve the offline scanner boundary and separate public database preparation; require a valid report and database in addition to the scanner exit status. High/Critical matches fail the job without exclusions. Retain JSON/logs and image/archive identity on failed runs; do not upload image archives, credentials or advisory caches. This is a regression gate, not acceptance of remaining Medium findings or bundled-library risks. No hosted workflow dispatch or deployment is authorized by this repository change.

- 2026-10-11 — Pin the new evidence uploader to the current official actions/upload-artifact v7.0.2 commit (Node 24 action runtime). Its maintained inputs support the required multi-file archive, failure-on-missing evidence and 14-day retention on the existing GitHub-hosted Ubuntu job. This does not change XEIP's Node 22 application runtime; hosted execution remains unverified.

- 2026-10-11 — The completed image scan reports 51 package/advisory matches (20 High), including the confirmed zlib fix, unused global npm dependencies and Alpine OpenSSL shared libraries. Pin libcrypto3/libssl3 to the vendor's 3.5.9-r0 release and remove global npm, Yarn and Corepack from the runtime stage only. Preserve application dependencies and build tooling. Node 22.23.3 bundles OpenSSL 3.5.8 independently; the latest Node 24 LTS does too. Do not claim the system-library update fixes the bundled copy or switch to the non-LTS Node 26 solely to silence a scan. Preserve those release/applicability questions explicitly.

- 2026-10-11 — The actual image contains zlib 1.3.2-r0; Alpine's 3.24 security database and packaging source identify 1.3.2-r1 as fixing CVE-2026-85091. The current Node 22 Alpine tag still resolves to the existing base digest. Apply only the signed Alpine zlib package revision with an exact version constraint in a shared base stage, then reuse it for build/assembly/runtime. Do not implement a custom C patch, change Node major versions or claim application exploitability from package presence alone. Verify the installed package in the real image and retain the pre-fix scan.

- 2026-10-11 — Assess the actual Linux image with a pinned Grype scanner and a dated public vulnerability database. Download scanner/advisories without source mounts, then scan an exported image offline without Docker socket access. Preserve scanner signals and verify material findings against upstream advisories; do not treat an empty report as security certification or change hosting/deployment scope.

- 2026-10-11 — Exercise physical PostgreSQL action-page corruption offline in a disposable held container. Require data checksums and disabled checksum/page-damage bypasses at readiness and runtime grants if the real configuration regression confirms these protections are currently unchecked. Do not enable checksums automatically on operator data. Restore the fixture’s fixed logical backup into a separate database and compare exact acknowledged rows/audit/consumed claims; no new acknowledgements are allowed after the backup cut. This is a detection/restore case, not whole-organization or arbitrary disaster certification.

- 2026-10-11 — Extend the disposable PostgreSQL harness with an opt-in bounded WAL filesystem and a holding shell so a database crash does not discard that filesystem. Force actual WAL growth at a claim’s commit boundary, require real WAL ENOSPC and server termination, then remove only the fixture filler and restart PostgreSQL against the unchanged files. No WAL deletion, reset, host disk fill or live configuration change. Keep the ordinary fixture path unchanged and verify it afterward.

- 2026-10-11 — Verify actual PostgreSQL data/tablespace exhaustion using only a disposable fixture's bounded shared-memory filesystem. Exercise the real ledger and audit transactions, preserve acknowledged rows and consumed claims, and restore space before checking a failed request by its original ID. No host disk fill, privileged container, production storage configuration, retention deletion or cloud mutation. This is one G3 failure case, not full WAL/disk-corruption or disaster certification.

- 2026-10-11 — A real PostgreSQL synchronous-commit cancellation reproduced a false successful action acknowledgement. Require warning visibility, reject any COMMIT notice as ambiguous, and emit an empty transactional WAL marker before the final authorization check so read-only/idempotent results also wait for configured synchronous durability. No schema migration or privileged-role membership is needed; explicitly grant and verify EXECUTE on the exact built-in marker function for the restricted runtime role. Standalone databases still do not gain independent durability.

- 2026-10-11 — Add a disposable PostgreSQL synchronous-replication/failover drill for the existing Linux option. Exercise real ActionStore commits and consumed claims; explicitly fence the old primary before promotion and retain a required replacement standby on the promoted server. This is functional failure evidence, not a hosting choice, complete organization restore or independent failure-domain acceptance.

- 2026-10-11 — Address measured synchronous Node trust-refresh CPU cost with a single bounded preparation worker per policy. Preserve the synchronous compatibility API; the organization launcher uses an awaited asynchronous reload. Only the owning thread commits rollback checkpoints and swaps active trust; expired, aborted, failed or post-close results never activate. No provider caching, deadline relaxation, hosting adoption or cloud deployment.

- 2026-10-11 — Resolve audit A5 runtime/CLI coupling by mechanically extracting Node identity implementations into packages/identity. Keep existing tools entrypoints and named exports as compatibility wrappers; preserve algorithms, signing bytes and rejection reasons. Production imports and image use only runtime modules. No hosting, protocol or deployment change.

- 2026-10-11 — Add an object-local append-only administrative journal before acknowledging owner changes. Binding labels identify privileged capabilities, not authenticated humans. Persist attempts before mutation and outcomes before acknowledgment; interrupted attempts remain unresolved, never replayed. Bounded private export carries no commands, credentials or provider data. This is local auditability, not an independent recovery journal or production adoption.

- 2026-10-11 — Verify reusable Workers request/MCP transport boundaries before composing the deployable organization object. Preserve exact signed commands, pinned OAuth destinations, live pre-send checks and durable single-use claims. Ordinary requests must never bootstrap missing trust or authority; explicit owner initialization and signed trust refresh remain required service work.

- 2026-10-11 — Compose the experimental object-local authority from persistent signed trust, the existing Keycloak verifier and a checked durable policy/binding snapshot. Keep credentials outside SQLite, gate updates until synchronization, reject stale requests across awaits, and verify actual provider behavior before claiming Keycloak/workerd integration. No public ingress or deployment is added by this batch.
- 2026-10-11 — Share signed trust preparation/checkpoint rules and add explicitly initialized, versioned SQLite trust persistence. Activate updates only after durability; retain removed-entity history and reject rollback/forks. This remains a local Cloudflare exploration; real Keycloak/policy/ingress composition and hosted recovery are still required.

- 2026-10-11 — Prototype the Cloudflare action ledger locally as a separate adapter. Preserve atomic action/audit transitions and single-use claims; reject stale authority across awaits and ambiguous durability. Keep Linux/Keycloak behavior intact and defer production adoption until verified trust, hosted recovery, retention and workload acceptance pass.

- 2026-10-11 — Build the human approval console for the existing signed organization API while hosting exploration remains undecided. Keep Keycloak, require operator-endorsed browser device keys, bind decisions to the exact reviewed digest, and preserve live authorization and ambiguous-outcome handling. Serve optional same-origin assets with a restrictive CSP; no root signing key or confidential client secret enters the browser.

- 2026-10-11 — Separate shared approval errors and adapter types from PostgreSQL migrations and the MCP client. Keep legacy exports and current authorization/commit/effect ordering. This improves the existing implementation and enables isolated native feasibility work; it does not adopt Cloudflare as the production backend.

- 2026-10-11 — No dedicated staging host exists. The user selected exploration of a Cloudflare-native redesign. Evaluate Workers/Durable Objects and identity/private-tool dependencies before changing the supported backend; preserve the existing Linux artifact and all workload/recovery targets. Exploration does not approve purchases, deployment or a replacement of self-hosted Keycloak.

- 2026-10-11 — The user selected a dedicated Linux staging host with reserved resources for final capacity/recovery acceptance. Prepare a local, unpublished Node 22/Linux container artifact and installation/acceptance procedure; do not certify the contended workstation or publish an unreviewed release.

- 2026-10-11 — The first completed capacity run failed. Instrument fixture stages and event-loop delay before changing service behavior; preserve live authorization checks, the population/rate and P95 target. Synchronous 700-identity refresh measured 5.8 seconds locally and needs further isolation.

- 2026-10-11 — Runtime final review found two Important blockers: privileged built-in database function grants and fatal listener supervision. Fix both with regressions before closing the launcher task. Capacity attempt four failed; preserve its results and diagnose before claiming rollout support.

- 2026-10-11 — Runtime database verification requires PostgreSQL 18, a dedicated database and a direct login without memberships. Owner provisioning removes PUBLIC create/temp/application privileges; startup only inspects. This avoids hidden SET ROLE escalation and keeps migrations separate from runtime credentials.

- 2026-10-11 — Runtime work follows spec/plans/organization-runtime.md: direct TLS, separate owner migrations and restricted runtime credentials, drain/restart for policy changes, verified atomic trust reload. Capacity target is P95 ≤2 seconds excluding human review; restore ≤1 hour with no acknowledged-action loss. Real fixture integration has passed; capacity measurement is in progress, and production infrastructure acceptance remains open.

- 2026-10-11 — Backfilled this plan from the code, not the docs. Read order: directory layout and source first, `git log`, in-flight plans/handoffs, README/roadmap last. Every `[x]` cites the implementing file it was checked against.
- 2026-10-11 — Evidence runs on this checkout: `npm test` = 365 relay/tools passing, `npm run test:ts` = 240 passing, `npm run test:organization` = 113 passing, `npm run build:ts` clean. Rust/Keycloak/PostgreSQL suites were not run here (need `cargo`/Docker) and are trusted from their cited test sources, so their tasks are checked on source evidence, not on this run.
- 2026-10-11 — Eight components chosen because each is a part one agent could own in a session with its own doneness and edges: spec, models, identity, relay, sdk, organization, conformance, demos. Rust core and identity are split because they have distinct owners, files and failure modes.
- 2026-10-11 — Doc drift found and corrected by code: `spec/plans/organization-service.md` and `services/organization/README.md` still say HTTP/MCP execution is unimplemented, but `services/organization/{controller,http,mcp,execution}.mjs` exist with 29 passing tests (`http.test.mjs`, `mcp.test.mjs`, `execution.test.mjs`, `controller.test.mjs`). The org tasks are checked against code. The plan's remaining unchecked items (production launcher, real end-to-end) are carried as `from: agent` tasks.
- 2026-10-11 — Production readiness (G0–G7 in PRODUCTION_READINESS.md) is a program, not a durable system part, so it is expressed as `[ ]` tasks on the components it touches (relay, identity, organization, sdk) rather than as its own card.
- 2026-10-11 — Groups are unchanged; `spec/**` owns all spec text including ADRs and in-flight plans. `conformance/**` owns the shared fixtures and cross-implementation runners; the code they exercise is owned by its own component.
- 2026-10-11 — Statuses left `[ ]` because no implementing artifact was found: scoped grants/enforcement, discovery+negotiation, automated status distribution, independent crypto review, durable-backend certification, relay operations controls, SDK/crate publishing, external third-party client, production launcher, real end-to-end org action, workload measurement.

- 2026-10-11: Implement the service lifecycle before exposing deployable owner RPC: explicit initialization persists an immutable deployment/initial-authority intent, opens empty trust, installs authority, then marks initialization complete. A separate signed refresh enables use. Public reopen never fills missing state; interrupted setup resumes only through an exact owner retry. Prefer private service-bound owner RPC over a public bearer-admin endpoint or implicit environment bootstrap. Deployment IAM is the owner trust boundary; no cloud resources are provisioned.

- 2026-10-11: Package the native lifecycle behind a fixed-name SQLite object and a private named owner entrypoint. Public fetch cannot invoke administration. Use strict HTTPS public profiles plus a separate secret binding, and deployment-binding operator metadata without claiming human authentication. Pin compatible Wrangler; no deployment/account mutation.

- 2026-10-11: Add opt-in minute Cron refresh from one pinned HTTPS feed; owner provisions the initial roster, automation preserves it and verifies signatures/anchors/checkpoints. Persist the feed URL in initialization intent, keep its token outside SQLite, deduplicate identical verified provisioning, and use the existing administrative journal for changed trust. No cloud resources or signer keys are introduced.

- 2026-10-11: The refresh review proved that default service bindings can invoke scheduled handlers. Separate Cron into a privileged scheduler Worker bound to the named fixed-purpose refresh entrypoint; retain the main default export as fetch-only. This correction was recorded in the refresh-plan ruling before implementation. Both configs are independently hashed and dry-run; no hosted deployment.

- 2026-10-11: Build a read-only administrative archive collector before retention deletion. Each archive is a complete fixed-head snapshot with durable immutable page files and a last-written seal; a verified previous archive supplies a continuity witness. This copies no action payloads, never prunes the source and does not establish zero-RPO recovery. Retention policy and the recovery failure boundary remain pending.

- 2026-10-11: Reconcile the action ledger with its audit before exporting or restoring it. Preserve the existing schema and effect semantics; quarantine inconsistent histories, never repair or replay them automatically. This is a recovery prerequisite, not independent zero-loss protection.

- 2026-10-11: Build action archives using a fixed audit cut and initial whole-snapshot checksum, reconstructing immutable historical fields while writes continue between pages. Keep export private and read-only, preserve consumed claims and exact payloads, and close no independent recovery/retention gate by inference.

- 2026-10-11: Recovery design identified an existing storage-contract mismatch: trust allows an 8 MiB canonical bundle in one SQL row, while Cloudflare documents a 2 MB row/value limit. Correct trust persistence first with an additive schema migration and bounded current-bundle chunks; retain legacy reads, signed bytes/checksums, atomic checkpoint updates and explicit durability activation. No retention deletion or narrower recovery failure boundary is inferred.

- 2026-10-11: Build the recovery journal storage contract in a separate database before wiring source acknowledgments. It records bounded opaque recovery payloads with immutable ordered checksums, expected-head concurrency and durable receipts. No automatic namespace creation, reset, pruning or source replay. Local SQLite conformance does not select or certify an independent failure domain; account/provider-loss requirements remain unresolved.

- 2026-10-11: Connect action acknowledgements to deterministic per-transition recovery records, with schema7 immutable journal enrollment and startup history comparison. Publish at most one interrupted local tail without executing it; fence remote-ahead/divergent state. Adapter hosting and full restore remain separate acceptance gates.

- 2026-10-11: Add a provider-neutral recovery HTTPS boundary with a separate 256-bit service credential, exact endpoint/scope, no redirects/retries and no initialization/reset operations. This prepares authenticated transport without choosing or provisioning a recovery failure domain. Keep deployment and the accepted no-loss failure boundary open.

- 2026-10-11: Wire recovery HTTPS into the Worker profile and service constructor as an explicit pre-initialization option. Pin endpoint plus normalized journal descriptor in lifecycle intent; exclude credential and runtime timeout. Do not auto-create journals, enroll initialized sources or allow an injected capability to override configured transport. Credential rotation preserves public identity. Hosted journal provisioning and failure-domain acceptance remain separate.

Recovery bundle decision (11 October2026): implement provider-neutral read-only journal collection and offline validation before restore mutations. Capture a fixed initial head; verify complete payload hashes, chained scope/capacity/IDs and prior evidence; interpret action records separately so unknown opaque journal payloads never become executable state. No deletion, provider selection, reset, source mutation or hosted durability claim. Existing standing readiness authorization covers local implementation.

Staged restore decision (11 October2026): reconstruct actual action/audit rows from complete journal records into explicitly empty isolated storage, with a schema8 fence normal runtime initialization/verification rejects. Preserve all existing action SQL guards; replay data transitions only, never tools. Verified action reconstruction remains fenced pending complete trust/authority/admin recovery and accepted external execution fencing. This is a production prerequisite, not a narrowed definition of production readiness.

- Hosting clarification: the user has an existing Cloudflare account. This permits planning around that account, not deployment, purchases or production adoption.

Staging planning decision (11 October 2026): prepare a private empty-service smoke stage separately from real workflow and workload acceptance. A successful uninitialized/private smoke cannot establish Keycloak/MCP integration, retention, recovery or production readiness. Existing account authentication permits read-only preparation; resource creation, route changes and paid-plan changes remain unapproved.

Staging smoke scope decision: repeated host load above700 prevents clean broad verification. Prepare a private uninitialized package smoke for explicit review, without treating it as release acceptance or weakening deadlines. Earlier staging-plan wording requiring all regression investigation before even preparing approval is narrowed to require all defects affecting this status-only smoke to be resolved; full workflow/recovery certification remains blocked by the broader findings. No deployment occurs during preparation.

Cloudflare smoke authorization: user explicitly approved the exact private smoke scope in spec/plans/cloudflare-staging.md. Execute that scope without re-requesting permission. Production rollout, initialization, real credentials, public routes, paid-plan changes and load testing remain outside this approval.

Regression investigation decision (11 October 2026): previous turn made progress by completing the approved private hosted smoke. Preserve the live corrected full-suite handle; instrument an isolated native maximum-size recovery request to locate timeout cost before changing production code or deadlines. No extra cloud calls or broad reruns are needed for this diagnosis.

Recovery parsing decision (11 October 2026): isolated native instrumentation attributes8163ms to the per-character nesting pre-scan of a22,370,450-character request, then4114ms to strict parsing. Replace only that nesting scan with a linear structural-token scan that skips string contents and escaped characters; keep strictParse,16-level bound, byte caps and10000ms deadline unchanged. Existing maximum-size native failure is RED evidence; add lexical-boundary compatibility tests before implementation.

String parsing decision (11 October 2026): structural scanning fell from8163ms to116ms, but strict string parsing still consumed2783ms and the full request missed its client deadline after a durable append. Optimize unescaped string runs in the shared TypeScript strict parser; retain existing escape, control-character, surrogate, duplicate-name and numeric validation. This affects signed inputs across the SDK and requires full SDK/reference and integration regression coverage. Do not redeploy the previously approved smoke artifact automatically.

Refresh fixture decision (11 October 2026): the overlap test's200ms deadline can expire while the Node caller schedules its second native request; the production service deliberately releases refresh admission after timeout, so2 fetches need not represent overlap. Give the held-fetch case the supported10000ms budget, assert the first call is still pending across the overlap check, and release the held response in finally. Preserve explicit timeout/late-update assertions and all production deadlines.

JSON throughput verification (11 October 2026): production caps/deadlines unchanged; native maximum16MiB RED→GREEN, SDK241/root370/organization201/interop33 and types pass. Fresh parsing review found no findings;12,000 parser and411,771 scanner compatibility comparisons pass. New Worker/scheduler dry-runs and rebuilt Linux image smoke pass. Complete macOS/Linux suites are still running; the first Linux command omitted schemas and stopped before Cloudflare tests, with failure preserved and corrected-copy rerun started. Keep parser/reconstruction tasks active until platform evidence is complete. The intermittent recovery-read startup failure remains unproven.

Recovery startup root-cause decision (11 October 2026): new diagnostic reproduced an HTTP500 in193ms with an active deadline; journal-side trace then identified `TypeError: this.handler is not a function`. The test journal stores its configured handler only in memory and loses it when workerd recreates the object. Fix the TEST ONLY HTTP journal fixture to persist its synthetic configuration and reopen the existing journal after object recreation; never initialize/reset on that path. Add a deterministic native restart regression before changing the fixture. This is not a production recovery-hosting implementation and does not authorize storing real journal credentials in the database.

Hosting decision clarification (11 October 2026): the completed private smoke establishes feasibility, not production adoption. Asked whether the remaining production target should be the Cloudflare application with separate Keycloak/recovery hosting or Linux/PostgreSQL/Keycloak with an optional Cloudflare edge. Continue shared correctness and verification while that choice is pending; do not infer paid hosting, an independent failure boundary or real credentials.

Recovery transport fixture budget decision (11 October 2026): affected-file regression exposed the same100ms setup problem in a decoded-chunked success test. Use the supported5000ms budget for protocol/body/receipt tests and an explicit separate100ms configuration only for the five deadline scenarios. This prevents unrelated short deadlines from either failing success cases or falsely satisfying rejection cases; no production timeout changes.

- 2026-10-11 — Extend the existing console conformance with a real public Keycloak client and synthetic human login over fixture TLS. Keep operator endorsement explicit; verify one exact approval and one tool effect, replay refusal and logout. This is local workflow evidence, not adoption of either hosting route or organizational acceptance.
- 2026-10-11 — The scoped real-browser review found credential logging on Playwright failure, interrupted nested fixture cleanup, and incomplete exact-display assertions. Fix all three within this batch, use a shared owned-fixture cleanup coordinator, and retain the first login-navigation timeout as failed evidence. Extend only cold browser navigation waits; production deadlines remain unchanged.

- 2026-10-11 — Real browser enrollment/reload succeeds, but inspection fails because the console generated bare UUID envelope IDs while the server requires absolute URIs. Prefix generated envelope IDs with urn:uuid and make console transport tests apply the production envelope validator. Use valid session URIs in console fixtures; the example runtime policy's bare operations session also needs correction and fail-fast configuration validation as a follow-up. Do not relax the protocol parser.

- 2026-10-11 — Fix the unusable session setup in this same batch: Node protected configuration and Cloudflare owner initialize/update validation must reject policy session IDs that are not absolute URIs, while leaving storage-only policy identifiers unchanged. Correct the public runtime example. This prevents configuration checks accepting sessions that the signed API can never process.

- 2026-10-11 — Restore complete organization bundles only into empty isolated SQLite databases. Add an immutable schema9 organization restore fence and resumable page progress; preserve schema1–8 migration bytes. Historical trust/current authority insertion and authority history use narrowly selected trigger suspension and exact recreation inside a single synchronous fenced transaction, because the source never retained old configuration bodies for command replay. No await or externally callable command occurs while a trigger is absent. Verify the exact schema catalog before/after, reconstruct every file hash from persisted rows, and require explicit bundle/checkpoint scope on reopen. Normal runtime, including old executables, remains blocked; activation, independent receipts/current-journal reconciliation and external execution fencing remain separate mandatory recovery work.

- 2026-10-11 — Prepare complete organization export over the existing private owner binding. Transfer canonical component bytes in bounded parts rather than raising the RPC response limit to fit a16MiB trust checkpoint. Pin one captured cut per expiring operator session; historical authority/admin page reads must prove the captured head against retained source history and never include newer records. Preserve existing current-head APIs and wire formats. A lost/expired source session leaves an incomplete unsealed bundle; no automatic source mutation, public route, cloud deployment, recovery acknowledgement guarantee or activation follows.

- 2026-10-11 — Measured administrative history reads rescan100000 rows to return16, implying at least625 million row inspections for a full maximum-size export. Add a scoped internal reader that fully verifies source/captured history once, then validates schema, live and captured heads, predecessor and selected records per page. Preserve standalone full-scan and live mutation behavior. Complete bundle verification still requires every selected record before sealing; the scoped reader does not claim continuous integrity of unrelated rows. Verify native corruption, advancement, closure and row-work bounds, then repeat the same scale probe; initial capture cost and memory remain gates.
- 2026-10-12 — The complete-service diagnostic fails export capture at100000 admin records; profiling attributes56.72% of administrative verification samples to canonical serialization/string checks. First optimize repeated audit serialization only: return the validated event with its canonical encoding, reuse it in full verification/appends, and compare exact validated start/result fields without serializing equivalent objects again. Preserve byte format, Unicode/shape/size checks, all full scans, limits and deadlines. Add byte-compatibility and rehashed-corruption coverage, remeasure, then assess further capture work separately.
- 2026-10-12 — Remove only the third control-history scan during export setup. Add store-owned checkpoint-and-reader factories that fully validate the source once and return an exact immutable checkpoint with a scoped reader. The service will create those readers during its post-sync capture, compare pre/post manifest digests as before, and close any acquired readers if capture or later admission fails. Public historical-reader APIs retain their existing verification. Assert native row-work bounds and preserve fixed-cut, corruption, synchronization and closure behavior; no deadline/capacity/schema change.

- 2026-10-12 — Follow the successful Node SQLite maximum-history capture with a standalone local workerd diagnostic using the existing test-only lifecycle fixture. Seed the same paired started/completed record shape in bounded batches while the service is closed, then reopen and measure synchronized checkpoint, export begin and first component. Require exact head/checksum and manifest equality, explicit close and zero outbound requests. Keep production deadlines unchanged. Measure parent-observed elapsed time and SQL row work; do not label Node coordinator memory/CPU as Worker resource use or infer hosted limits. Run sizes in fresh processes after current native/Linux verification, never concurrently with heavy tests.

- 2026-10-12 — Extend the existing real-Worker diagnostic with an opt-in full-bundle mode. Reuse production collection, receipt correlation and offline verification; collect all pages into a fresh protected temporary directory, confirm source cleanup and unchanged head, stop the runtime before offline verification, and preserve artifacts on failure. Run increasing history sizes sequentially without changing production code, resource limits or deadlines. This implements the existing local export acceptance plan, not deployment or hosting adoption.

- 2026-10-12 — Investigate export memory independently of the shared-host maximum-history timeout. Establish a loopback-only local workerd inspector measurement with a bounded synthetic calibration before changing any runtime instrumentation. Use existing production contracts to construct large valid components, retain normal eviction and deadlines, and report observer overhead and measurement limits. No cloud inspection, deployment, forced garbage collection during timed product operations or hosted-capacity claim.

- 2026-10-12 — Profiling the valid signed-large capture failure attributes50.86% of leaf samples to serialization/Unicode checks,9.55% to snapshot traversal and8.81% to GC. First remove downstream repeated validation/serialization of the same historical trust checkpoint using private WeakMap provenance over deeply immutable validator outputs. Cache only derived canonical text; copied, externally frozen or foreign-organization inputs cannot inherit provenance. Do not cache storage reads or change signatures, wire bytes, capacities or deadlines. Re-run boundary/corruption tests and large measurements before assessing further changes.

- 2026-10-12 — The first immutable-reuse signed-large probe completes all components and close but records an instance change and32179.93ms parent-observed begin. Heap samples are320.95MB after capture/343.65MB after close. Do not claim a same-instance latency improvement or memory reduction. Add test-only owner-call instance attribution for status/begin/close and repeat with profiling; keep the actual production constructor, owner calls, eviction and deadlines.

- 2026-10-12 — For source trust capture, extract the existing SQL/chunk/record/checksum portion into private #readState. Keep #read's live signed-bundle preparation, canonical equality and active-record agreement unchanged. Only checkpoint uses #readState followed by the full historical validator; it still compares the captured row with the instance's accepted checksum and quarantines every integrity failure. This removes duplicate signed preparation within each captured read without caching reads, removing the synchronized second read or weakening external validation. Add signature-only tampering with recomputed outer checksums and noncanonical persisted-row regression guards before applying the extraction. The existing signed-large unavailable receipt remains the red performance evidence.

- 2026-10-12 — Before changing shared canonicalization, add optional heap allocation sampling to the existing local export diagnostic. Current CPU attribution identifies serialization but does not identify retained memory or allocation churn. Prefer sampled allocation call trees over a full heap snapshot (larger artifacts and intrusive collection); do not force GC, evaluate code through the inspector, change eviction, or use a remote inspector. Keep CPU and allocation modes mutually exclusive, preserve exact component/source/close verification and profile artifacts on capture failure, and run after the frozen Linux suite. This is diagnostic evidence only, not a substitute for combined or hosted resource acceptance.

- 2026-10-12 — Allocation sampling identifies the shared reference strict parser's per-character string construction as a major allocation source. Apply the already implemented SDK ordinary-run scan only to packages/identity/signed-envelope.mjs; do not replace the strict parser with JSON.parse or change canonicalization, input limits, rejection rules or deadlines. Preserve raw/escaped surrogate and control checks, escape decoding, duplicate decoded names, numeric bounds and null-prototype objects. Baseline long-string guards before the port, then broad shared-consumer and platform verification plus a new allocation capture. Profiling is provisional attribution, not precise peak or live memory.

- 2026-10-12 — Diagnose the remaining large export unavailability using a temporary local instrumented bundle, not production changes. Emit stage names, elapsed clock values and synthetic error stacks at synchronized capture/export expiry boundaries; preserve exact logic, clocks, deadlines, eviction and full component checks. Record source and instrumented artifact hashes and treat timing as diagnostic only. Run after the frozen Linux suite. No remote inspection or cloud mutation.

- 2026-10-12 — Investigate overlapping retained capture graphs independently of the unreproduced large-export failure. Use an isolated, network-refusing Node lifetime probe with WeakRef and explicit GC solely to prove reachability across the sync await; never call this a benchmark or use forced GC in Worker measurements. If the first complete checkpoint is retained, preserve only its independently frozen manifest in the coordinator before the second read. Keep both reads, fixed action cut, exact digest comparison and failure/quarantine behavior unchanged.

- 2026-10-12 — Complete the audited Rust identity decomposition as a mechanical internal move with explicit imports and unchanged crate-root public API. Preserve function bodies, constants, public types and profile-specific timestamp rules; do not consolidate independent cross-language implementations or alter dependencies/MSRV. Record pre-change source/API inventory, run existing workspace/vectors on1.94.1 and1.81, check formatting/Clippy/rustdoc and Node↔Rust interoperability, then obtain scoped review. This does not substitute for independent cryptographic review or protocol stabilization.

- 2026-10-12 — Direct restricted SQL with a separately valid signed alternate chain bypasses counter-only control transition checks. Preserve the exact previously accepted signed key documents for every entity that remains active in a runtime trust update; require JSONB document equality, including signatures (the chain digest binds the complete signed document). Removal remains allowed and re-addition remains owner-only. This supplements signed validation without adding database cryptography or permitting a new chain branch under higher counters. Add failing actual-SQL evidence before the trigger correction; runtime integration and scoped review remain open.

- 2026-10-12 — Compose PostgreSQL trust as an asynchronous factory with private prepared bundles and an immutable control token. Startup opens exact enrolled public inputs, validates current freshness in the bounded identity worker, then reopens the same durable head before activation. Updates retain old authority only during preparation; entering publication disables local authorization, and any uncertain publication requires a fresh open. Close/cancellation cannot activate a late result. Extract the launcher's existing runtime composition into a callable function so the disposable-PG acceptance case exercises the actual startup boundary and real TLS listeners. No automatic enrollment, weaker test-only production settings or new deployment is introduced. Task4 still must serialize action authorization/dispatch with publication; this task alone does not close A12.

- 2026-10-12 — Task3 review measured synchronous ControlStore signature revalidation blocking the main thread for4.9s at700 entities. Move both historical validation and complete transition preparation into a dedicated bounded worker that calls the existing pure control-state model; no caller-supplied prepared state becomes trusted. Keep input snapshots and SQL ownership in the parent, freeze returned public state, propagate cancellation and enforce an8s worker deadline below the30s idle-transaction limit. Existing SQL grants/digests/expected-head ordering and transaction helper stay unchanged. Add actual-store timer-progress and cancellation regressions before implementation; record maximum-state and hosted latency as still unaccepted.

- 2026-10-12 — Capture a request-scoped control token before pool acquisition. The organization launcher must compose a control fence into each ActionStore; the reusable ledger primitive still supports isolated ledger conformance without enrolled control state. Fenced transactions take the shared control-head lock before any action row, check local snapshot usability after lock waits and before commit, and retain the lock through commit. Internal finish remains unfenced so an already attempted effect can be recorded. Dispatch additionally needs a synchronous invocation permit; a transaction fence alone does not close A12.

- 2026-10-12 — The dispatch permit is a synchronous check-and-invoke section in the single Node runtime. It checks the request-scoped trust token while publication holds the conflicting publishing phase, then invokes fetch without an await. Database revision validation remains asynchronous and durable before this section. Provider/request/policy checks precede dispatch, with synchronous request expiry/cancellation rechecked at invocation. This relies on the planned single-runtime/owner-maintenance lease; uncoordinated external publication and infrastructure fencing remain unresolved until that boundary is implemented/accepted.

- 2026-10-12 — Enforce one runtime or owner-maintenance operation using an exclusive session advisory lock (1480935760,3) on a dedicated bounded PostgreSQL Client. Never borrow a work-pool slot. Acquire before opening control trust or listeners; observed connection/end/heartbeat failure immediately invalidates authority and triggers drain. Keep the lease until accepted work and its database shutdown complete. Owner control commands and schema maintenance use the same conflict key. The lease coordinates sessions on one database; it does not certify fencing after an unobservable partition or a separately restored database.

- 2026-10-12 — Owner control/schema mutations must execute on the session holding their maintenance lease. A separate owner work connection could outlive lease-backend termination and commit after a new runtime acquires ownership. Runtime ownership uses its dedicated client as implemented; owner maintenance still needs a scoped same-session transaction adapter and interruption tests before the commands are shipped.

- 2026-10-12 — Explicit lease failure must settle both connection setup and advisory-lock acquisition even when the driver leaves its promise pending after intentional shutdown. Race each acquisition await against the existing non-rejecting failure notification, then check opening state before accepting any result. A real TCP stalled-authentication regression reproduces the review finding; no database or public network is required.

- 2026-10-12 — Adapt the owner lease's existing PostgreSQL session to the shared transaction boundary, exposing only bounded options and sequential connection acquisition. Every borrowed handle delegates to that same backend; releasing a transaction keeps the session lock, while a broken release invalidates and closes it. Reject concurrent borrows and use of released handles; pause heartbeat queries during a borrow. Runtime callers retain the small lease-only interface. Schema maintenance will migrate and grant on this adapter, preventing a separate transaction from surviving lease-backend loss.

- 2026-10-12 — Owner control enrollment/change commands use the verified same-session maintenance adapter and existing protected owner/runtime configuration loaders. Enrollment locks and reads the complete legacy checkpoint without constructing its writing TrustCheckpoint class; a newly absent directory may be reserved for the import window, while any existing incomplete/unsafe directory is refused. Add a read-only-in-purpose owner `inspect` command that verifies and returns only the historical head (or explicit empty state), so an uncertain command result can be reconciled even when provisioning has expired. Inspection does not confer live trust; the shared durability acknowledgement still emits its transaction marker. No command opens listeners.
