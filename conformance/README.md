# XEIP 0.1 conformance checks

`npm run test:postgres:archive-recovery` uses the existing pinned PostgreSQL image to verify a physical base backup and restore later action/audit changes from archived WAL. It checks missing-segment refusal, exact read-only target state and consumed-claim suppression after destroying the source. All containers, volumes and protected synthetic backup files are disposable and owned by the fixture; it accepts no operator target. [Scope and evidence](../spec/plans/postgres-archive-recovery.md) distinguish this explicitly archived cut from independent disaster recovery, whole-organization restoration and arbitrary-failure zero-RPO.

`npm run validate:fixtures` checks JSON Schemas and the shared structural validation vectors. Rust and TypeScript run the same vectors in their own tests. It also validates the self-certifying key-ID vectors (`conformance/fixtures/identity-keyid/`) with `tools/derive-keyid.mjs`, including negative cases a decoder must reject.

For a real HTTP/SSE exchange between the TypeScript SDK and a separately implemented Rust example:

```sh
npm ci --ignore-scripts
npm run test:interop
```

This requires Node 22+ and Rust 1.81+. The harness builds the TypeScript SDK and the Rust `local_relay_peer` example using the checked-in lockfiles, chooses free loopback ports, generates temporary credentials, and cleans up all streams and processes. It runs the bidirectional exchange in shared-token, local-admission and local-replay modes. No separately running relay is needed. CI runs it on both supported Rust toolchains.

The same command also runs `conformance/websocket.test.mjs`, which builds the Rust `websocket_peer` example and drives it against the Node `/ws` transport: a TypeScript HTTP send reaches the Rust WebSocket subscriber and a Rust WebSocket send reaches a TypeScript SSE subscriber (including nested Unicode), plus admission binding, unauthenticated/wrong-token/misrouted upgrade rejection, and delivery resume/gap. The `local_relay_peer`/`websocket_peer` examples are short-lived references, not production networking SDKs.

The TypeScript client subscribes as `message.valid.json`'s sender; Rust subscribes as its recipient. TypeScript sends the public fixture, then a command envelope containing nested JSON, null, booleans, numbers, a newline, accented text, emoji and a namespaced extension. Rust validates each envelope using `xeip-core`, preserves its content, kind, timestamp and extensions, swaps sender/recipient, appends `-reply` to the ID and sets `replyTo` to the original ID. TypeScript validates and compares the complete reply. These are transport echoes, not command execution or delivery receipts. The `delivered` response reports writes to active streams only.

The Rust example independently parses SSE, with fragmented UTF-8, LF/CRLF/CR endings, multiline data, comments, an initial BOM and bounded unfinished frames covered by Rust tests. It rejects invalid UTF-8. Its limit is 128 KiB of frame content including field/comment lines (CRLF counts as one line ending). It rejects non-SSE HTTP responses and unauthorized connections before declaring readiness. Connections use a fixed loopback host, disable proxies/redirects, and have a 30-second total request timeout. The peer is deliberately a short-lived example, not a reusable Rust networking SDK.

The admission exchange gives TypeScript and Rust separate credentials bound to the fixture's sender and recipient and provisions a direct session containing those two entities. TypeScript spoofed-sender and unknown-session sends fail 403; Rust cannot subscribe as the other entity using its valid credential. Native relay HTTP tests additionally cover membership removal, revocation, rotation, authorization changing during a POST body read, and subscription quotas.

The replay exchange adds a bounded retry ledger to that same admission setup. Each new send reports `duplicate: false`; a TypeScript retry of the identical envelope reports true/zero writes, and a changed-body retry fails 409. Rust accepts the optional false flag on its reply acceptance; its short-lived echo example still requires a new write to a subscriber and rejects duplicate replies. Both adapters reject malformed duplicate flags. Native HTTP tests verify simultaneous retries, lost HTTP responses, conflicts, expiry, capacity refusal, sender/session isolation, authorization changes, and reconnects without offline delivery.

These checks prove interoperability and local credential/membership enforcement between the current in-repository implementations. They do not establish independent authorship, production security, durable replay/reconnect, portable cryptographic identities, or interoperability with third-party clients. Those remain roadmap work.

## Entity-bound signing 0.2

`fixtures/entity-envelope/vectors.json` is consumed by the Node, browser TypeScript and Rust identity tests. It fixes domain-separated signing bytes and an identical device signature, then tests parent binding, extension/proof tampering, removed/revoked keys, anchors, freshness, malformed carriers and downgrade rejection. Run `npm test`, `npm run build:ts && npm run test:ts`, and `cargo test --workspace --all-targets --locked`. The fixture validator also checks the Node results. Relay HTTP/WebSocket and checkpoint tests cover enforcement and restart failures; the transport interop examples still use their existing profiles and do not prove an independently authored 0.2 client.

## Organization approval and execution

After `npm ci --ignore-scripts && npm run build:ts`, run `npm run test:organization` for focused tests, `npm run test:postgres` for the real ledger upgrade, fault and restore drills, and `npm run test:organization:integration` for the combined signed HTTPS → Keycloak → PostgreSQL → MCP path. Docker must be running with the exact images pinned in `keycloak.mjs` and `postgres.mjs` available. Fixtures use only newly created disposable containers, loopback ports and synthetic identities. The checked-in TLS key is a public test fixture, never a deployment credential. The separate `npm run test:console:keycloak` command adds real Chromium human login, a public PKCE client, explicit device enrollment and the browser-to-tool approval path; see the [console guide](../services/organization/CONSOLE.md) for browser setup and evidence limits.

`npm run test:organization:load` first repeats the real functional checks, then schedules 600 actions at 120/minute across 200 agent and 500 approver service accounts. Each action proposes, approves, executes and inspects. Set `XEIP_LOAD_REPORT` to a local report path to retain operation percentiles, errors and achieved rate. Passing requires no failures, every identity used, at least 114 completed actions/minute, and every operation P95 ≤2 seconds. Token issuance and envelope signing are outside the measured request latency; live token introspection is inside it. Human review and browser login are not simulated by this machine workload.

These checks do not certify production hardware, concurrent browser sessions, a real internal tool's latency/side effects, human usability, storage disaster recovery, or third-party security review. The ≤1-hour restore/no-acknowledged-action-loss targets require evidence from the selected deployment. Current gates and limitations are in [production readiness](../PRODUCTION_READINESS.md).

When running a frozen source copy in an isolated Linux container, retain runtime assets as well as imported modules. The relay's console tests read `examples/local-relay/console.html`, `console.css` and `console.js` directly; a source archive that omits them produces HTTP500 failures. Record the source inventory/hash and run from that immutable copy. A partial archive is not equivalent to the full checkout used by CI.

Protected-configuration tests also validate filesystem ancestors. Use a root-owned sticky `/tmp`, or a private temporary directory whose ancestors satisfy the same ownership and permission rules. For a single-user disposable container running as uid1000, a private tmpfs can use `--tmpfs /tmp:rw,exec,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=536870912`. A uid1000-owned mode1777 `/tmp` intentionally fails the checks: only root-owned sticky writable ancestors are accepted. Correct the test mount rather than weakening application permission validation.

### Synchronous PostgreSQL failover

`npm run test:postgres:replication` creates an isolated PostgreSQL 18.6 primary/standby pair with separate fixture storage and synthetic replication credentials. It verifies eight acknowledged action states and audit history after destroying the original primary, preserves four consumed claims, and refuses success on cancelled replication waits (including inspection and idempotent retry). The promoted server retains a required replacement standby. No operator endpoints or credentials are accepted. See [design and evidence](../spec/plans/postgres-replication.md); this is local functional evidence, not hosted recovery acceptance.

### Real PostgreSQL data-storage exhaustion

`node conformance/organization-disk-full.mjs` fills only the disposable PostgreSQL container’s 64 MiB shared-memory filesystem after placing its audit table in a test tablespace. The drill requires PostgreSQL SQLSTATE `53100`, checks rollback of actions whose audit append fails, verifies that a failed execution claim never reaches the connector, preserves acknowledged history and consumed claims, then retries the unaccepted proposal by its original ID after freeing space. It accepts no operator target or credential. This is audit data ENOSPC coverage, not primary/WAL disk exhaustion, physical corruption or hosted recovery certification. [Design and evidence](../spec/plans/postgres-disk-full.md).

### Real PostgreSQL WAL-storage exhaustion

`node conformance/organization-wal-full.mjs` uses a 64 MiB WAL tmpfs inside a new disposable PostgreSQL container. Actual WAL growth at a pending claim’s commit boundary must cause WAL ENOSPC and server termination. A holding shell preserves the mount while PostgreSQL is down. The fixture removes only its filler file, restarts PostgreSQL without resetting WAL or data, compares every acknowledged action/audit row, and refuses replay of consumed claims. No connector may run for the interrupted claim. This proves a local failure/restart path, not production durability of tmpfs, independent storage or full organization recovery. [Design and evidence](../spec/plans/postgres-wal-full.md).

### PostgreSQL corruption protection and isolated restore

`node conformance/organization-corruption.mjs` checks real checksum settings, changes one checksum byte of a selected synthetic action page while PostgreSQL is stopped, requires offline and live corruption detection, and refuses inspection/claim without any connector call. It restores a fixed pre-fault logical backup into a new database and compares all acknowledged action/audit rows and consumed claims. All checksum enable/disable and byte writes occur only inside the newly created disposable fixture; operator targets are not accepted. No actions are acknowledged after its backup cut, so this is not a periodic-backup zero-loss guarantee. [Design and evidence](../spec/plans/postgres-corruption.md).

## Organization staging artifact

Build the unpublished Linux/amd64 candidate with `docker build --platform linux/amd64 --file deploy/organization.Dockerfile --tag xeip-organization:local-review .`, then run `node conformance/organization-artifact.mjs`. The latter never pulls or publishes; it uses no network and a read-only, non-root, capability-free container to check installed dependencies against the source lock and SBOM, file integrity, fixture exclusions and redacted CLI failure. See [reserved staging acceptance](../deploy/STAGING.md). A smoke pass does not satisfy the real human/tool, capacity or recovery gates.

## Experimental Cloudflare ledger and trust

`npm run test:cloudflare` runs the shared action lifecycle against a real local SQLite Durable Object using pinned Miniflare/workerd. `npm run typecheck:cloudflare` checks the adapter contract. No cloud account or Docker is needed. Coverage includes schema/scope checks, immutable state/audit, quota, expiry, concurrent claims, authority changes during awaits, transaction rollback, synchronization ambiguity, completion failures and persistence across an actual local runtime restart. The ledger-only cases use a fake effect counter; transport/lifecycle cases also use a controlled local official-SDK MCP fixture. No organizational tool is called.

The same command also runs persistent trust tests with real signed provisioning, checked schema upgrade, retained rollback history, revocation during authorization, storage failures and restart. Provider callbacks and tool effects remain synthetic. The [trust guide](../services/organization/cloudflare/TRUST.md) documents explicit initialization, refresh and quarantine.

The authority suite adds the real Keycloak verifier against controlled RSA/JWKS/introspection endpoints, durable policy/binding updates, signed controller lifecycle and authority changes during claim/effect checks. `npm run test:cloudflare:keycloak` separately exercises real Keycloak in an isolated Docker fixture through workerd, including signed approval/execution and live token revocation. Its approver uses fixture client credentials; browser/PKCE acceptance remains separate. See the [authority guide](../services/organization/cloudflare/AUTHORITY.md).

The coordinated checkpoint and [organization bundle](../services/organization/cloudflare/ORGANIZATION_BUNDLE.md) cases verify complete fixed-cut action/control capture, protected canonical files, exact inventory and histories, external-digest mismatch, I/O and deadline failures, and large retained trust records. A native lifecycle case captures a consumed execution claim, lets its local MCP effect finish, verifies the earlier bundle offline, reconstructs the captured claim in a separate native database and refuses execution there as well as live replay. These are content and failure-path checks; they do not activate restored state or certify independent durability.

The organization export cases check bounded component reassembly, operator/session isolation, timer expiry, late responses, source closure, invalid history and full-size action evidence. Native lifecycle cases exercise the internal export service while authority, trust, administrative history and action state advance; exported files still reconstruct the original captured claim in a permanently fenced candidate. Additional native Worker tests exercise the private owner RPC and actual Node collector, with offline bundle verification. CLI process cases use a substituted binding provider to verify metadata-only output, mode/scope refusal and clean/rejected/stalled transport cleanup; the latter preserves sealed-bundle success while failed collection remains failed. These are local tests, not deployed CLI acceptance. Large-source capture/memory and hosted capacity acceptance are separate gates.

The fixtures have no public Worker ingress and must never be deployed: their private test interfaces include unrestricted SQL and fault controls. The [adapter guide](../services/organization/cloudflare/README.md) explains this boundary. Hosted PITR, real provider/MCP integration and the workload/recovery acceptance targets remain unverified.

The [organization reconstruction](../services/organization/cloudflare/ORGANIZATION_RESTORE.md) suite covers full control/action restore, interleaved audit sequences, chunked signed trust and removed-entity rollback records, interrupted/uncertain writes, transactional DDL rollback, exact-intent resume, permanent runtime fences, corruption and close/deadline races. Schema9 preserves earlier migration bytes; schema8 staged-action candidates upgrade only through explicit transactional reconciliation. These tests do not establish hosted capacity or activation safety.

For local capture-cost diagnosis, run `node --expose-gc conformance/organization-cloudflare-export-cost.mjs 1000` (also10000 or100000, one fresh process per size). This uses the real service on synthetic in-memory Node SQLite, reports stage times/result-row counts/process memory, refuses outbound fetches and changes no deployed state. It is intentionally separate from the correctness suite. It excludes real sync/network costs and does not certify workerd memory or hosted latency. The100000-record baseline failed its unchanged export deadline; confirmed-capture readers reduce begin from300017 to200000 admin row reads and the latest local run completes. See [capture evidence and its limits](../spec/audits/2026-10-12-organization-export-performance.md).

The companion `node conformance/organization-cloudflare-workerd-export-cost.mjs 1000` (also10000 or100000) is prepared for local workerd measurement using the private test-only lifecycle fixture. It seeds paired synthetic history in bounded batches while closed, reopens the actual service, verifies the captured head and manifest, reads the first component and closes the session. Every outbound request is refused. Stage times are observed by the Node parent and row counts come from fixture instrumentation; these are not Worker CPU/heap measurements or hosted acceptance. Run each size separately after correctness checks finish. The1000- and10000-record runs complete successfully; the100000-record manual-open fixture loses its live service to instance eviction, so it does not establish a usable maximum-size export. The diagnostic now records instance changes rather than interpreting reset counters as zero work. See the capture audit for exact results and limits. The pinned [local workerd limit enforcers](https://github.com/cloudflare/workerd/blob/v1.20260730.1/src/workerd/server/server.c%2B%2B#L3896) do not enforce hosted request CPU or isolate heap limits, so completion cannot certify those limits. Output records the installed workerd and Miniflare versions.

For actual private RPC/startup measurement use `node conformance/organization-cloudflare-worker-export-cost.mjs 1000` (also10000 or100000). Its local test-only subclass seeds synthetic history, then restarts and uses the real production constructor and owner RPC with eviction enabled. The default mode validates the administrative component, final history page and close; it does not collect a full bundle or enforce hosted CPU/heap limits. All three sizes complete; the100000-record begin takes11.81seconds in the recorded local run, followed by verified component/page/close. The performance audit preserves exact samples, earlier fixture failures and acceptance limits. Never deploy `organization-cloudflare-export-cost-worker.mjs`, which contains private test seeding methods.

For complete local transfer, add `--full-bundle`, for example `node conformance/organization-cloudflare-worker-export-cost.mjs 1000 --full-bundle` (also 10000 or 100000). This mode invokes the production collector through the private owner receipt-validation boundary with unchanged deadlines. It validates every page, writes synchronized protected files in a fresh temporary directory, confirms source cleanup and the unchanged administrative head, stops the runtime, and verifies the entire bundle offline against the captured digest. The printed directory is preserved for inspection, including on failure; it contains synthetic data only. Output includes collection/verification wall times, file/byte/page counts and Node coordinator peak RSS (not Worker heap). Other components remain small and there are no actions; this is not combined-capacity or hosted recovery acceptance. Run sizes sequentially. The [performance audit](../spec/audits/2026-10-12-organization-export-performance.md) records outcomes.

For local isolate memory diagnosis, run `node conformance/organization-cloudflare-export-memory.mjs small`, then `large` or `signed-large` in separate processes. The optional inspector binds only to127.0.0.1 and reads the XEIP isolate's operation-boundary JavaScript heap/backing-storage metrics. No garbage collection is forced. Synthetic trust records and large public authority data are seeded into a new private test database; the runtime restarts through the production constructor before capture and component verification. The signed-large mode adds valid signed provisioning near the checkpoint byte budget. All modes use1000 administrative records and zero actions. Samples are neither peaks nor retained-live-memory/hosted-limit acceptance. See the [performance audit](../spec/audits/2026-10-12-organization-export-performance.md) for exact workloads, failed fixture attempts, observed values and limits. The synthetic seeding subclass and inspector helper must never be deployed.

Add `--cpu-profile` to the memory diagnostic to profile only export begin in the local XEIP isolate. The diagnostic saves `capture.cpuprofile` and its compiled `worker.mjs` into a fresh mode0700 temporary directory with mode0600 files; the directory is printed and retained even when capture fails. Profiling adds observer overhead and does not certify CPU allowance or latency. Test-only status/begin/close logs identify the serving instance; if it changes before begin, the profiled request interval includes constructor/reopen work as well as capture. A post-failure heap sample is attempted before cleanup; it is not a failed operation's peak.


Use `--heap-profile` instead of `--cpu-profile` to sample allocation call stacks during export begin. It requests a32768-byte average sampling interval and includes objects collected by both minor and major GC, following the [Chrome DevTools protocol](https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/js_protocol.pdl). The protected temporary directory contains `capture.heapprofile` and the exact compiled Worker. These samples describe estimated allocation activity, including discarded objects; they are not current live memory, a peak, or a hosted memory-limit check. Heap and CPU profiling are separate runs. No explicit GC or runtime evaluation is requested. Unsupported profiler commands fail the diagnostic; do not interpret absence of a profile as a zero-allocation result. All normal component/hash/head/close checks remain required.


Observed allocation profiles can contain sample node IDs absent from the reported call tree, and the sum of sample sizes can differ from the tree's summed `selfSize`. Preserve and report both totals and unmatched sample counts/bytes. Do not silently assign missing samples or describe tree shares as fully reconciled allocation totals. Such a capture can guide investigation provisionally; it cannot establish an exact allocation budget.

## PostgreSQL control history

`npm run test:postgres:control` uses an owned disposable PostgreSQL instance and a
restricted runtime role to test explicit owner enrollment, trust publication,
concurrent/stale heads, retained identities, direct-SQL privilege/transition guards,
missing/rolled-back head refusal and valid versus alternate signed key chains.
The replication drill additionally refuses acknowledgements for cancelled control
publication and reopen commits. This is local storage evidence; runtime integration is tested separately below.
Independent recovery and production acceptance remain open. See the
[control recovery plan](../spec/plans/postgres-control-recovery.md).

`npm run test:postgres:trust` exercises the actual launcher composition against an
owned PostgreSQL fixture: unenrolled/stale startup refusal before listeners, a
retained approved/unconsumed action, durable revocation, and current-input TLS
startup. Provider readiness and action revalidation are synthetic; no real tool is
called. `node conformance/organization-control-performance.mjs` measures local
700-entity ControlStore timer progress through actual SQL. It reports elapsed time
and timer gaps without claiming hosted latency or maximum-size acceptance.


`npm run test:postgres:fence` exercises four actions with the actual restricted
PostgreSQL role, runtime trust and executor. It verifies control-head/action lock
ordering, stale cached revision refusal, both dispatch/publication orderings after
asynchronous validation, post-revocation completion and consumed-claim refusal.
Provider checks and counted tool effects are synthetic; real MCP callback behavior
is covered separately by `mcp.test.mjs`. Combined physical recovery and hosted
acceptance remain open.

`npm run test:postgres:lease` checks exclusive runtime/owner session ownership,
continued use of a one-slot runtime work pool, competing acquisitions, and observed
lease loss. It also runs the schema-maintenance entry point, verifies that owner
transactions use the lock-holding backend, terminates that backend during an
uncommitted mutation, and requires rollback before a new runtime acquires ownership.
The launcher checks in `test:postgres:trust` separately require readiness loss and
shutdown after lease termination. These owned fixtures do not prove external
infrastructure fencing. Owner enrollment/change commands are covered separately below.


`npm run test:postgres:owner` executes the protected owner CLI over verified TLS
against an owned disposable PostgreSQL instance. It checks initial enrollment,
exact-head authority changes, historical inspection without provisioning files,
preservation of removed-entity checkpoint records, unchanged checkpoint bytes,
restricted-runtime SQL denial, active-runtime exclusion and cancellation during
a blocked database read. Separate databases prove fresh enrollment succeeds and a
populated legacy action/audit ledger is refused without losing its rows. No provider
or tool is called. This is owner workflow evidence, not complete-history verification,
physical recovery, independent rollback evidence or production activation.
