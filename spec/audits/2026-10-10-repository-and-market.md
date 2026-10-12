# XEIP repository and market audit

Audit baseline: `1dcfdec51b179ac548ce83ef80dbddf95f6fe53c`, 10 October 2026. Scope: engineering quality, architecture, maintainability, features, customization, competitors and market alignment. This is historical evidence; current remediation state lives in [the hardening plan](../plans/production-hardening.md).

XEIP has a credible experimental foundation. Its tested local profiles do not yet compose into a production identity and delivery system. The strongest product hypothesis is a focused human–agent–device workflow using existing protocols. Market demand for interoperability does not establish demand for another envelope protocol.

Hosting follow-up (11 October 2026): the user requested a [Cloudflare-native feasibility assessment](2026-10-11-cloudflare-feasibility.md). This explores a managed platform alternative; it does not replace the current self-hosted profile or certify recovery/capacity.

## Findings

| ID | Priority and confidence | Evidence at baseline | Consequence and remediation |
| --- | --- | --- | --- |
| A1 | High, reproduced | `services/relay/relay-core.mjs`: replay acceptance precedes `store.append`; `durable.mjs`: retained state is mutated before disk writes | With admission, replay and durable `fsync:always`, forcing `manifest.json.tmp` to be a directory makes the first send fail. A retry returns accepted/duplicate; the failed message is visible in memory but absent after reopening. Commit replay only after storage succeeds; keep uncertain writes unavailable until recovery; never expose an uncommitted entry. |
| A2 | High, reproduced | `sdks/typescript/src/index.ts`: `events()` discards non-message events and SSE IDs | A gap followed by sequence 42 yields only an envelope. Expose typed delivery events, cursors and gaps; make the envelope-only API fail visibly on gaps. |
| A3 | High architectural gap, reproduced | `tools/signed-envelope.mjs`: `entityUrn(kid) === sender`; `relay-core.mjs`: key registry checked afterward; `spec/identity-keys.md` section 8 repeats both rules | An endorsed device gets 403 as its parent entity and 202 as its own key-derived entity. Define a separately versioned entity-bound signing profile; preserve the existing self-certifying profile. |
| A4 | Medium, confirmed design constraint | `spec/local-signed-envelopes.md`: all extensions excluded from signed bytes | Application authority must not rely on unsigned extension metadata. A new signing profile must authenticate relevant extensions and define unknown/critical extension handling. |
| A5 | Medium, confirmed | Relay imports runtime identity from `tools/` and validation from SDK sources; repeated Node/TS identity logic; 2,946-line Rust identity module; JS gate is syntax-only | Extract runtime packages, use thin CLI wrappers, split identity modules, add semantic static analysis incrementally, preserve independent Rust conformance. |
| A6 | Medium, confirmed | README says locking and durable receipts absent; RELEASING says Actions use mutable tags | Code implements locking, receipt persistence and SHA-pinned Actions. Reconcile canonical status and release documents. |
| A7 | Production gap, confirmed | Loopback enforcement, static key/status provisioning, planned grants/discovery/bridges/tracing; SDK/crates not publishable | Define a supported deployment envelope, identity lifecycle, policy enforcement, operational controls and distribution before release. |
| A8 | Performance limitation, measured locally | Synchronous filesystem path; `npm run bench` | On the audit machine, durable append measured ~16 ops/s with fsync always versus ~2,700 batch. This is not a production capacity estimate. Set durability/latency requirements and benchmark realistic load before selecting a production backend. |

Follow-up (11 October 2026): the Node runtime/CLI portion of A5 is resolved by the [identity runtime extraction](../plans/identity-runtime.md): shared modules live under `packages/identity`, existing command entrypoints retain compatibility, and production imports no longer depend on `tools/`. Rust decomposition and incremental semantic-analysis work remained open at that checkpoint.

Follow-up (12 October 2026): the [Rust identity module extraction](../plans/rust-identity-modules.md) resolves the decomposition portion of A5. The current 2,949-line root becomes an 82-line public entry point with private responsibility-based modules; all 53 public items and original implementation/test bodies are preserved. Rust 1.94.1 and 1.81 each pass 80 workspace/all-target tests with one pre-existing live-relay smoke ignored; formatting, Clippy, rustdoc and 36 interoperability cases pass. Scoped review reports no findings. Broader semantic-analysis coverage remains open, so A5 is still partially resolved. This is maintainability evidence, not independent cryptographic review or production acceptance.

Current implementation follow-up (11 October 2026): the baseline feature and customization assessments below are historical. The organization service now composes signed identities, Keycloak authentication, explicit session/tool policy, a browser approval console, durable execution claims and an MCP adapter. Linux/PostgreSQL fault drills and experimental Cloudflare recovery components have local evidence. The Cloudflare account has only a bounded private smoke deployment; real organizational integration, complete recovery, sustainable retention and workload/security/operator acceptance remain open. Use the [current capability table and release gates](../../PRODUCTION_READINESS.md) for the present status. These engineering changes do not establish customer demand or change the market-evidence limitations below.

Semantic-analysis follow-up (12 October 2026): the [Node identity foundation gate](../plans/identity-static-analysis.md) adds direct strict/noUncheckedIndexedAccess checking for key IDs, strict JSON and legacy envelope signatures. All 45 baseline diagnostics are resolved with unchanged executable ASTs. Compile-only consumers preserve supported Node/JWK key forms; deliberate faults confirm both implementations are checked. Existing runtime suites, vectors and consumer gates pass, and both scoped-review contract findings are fixed. CI is configured but hosted execution is unverified. The other Node identity implementations remain outside this new gate, so A5 remains partially resolved.

## Engineering assessment

Follow-up findings during remediation (10 October 2026), separate from the
original baseline table:

| ID | Confirmed issue | Remediation status |
| --- | --- | --- |
| A9 | Enabled status enforcement allowed a trusted entity with no status; configured age was checked only at startup; caller mutation could remove an accepted revocation | Reproduced and fixed in the second batch: per-send presence/age/issuance checks and provisioning snapshots. Production refresh, persisted trust and a successor signing profile remain open. |
| A10 | Receipt append failure mutated the in-memory ledger; failed compaction of a full receipt log could return success despite no persisted record | Reproduced and fixed: persistence precedes ledger commit; required compaction failures restore ledger state and produce 503. Ordinary budget saturation remains explicitly advisory. |
| A11 | Failed torn-tail truncation, receipt reads or quarantine could resume on unreadable storage; failed initialization could leave a stale lock or leaked receipt descriptor | Reproduced and fixed: refuse unsafe recovery and clean up acquired resources on initialization errors. Wider failure certification remains G3. |
| A12 | Linux organization restoration of old signed provisioning and its filesystem checkpoint reactivates a revoked device against the unchanged current PostgreSQL ledger | High recovery gap, reproduced 12 October 2026; unresolved. The intact checkpoint rejects rollback. A previously approved, unconsumed action reaches a synthetic effect after the stale restore. [Evidence](2026-10-12-linux-control-recovery.md) and [control-history decision](../decisions/0018-postgres-control-history.md); production activation remains no-go. |

These findings strengthen the requirement for combined-profile and fault-path
tests; successful isolated primitive tests did not establish safe composition.

| Dimension | Assessment |
| --- | --- |
| Code quality | Good experimental baseline: defensive validation, bounded resources, negative tests and standard crypto primitives |
| Structure | Clear spec/schema/implementation/conformance separation; runtime dependency boundaries need work |
| Architecture | Shared policy across transports is valuable; identity/delivery composition needs repair |
| Maintainability | Moderate: vectors and ADRs help; duplication, large modules and documentation drift hurt |
| Features | Substantial local messaging and identity primitives; external integrations and operational lifecycle incomplete |
| Customization | Strong profile configuration; limited replaceable storage/auth/transport contracts |
| Production readiness | Experimental only; no public deployment approval |

Implemented slices include local admission, live bearer revocation, replay suppression, cursor delivery, durable segments, compaction, exclusive locking, durable advisory receipts, limits, signatures, key documents, status documents and root/device rotation verification. Their existence does not establish integrated identity, production durability or processing acknowledgments.

The demo uses simulated participants. Discovery, MCP/A2A/Matrix bridges, grants, delegated command authority, human approvals, federation and media remain incomplete. Entity/transport enums are closed, capability descriptions are minimal, and extensions have no general negotiated semantics. TypeScript is private and Rust crates have publishing disabled.

## Competitive evidence

Sources checked 10 October 2026. Product capabilities below are vendor/project documentation claims, not independent deployment tests.

| Alternative | Relevant capability | XEIP implication |
| --- | --- | --- |
| [MCP](https://modelcontextprotocol.io/specification/2026-07-28) | Tools, resources, prompts, elicitation, progress and cancellation | Integrate existing tools without replacing their semantics |
| [A2A](https://a2a-protocol.org/latest/specification/) | Discovery, tasks, artifacts, streaming and security schemes | Preserve task lifecycle and context; human input is already supported |
| [agentgateway](https://agentgateway.dev/docs/standalone/latest/documentation/about/) | Open-source MCP/A2A connectivity, auth, TLS, policies, retries and observability | Vendor neutrality alone is not a differentiator |
| [Kong AI Gateway](https://developer.konghq.com/ai-gateway/) | Routing and governance of MCP/A2A traffic | General enterprise agent connectivity is competitive |
| [AWS AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html) | Managed runtime, gateway, identity and observability | Compete on a specific deployment/workflow advantage; [pricing](https://aws.amazon.com/bedrock/agentcore/pricing/) is consumption based |
| [Matrix](https://matrix.org/) | Decentralized messaging, clients, bots, servers and bridges | Integrate human collaboration instead of rebuilding it |
| [W3C WoT](https://www.w3.org/TR/wot-thing-description/) | Device properties, actions, events, schemas and security metadata | Demonstrate entity neutrality through a real device binding |
| [NATS JetStream](https://docs.nats.io/concepts/jetstream) | Persistence, replay, acknowledgments, consumer positions and redelivery | Evaluate an established optional backend before expanding custom persistence |

## Demand and positioning

[LangChain's survey](https://www.langchain.com/state-of-agent-engineering) reports 57.3% of respondents running production agents and 89% using some observability. Security was the second-largest production concern among respondents at enterprises with 2,000+ employees. Its 1,340 responses were collected 18 November–2 December 2025, with 63% from technology: directional evidence, not a representative market-size estimate.

The [Agentic AI Foundation reported 247 members in August 2026](https://www.linuxfoundation.org/press/agentic-ai-foundation-welcomes-57-new-members-gaining-major-financial-services-players-and-apac-leaders), supporting ecosystem investment in open standards, not willingness to adopt XEIP.

XEIP aligns in intent with interoperability, accountable actions, recovery and vendor-neutral operation. It lacks the working adapters, scoped policy, observability and distribution needed to realize that intent. Validate a self-hosted human-approved agent-to-device/service workflow with design partners. Measure integration time, operational complexity and recovery against direct MCP/A2A integration and existing gateways. Customer adoption, willingness to pay and market size were not validated by this audit.

## Verification at baseline

- Node 26.8.1: 268 relay/tools tests, 191 SDK tests, 32 interop tests passed.
- Rust 1.94.1: 78 tests passed; formatting and Clippy passed.
- JS syntax, JSON Schema/shared vectors and TypeScript build/typecheck passed.
- Node measured coverage: 93.30% lines, 87.38% branches, 96.10% functions. This excludes SDK TypeScript and Rust coverage.
- npm/Cargo advisory scans reported no known vulnerabilities.
- Local benchmark completed; results are machine-specific, not service-level guarantees.
- Node 22/Rust 1.81 CI matrix, external cryptographic review and independent-client adoption were not independently established in this audit.

## Third-batch remediation update — 10 October 2026

A3 and A4 now have an experimental opt-in implementation: [entity-bound signing 0.2](../entity-signed-envelopes.md), with shared JS/TS/Rust vectors, explicit pinned current identity chains, mandatory fresh status, authenticated application extensions and critical-extension checks. The relay persists counters and digests to reject restart rollback and same-counter forks. Legacy signing behavior is unchanged. These changes address the reproduced architectural gaps, but G1 remains open for live refresh, trust-recovery operations and independent cryptographic review. See the [execution record](../plans/entity-signed-envelopes.md).

## Subsequent remediation — 11 October 2026

Owner-driven atomic live trust refresh and device-bound revocation/expiry now close affected streams and reject new use, with failure injection and rollback regressions. See [live trust evidence](../plans/live-entity-trust.md).

The separate organization modules now include a Keycloak adapter tested against a real pinned provider, deny-by-default action policy, canonical exact-content approvals and a PostgreSQL ledger. Local drills cover concurrent single-use claims, audit-write rollback, revocation races, a lost commit response, database kill/restart and logical backup restoration. Review prompted authorization-before-lock checks, an authorized status lookup after expiry/policy changes and bounded database waits. See [authentication evidence](../plans/organization-auth.md) and [action ledger evidence](../plans/organization-actions.md).

The signed HTTPS operation boundary and pinned MCP connector now compose these modules. A real Keycloak → PostgreSQL → official MCP SDK fixture covers exact approvals, concurrent single-use execution, live revocation before the effect, ambiguous completion and historical result lookup. The human role is a simulated service account; browser login and approval UX remain open. Review added a final authorization/cancellation check after SQL and audit waits, immediately before initiating COMMIT; internal effect completion remains recordable after client disconnection. Post-fix verification passed 127 combined organization tests (99.12% line coverage) and 126 organization unit tests on Node 22/Linux. See [signed-service evidence](../plans/organization-service.md).

The experimental launcher now supplies protected file configuration, direct TLS, separate owner migrations and restricted runtime credentials, startup/dependency checks, bounded worker drain, verified trust reload, redacted request metrics and private management TLS. One final review found and fixed privileged PostgreSQL built-in EXECUTE grants bypassing verification and listener failures bypassing supervised shutdown. Post-fix verification passed 166 combined tests with real PostgreSQL and 165 tests on Node 22/Linux. The operational guide and service/configuration templates exist; they are not an installed or supported release. Dependency-health transition events remain a deferred observability minor. See [runtime evidence](../plans/organization-runtime.md).

The user selected 500 users, 200 agents and 120 action requests/minute, P95 machine-operation latency ≤2 seconds excluding human review, restore ≤1 hour and no loss of acknowledged actions. The first completed load attempt failed with only 11 completed actions and successful-response P95 20.7–28.0 seconds; see [capacity evidence](2026-10-11-capacity-attempt-four.md). Performance diagnosis is active. Human browser approval, actual organizational tool/operator acceptance, retention, supported distribution, independent security review and selected storage disaster recovery remain open. [Production readiness](../../PRODUCTION_READINESS.md) remains experimental.
