# ADR 0017: Explore a Cloudflare-native organization backend

Date: 2026-10-11. Status: **Proposed (local exploration in progress)**. Exploration requested by the user; local compatibility probes and experimental ledger/trust adapters are authorized within that exploration. Production adoption of this architecture is not accepted. Does not supersede ADRs 0013–0016.

## Context

The user has no dedicated Linux staging host and selected exploration of Cloudflare-native hosting. The existing organization service depends on PostgreSQL, POSIX trust checkpoints, protected files and a long-running Node process. Self-hosted Keycloak remains the selected identity provider. Workload, latency and recovery targets remain unchanged.

## Proposal

Evaluate a Workers ingress with SQLite-backed Durable Objects for the action ledger, audit and monotonic trust state. Use one configured organization object only for the bounded correctness prototype. Preserve the signed protocol, exact-action approvals, live provider/trust checks and durable single-use claims. Never automatically retry an ambiguous external effect.

Keep the Linux/PostgreSQL implementation and artifact. Evaluate Keycloak hosting and private MCP connectivity separately. A cloud-native backend changes the fully self-hosted operating model; the platform dependency must be accepted explicitly before production adoption.

## Alternatives and consequences

Cloudflare DNS/proxy plus a Linux host minimizes application changes but retains the server. Workers plus Hyperdrive retains an externally hosted database. Containers do not by themselves preserve the current disk durability contract. The native object route removes those XEIP server dependencies at the cost of a new state/recovery adapter and provider-specific operations.

The decision requires proof of authorization ordering across awaits, acknowledgment durability, prevention of replay after restore, practical retention/partitioning, runtime compatibility and the unchanged workload SLO. A single object's storage cap and snapshot rollback risks prevent declaring this design production ready from documentation alone.

Evidence, source links, repository boundaries and ordered feasibility work: [Cloudflare feasibility audit](../audits/2026-10-11-cloudflare-feasibility.md).
