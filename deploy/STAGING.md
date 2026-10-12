# Reserved Linux staging acceptance

The user selected a dedicated Linux host with reserved resources for final acceptance. This repository's workstation was severely contended; its failed load result is recorded in [the audit](../spec/audits/2026-10-11-capacity-attempt-four.md). A successful fixture run on staging would be preliminary evidence. The actual installed organization runtime, human login flow, target tool and storage failure model must also pass acceptance before production.

## Build and inspect locally

The initial artifact target is Linux/amd64 with digest-pinned Node 22.23.3 Alpine. Build from the intended checkout:

```sh
docker build --platform linux/amd64 --file deploy/organization.Dockerfile --tag xeip-organization:local-review .
node conformance/organization-artifact.mjs
```

The build compiles the SDK and the optional approval-console assets, includes only production npm dependencies and explicitly selected runtime files, and generates `sbom.cdx.json` plus `files.sha256` inside `/opt/xeip`. The original manifests are retained as `source.package.json` and `source.package-lock.json`; runtime manifests contain the production graph with the same locked versions/integrities. npm's lockfile-based [SBOM command](https://docs.npmjs.com/cli/v10/commands/npm-sbom/) supplies a CycloneDX dependency inventory; it does not inventory the base OS or sign provenance. The build uses [separate Docker stages](https://docs.docker.com/build/building/multi-stage/) to keep the compiler and fixture files out of the runtime. Record the resulting image digest and base digest. A build from this uncommitted branch is an experimental working-tree artifact, not a release of HEAD. Never reuse its tag as proof that two builds contain identical bytes.

The smoke check runs the actual image with no network, a read-only root filesystem, no capabilities and no-new-privileges. It checks non-root identity, checksums, inventory, module/migration imports and redacted rejection of missing configuration. It does not open the production service or test real dependencies. The new CI job performs the same build/smoke procedure; hosted CI must actually run on the reviewed commit before being reported green.

## Install the candidate

Follow [OPERATIONS.md](../services/organization/OPERATIONS.md) for protected configuration, verified TLS, Keycloak mappings, signed provisioning and separate owner migrations. The container runs as UID/GID 1000; ensure its mounted private configuration/secrets are readable by that UID with the required restrictive modes. Root-owned application files must stay immutable. Mount a dedicated state directory owned by UID 1000 with mode 0700; the configured trust child is initially absent. Do not mount a whole home directory or repository.

Mount `/etc/xeip` read-only and `/var/lib/xeip` read-write. Keep the root filesystem read-only, drop all capabilities, enable no-new-privileges, impose memory/PID/CPU limits and use a stop timeout longer than configured `shutdownMs` (the example uses 30 seconds; allow 45). Use a private network with only the required ingress and dependency egress. Configure database/provider/MCP addresses that are reachable from the container and match their TLS names; container loopback is not the host's loopback.

Only port 8443 is exposed in the image. Metrics bind to loopback inside the container and must be scraped from that same network namespace by an authorized co-located scraper, or use the systemd installation with a host-local scraper. Do not publish or move management to a public bind address. Readiness is the verified TLS `/ready` endpoint on the canonical Host, distinct from `/live`.

Owner maintenance uses a separate, temporary protected configuration and owner credential mount, never the long-running service's credentials. Override the image entry point to `node services/organization/maintenance.mjs` and pass `--config` and `--runtime-role` explicitly. Remove the owner credential mount after maintenance. No startup migration is automatic.

## Record acceptance evidence

Before testing, record the reviewed source commit (clean), image/base digests, all component versions, CPU reservations and RAM limits, storage/WAL/fsync contract, network topology, TLS issuers, configuration/policy revision digests, retention policy and named operator. Record host contention throughout. Keep real secrets and action contents out of the report. Define the concurrent connection count and representative argument/result sizes; population alone does not specify these.

1. On the reserved host, run the repository's real Keycloak/PostgreSQL integration and diagnostic capacity fixture with 500 simulated approvers, 200 agents and 120 requested actions/minute. Preserve JSON output, requested/dispatched/completed/failed counts, successful-response percentiles, failure counts, stage timings and resource observations. Zero failures and each machine-operation P95 ≤2 seconds are required; human thinking is excluded. The fixture uses development Keycloak and simulated service accounts, so it must not become the deployment or substitute for human PKCE testing.
2. Run the installed candidate against the intended production-mode Keycloak and a harmless authorized internal MCP target. Exercise real human login, enrollment, exact argument review, approval/rejection, key/user revocation, concurrent claims, lost responses and restart. Then repeat the selected machine workload with representative enrolled test identities, payloads and connection concurrency. Preserve the exact approved content digest and tool-side evidence; do not execute destructive real actions as a load test.
3. Rehearse SIGTERM and listener/dependency failure during pending and in-flight effects. Verify readiness refusal, bounded exit, durable outcome inspection and no replay of consumed claims. Reconcile ambiguous tool effects using the tool's own records.
4. Select the storage failure model and prove **no acknowledged-action loss** under it. A database process kill or logical dump alone is insufficient for lost primary storage. Use the approved synchronous replica/storage design, backup/WAL archive and fenced failover. Compare an independently retained acknowledged-action list to the restored ledger and audit. Time recovery through usable service, requiring **≤1 hour**. Include trust checkpoint restoration, checksum/privilege verification and current revocation state.
5. Resolve external security review findings, verify data retention/backup controls and signed artifact provenance, assign maintenance/security owners, and obtain pilot sign-off. These remain open repository/deployment gates; this document does not certify them.

Stop acceptance on missing acknowledgments, unauthorized/duplicate effects, unverified TLS, failed latency/error targets or unbounded shutdown. Preserve the failed report. Do not reset claims, delete checkpoints, lower security checks or relax the targets to obtain a pass.

The browser console remains disabled until configured. Follow the [console enrollment and Keycloak guide](../services/organization/CONSOLE.md), including both required token audiences, before human staging acceptance. Local controlled-issuer browser tests do not certify the real realm, enrolled users or internal tool.
