# Linux authorization recovery audit

Status: **reproduced, unresolved production blocker**, 12 October 2026.

## Finding A12: restoring trust can restore revoked authority

The Linux organization runtime persists actions in PostgreSQL and signed-trust
high-water marks in a separate filesystem checkpoint. PostgreSQL contains no
record of a successful trust reload. Restoring an older checkpoint together with
its older, still-fresh signed provisioning can therefore reactivate a revoked
device while retaining the current action database.

The existing anti-rollback checks work when the latest checkpoint survives.
The defect is the missing recovery boundary across the two stores, not a signature
bypass or a rollback accepted against an intact checkpoint. It requires stale
operator-restored state or equivalent control over protected files; this probe
does not establish an unauthenticated remote exploit.

## Reproduction

Run the [disposable evidence probe](evidence/2026-10-12-mixed-trust-recovery.mjs)
from any directory with this repository's dependencies, compiled SDK, Docker and
the pinned PostgreSQL fixture image available:

```sh
node spec/audits/evidence/2026-10-12-mixed-trust-recovery.mjs
```

This is a historical defect probe, **not a passing acceptance test**. It uses the
current filesystem adapter directly. It must not be added to CI as evidence of
safe recovery. New PostgreSQL-backed recovery tests must require refusal of the
same stale state through the actual organization runtime.

The probe generates two synthetic signed identities, retains an early checkpoint,
proposes and approves one action in real disposable PostgreSQL, then:

1. Successfully reloads signed status serial 2 revoking the agent's device.
2. Confirms execution is denied with zero synthetic effects.
3. Confirms both action rows and action audit are unchanged by that revocation.
4. Closes trust and confirms serial 1 provisioning is rejected against the intact
   serial 2 checkpoint.
5. Replaces only the checkpoint with its early copy and opens the old serial 1
   provisioning; both signatures remain valid and fresh.
6. Confirms the revoked device is allowed again, the database is still unchanged,
   and the previously approved action reaches one synthetic effect.

Actual local result, exit 0 on 12 October 2026:

```json
{"finding":"stale-trust-restore-reactivates-revoked-device","intactCheckpointRejectsRollback":true,"revokedClaimDenied":true,"databaseUnchangedByRevocation":true,"restoredOldTrustAllowsDevice":true,"syntheticEffects":1,"scope":"real disposable PostgreSQL and signed trust; provider revalidation stub; no HTTP/MCP/network effect; not an acceptance pass"}
```

The initial run is retained at `/tmp/xeip-mixed-trust-recovery-probe.log`.
The repository-relative probe was run separately and reproduced the same result;
its [evidence record](evidence/2026-10-12-mixed-trust-recovery.json) retains the
command, Node version, result and source SHA-256 fingerprints. Both processes
exited 0 because they asserted the known defect. No owned fixture remained.
The durable script uses only its generated temporary directory and the existing
owned PostgreSQL fixture. Provider revalidation returns true intentionally; no
Keycloak, HTTP, MCP endpoint or external side effect is used. The connector invokes
the real executor's pre-send authorization guard before incrementing a counter.
This isolates the local trust recovery failure; real provider recovery remains
an additional test requirement.

## Related boundaries found by inspection

- `main.mjs` constructs trust from protected files before opening listeners.
  Startup verifies database schema/durability independently. No shared revision
  binds the trust snapshot to that database.
- `configuration.mjs` validates policy and identity bindings, but no persisted
  accepted revision detects restoration of an older valid configuration.
- `TrustCheckpoint` retains omitted entities' counters, but restoring the entire
  old checkpoint removes those later counters. Signed status freshness alone
  cannot distinguish the old state during its validity window.
- Action claims still prevent replay of already consumed claims. The reproduced
  effect uses an approved, **unconsumed** claim and therefore does not contradict
  the earlier claim-preservation recovery drills.
- Even a shared database can be restored consistently behind its latest commit.
  An accepted independent durability/witness boundary and old-writer fencing
  remain necessary; moving tables does not establish zero recovery-point loss.

## Remediation and evidence required

The [control-state decision](../decisions/0018-postgres-control-history.md) and
[implementation plan](../plans/postgres-control-recovery.md) define the local
remediation. Store current public authorization state and append-only changes
with the action ledger, pin the running process to an accepted revision, and
refuse stale file inputs or stale-process authorization. Retain the filesystem
adapter for the loopback relay; do not silently discard its historical records
when enrolling an existing organization.

Closure requires the failing scenario to be refused through the composed Linux
runtime, with no connector call, including omitted entities, configuration
rollback, ambiguous control commits, concurrent requests, restart and physical
WAL recovery. Full organization acceptance additionally covers Keycloak,
secrets, independent storage, external fencing, operator timings and the selected
workload. This audit does not close any of those gates.


## Local remediation progress — 2026-10-12

The historical reproduction above remains unchanged. The launcher now opens exact
PostgreSQL control state and refuses old provisioning before listeners. It no longer
uses the filesystem checkpoint as its organization authorization authority. Runtime
trust lifecycle checks cover uncertain publication and close/cancellation.

Action transactions now lock the captured control head before action rows, and the
actual MCP fetch is invoked synchronously under the captured local trust revision.
A restricted-PG four-action regression proves publication waits for the transaction,
a separate stale cache cannot claim, publication-first prevents dispatch with its
claim consumed, and dispatch-first completion persists after revocation. Its one
counted effect is synthetic. Actual MCP fixture tests separately prevent the tool
request when the final dispatch callback refuses it. Scoped review found no
Important/Critical issues in this boundary; it excluded wider SQL review and leases.

Native organization285 and root385 tests, full Node22/Linux285 cases, strict
organization/Cloudflare types, real Keycloak/signed HTTPS/MCP integration and the
rebuilt Linux artifact pass. The initial Linux harness denied execution of its
private temporary Docker shim; that five-case failure and the corrected full pass
are retained in the evidence. Exact source fingerprints and current verification scope are in the
[action-fence evidence](evidence/2026-10-12-postgres-action-fence-results.json).
A12 remains open for lifetime/maintenance coordination, combined physical recovery,
and the remaining review/acceptance requirements described above.

### Runtime and schema-maintenance ownership follow-up

The Linux launcher now owns a dedicated PostgreSQL session lease before opening
listeners and keeps it through drain. Schema maintenance uses the same exclusive
key and performs its transactions on that lock-holding connection. Actual-PG tests
verify runtime/maintenance exclusion, a usable one-slot work pool, observed lease
loss/shutdown, and rollback of an interrupted owner mutation before a replacement
runtime acquires ownership. A real pg/TCP regression reproduces and fixes the
reviewed cancellation-during-authentication hang. Native300/Linux300, strict types,
launcher/lease drills and rebuilt artifact checks pass; scoped review found no
remaining important issue within this slice. The minor fluent-handle escape was
also reproduced and fixed.

[Exact ownership evidence](evidence/2026-10-12-postgres-owner-session-results.json)
records scope and source fingerprints. Explicit owner control commands, complete
legacy-checkpoint import, combined physical control/action recovery and broader SQL
review remain open. Session ownership does not certify external fencing, restored
provider/secret state, hosted SLOs or production readiness. The original reproduction
above remains historical evidence; A12 is not closed by these ownership checks.

### Owner command and SQL review follow-up

Protected owner enrollment/change/inspection and complete read-only legacy import
are now locally verified: native322/Linux322, strict types, actual PostgreSQL CLI
over verified TLS and artifact smoke pass. [Evidence](evidence/2026-10-12-postgres-owner-command-results.json).

The broader SQL review found an unresolved P2 retained-history gap: forged retained
metadata can survive identity removal and enable an incompatible owner re-addition.
Model acceptance is reproduced; actual-PG exploit reproduction and correction are
pending. Invalid active metadata followed by removal and invented inactive keys
also require regressions. Full details are in the control-recovery plan. A12 remains
open for this finding, combined physical recovery and external acceptance.
