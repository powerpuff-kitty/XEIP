# PostgreSQL organization control recovery

Status: model, storage and Linux runtime trust integration implemented locally.
[A12](audits/2026-10-12-linux-control-recovery.md) remains open: action/dispatch
fencing, runtime/maintenance coordination and explicit owner commands are implemented
locally with scoped reviews. Combined physical recovery, broader SQL review and
whole-organization acceptance remain pending.
Decision: [ADR 0018](decisions/0018-postgres-control-history.md).

The launcher now opens enrolled PostgreSQL control state before its listeners.
Older provisioning fails even if its signatures are still fresh; no filesystem
checkpoint grants authority. Local tests preserve a revocation with one approved,
unconsumed action and refuse stale startup with zero synthetic effects. Provider
readiness in that test is simulated; it is not real organizational acceptance.

## State and scope

One dedicated organization database contains a singleton control head and ordered,
append-only control events. Each event binds schema/profile version, organization
gateway identity, revision, previous event digest, operation, exact canonical
public configuration, complete signed trust provisioning, retained high-water
records and the original acceptance time. The current head identifies an exact
event; its checksum alone is not an independent rollback witness.

Public authorization configuration comprises origin/gateway, provider issuer,
audience, allowed clients, explicit subject/entity/key bindings, token lifetime
policy, session memberships/approvers, allowed targets/tools and their revisions,
target recipient/endpoints/OAuth issuer/client/scope, the introspection client ID,
trust freshness policy and
optional console client. Secret values, secret file paths, bearer tokens, database
credentials, TLS keys, management token and machine-specific bind/storage paths
are excluded. Operational timeout/resource settings remain validated by the
existing loader; they do not grant authority. The exact projection and canonical
encoding must have negative tests before storage is integrated.

Trust includes the complete active entity set, not only per-entity counters.
Removing an entity is a control change. Retained high-water records survive its
removal and cannot be reduced by later updates or enrollment. Existing
`prepareEntityTrust` and `mergeTrustRecords` remain the cryptographic and monotonic
validation rules. Historical signatures are validated at their recorded acceptance
time; active authorization additionally requires freshness at current monotonic
time. A valid historical backup is not automatically fit to activate today.

Use existing input limits: 4 MiB configuration, 8 MiB signed provisioning, at most
4096 key/status entries and 8 MiB serialized high-water checkpoint. Bound the
combined canonical event to 24 MiB after serialization; oversize inputs must
fail before SQL writes. Do not relax these limits to make a fixture pass. History
is append-only initially; no deletion or retention-policy acceptance is inferred.

Canonical-state implementation uses the existing safe JSON snapshot helper with
independent node ceilings: 262144 each for public authority, provisioning and
retained target mappings; 32768 for retained trust records. Retained target mappings
also have an 8 MiB byte ceiling. Metadata accepts primitive operation strings and
nonnegative safe-integer UTC seconds only. All returned JSON is recursively frozen;
no mutable Set/Map authorization objects escape this boundary.

`publicAuthority` extracts whitelisted data from validated loaded configuration and
returns `{value, canonical, digest}`. `prepareControlState` takes that result,
complete provisioning, operation and acceptance time. Enrollment explicitly imports
retained trust records; later transitions take one previous canonical snapshot,
preventing independently substituted history sections. `verifyControlState` checks
historical canonical bytes and signatures at original acceptance time, including
active-record and target-history agreement. It does not verify the database event
chain or establish that no later state existed.

Canonical payload profiles are `xeip.org.authority/1` and `xeip.org.control/1`.
SHA-256 domains are `XEIP organization authority v1`, `XEIP organization control
state v1` and `XEIP organization target v1`, each followed by one newline and its
canonical payload. The target digest binds public execution fields excluding its
ID and revision, which are stored separately as the mapping key. Permission-array
order is preserved, matching the existing policy revision algorithm. Omitted
maximum token lifetime is explicitly normalized to 300 seconds; invalid explicit
values are rejected.

## Enrollment and changes

Schema creation uses the existing explicit owner migration command, preserving
all prior migration bytes/checksums. Startup verifies the new schema and grants,
but never creates tables or enrolls control state.

Initial enrollment is an owner operation. It requires a validated complete input,
the expected empty control head, an empty action/audit ledger and an explicit
organization identity. If a filesystem checkpoint already exists, its complete
validated retained records are included; it must not be replaced by only active
provisioning. Missing historical trust on a legacy database is an unresolved
reconciliation requirement, never evidence that no history existed. A database
already containing actions is refused by fresh enrollment.

Owner configuration changes require the exact previous head and a drained runtime.
They record both the new public state and complete signed trust. They must not
reset trust history, retarget existing approved action content or overwrite a
concurrent update. Runtime credentials cannot initialize, delete, rewrite history
or change organization/public authority configuration.

For each target ID, a revision identifies one immutable public execution
configuration: recipient, tools, endpoint, resource metadata URL, OAuth issuer,
token endpoint, client ID and scope. Changing any of these requires a different
target revision, also updated in policy. An old revision must never be reused
for a different execution configuration, including after target removal. Retain
and check that mapping across the full history. Secret rotation alone does not
change it. Thus an approved action bound to the old policy/target cannot execute
against a replacement endpoint even after a valid owner change and restart.

SIGHUP trust reload prepares signatures off-thread, then serializes against the
current control head. It checks the runtime's configuration revision and merges
all retained records. It commits one complete trust event before changing the
active snapshot or logging `trust_reloaded`. Repeating the exact accepted input
may reconcile an uncertain result; it never creates authority from a local cache.

SIGHUP may refresh or remove currently active entities; it must not add an entity
outside the current active set, even if its signed counters match retained history.
Adding or re-adding an entity requires the explicit owner operation with the exact
expected head and a recorded active-set change. This prevents a restored old input
file plus SIGHUP from silently undoing an accepted removal. Both paths still enforce
signature freshness, chain continuity and retained high-water marks.

## Implemented storage boundary

`ControlStore` returns an immutable `{revision,digest,snapshot}` result. `open`
compares the exact public authority and provisioning with the current verified
snapshot; it does not decide current freshness. Publication locks serialize before
reading the expected head. `assertCurrent` holds a shared head lock inside the
caller’s existing transaction; that caller still owns its durability decision.

Migration003 adds append-only `control_events` and singleton `control_head`.
An AFTER INSERT trigger advances the head in the same statement. Invoker-rights
triggers require the table owner for initial enrollment or public authority changes;
runtime credentials can refresh/remove active trust only. Runtime changes preserve
earlier signed key documents for entities that stay active, as well as retained
counters, target revision mappings and public authority. Direct SQL cannot replace
an accepted key-chain prefix simply by increasing its counters. Signature validation
remains in the shared identity implementation; SQL guards are not cryptographic
verification. Owner credentials can bypass protection and remain trusted.

Migration004 replaces the event trigger without rewriting migration003. Retained
records are bound to the accepted signed provisioning: an entity absent from the
current key documents may only preserve its exact prior record and cannot be
invented, and every active record's generation/serial must equal its accepted signed
key/status document. The bounded startup/open read verifies the current snapshot and
its immediate predecessor transition together, so inactive records are checked
against signed history rather than only active checkpoints. This remains structural;
signatures are verified in the shared identity worker, and full ordered history
verification stays a separate recovery task.

Each event digest is SHA-256 of `XEIP organization control event v1\n`, decimal
safe-integer revision, newline, previous event digest, newline and canonical state
digest. The first predecessor is 64 zeroes. SQL checks the domain-separated state
and event hashes. Startup storage reads validate the current snapshot, matching head,
immediate predecessor link and absence of later orphan events with bounded queries;
full historical verification remains the separate recovery task.

Normal startup uses this store and never initializes it. The explicit protected-file
owner CLI now provides enrollment, exact-head configuration changes and historical
head inspection under the same-session maintenance lease. Inspection verifies the
current snapshot and adjacent head links; it does not activate trust or replace full
history/recovery verification. The operations guide documents syntax and uncertain
result handling; combined recovery and production activation remain separate gates.

`openPostgresTrust` verifies exact enrolled inputs, prepares currently fresh signed
trust in the bounded identity worker, and reopens the same durable head before
returning authority. It keeps prepared bundles private and exposes only an immutable
revision/digest token. Trust publication disables local authorization before calling
the store; certain durable success and fresh state are required to activate again.
Failure/cancellation after publication begins requires reopen. Closing aborts worker
preparation and cannot activate a late commit. Invalid preparation before publication
does not replace the previously valid state.

The store itself runs complete historical and transition validation in a dedicated
control worker, including signatures. Parent-side code retains SQL ownership,
expected-head locks and safe input snapshots. The worker has an 8-second deadline
and a 128 MiB old-generation limit; returned structured-clone state is frozen again.
Optional cancellation is checked before transaction work, during worker validation,
before commit and before acknowledgement. A cancelled/uncertain commit never grants
live authority. The existing shared transaction helper is unchanged.

A local actual PostgreSQL 700-entity probe (855005 bytes of canonical state) demonstrated timer
progress during open and publication. It does not certify maximum input size, the
selected hosted latency target or aggregate memory at rollout load.

## Startup and request ordering

Open verifies the bounded complete current snapshot and its matching head event,
exact organization and
public-file input match, current provisioning match, signed trust, retained
records and current freshness. Unenrolled, corrupt, stale or mismatched state
refuses listeners. An older valid provisioning file is not automatically upgraded
or accepted by normal startup. An owner can provide current signed data through
the explicit recovery/update path, preserving the old accepted history.

The current snapshot contains all retained trust high-water marks and target
revision mappings needed for authorization; it cannot depend on scanning unbounded
history during startup. Full ordered history verification belongs to the offline
backup/recovery verifier and migration acceptance. Snapshot publication must be
atomic with its append-only event. The owner cannot replace this proof with a
fabricated checkpoint without leaving the trusted-owner boundary. Test startup
at maximum current-state size and offline verification at measured history sizes;
neither a per-event ceiling nor a checksum establishes the one-hour restore target.

The opened runtime receives a verified immutable snapshot and revision token.
During each action transaction, lock/check the authoritative control head before
authorization and preserve that ordering through the transaction's commit. A
control publisher obtains the conflicting lock. A request with a stale revision
must return unavailable/denied without acknowledging or creating an executable
claim. Recheck expiry, cancellation and live provider state after waits.

The asynchronous `beforeSend(): boolean` check alone is insufficient for ordering
dispatch with control publication. The Linux launcher now supplies a request-scoped
control fence to the action store and executor. Each authorizing transaction locks
the head before action rows; internal completion deliberately takes no control lock.
Before the effect, a separate durable head check runs before live provider
revalidation. The connector then calls a synchronous dispatch callback around the
actual tool fetch. The callback checks request expiry/cancellation, policy, and the
captured trust revision. JavaScript run-to-completion supplies the local permit: no
await separates the final token/phase check and fetch invocation. Invocation is the local dispatch linearization point;
release the permit after invocation, not after the tool response. Publication takes
the exclusive side of this barrier before its database mutation and holds it through
certain activation or transition to an unavailable state. Pending dispatch permits
cannot survive uncertain publication or shutdown.

Owner authority changes require a drained runtime and an exclusive database
maintenance lease conflicting with the runtime's lifetime lease. Lease loss stops
admission and dispatch. These leases do not substitute for external infrastructure
fencing after unobservable connection loss/partition or a separate database restore;
that failure-domain guarantee remains unproven.

If publication wins the barrier, old-snapshot dispatch is refused and the claim
remains consumed with the appropriate outcome. If dispatch wins, publication cannot
recall the started POST. Internal completion must still persist its result after a
control change; it is evidence, not a new authorization. Tests must pause after the
asynchronous revision check to exercise both orderings, rather than only delaying
authorization before the check.

Only one application process is supported. Revision checks detect stale snapshots
sharing the same database; they do not fence a separately restored old database or
replace external execution fencing. Concurrent same-revision claim suppression
continues to rely on the durable action ledger.

## Durability and uncertainty

Share the existing synchronous transaction boundary, including a WAL marker for
read/idempotent acknowledgements, warning detection during COMMIT, bounded waits
and destruction of uncertain connections. Do not reuse the maintenance helper's
weaker read-only transaction behavior for control acknowledgements.

Publication failure or an uncertain COMMIT disables local authorization. No old
in-memory trust snapshot may authorize while the database might contain a newer
revocation. Startup, reload cancellation, shutdown and a late successful commit
must not resurrect a closed runtime. Reopen revalidates the durable head and
current input rather than automatically retrying a mutation.

The database protects control history against runtime UPDATE/DELETE/TRUNCATE and
unauthorized public-configuration changes, with trigger/grant verification at
startup. Owner credentials remain capable of recovery and are not a security
boundary against a malicious database owner. Chain digests detect damage or mixed
history, not a consistent rollback of all data.

## Recovery and activation

Physical backup plus WAL restores actions, audit and control history together.
The candidate remains read-only/fenced while comparing the expected acknowledged
action and control heads with independently retained evidence. Missing later
revocation/configuration events, stale file inputs, missing retained entities or
unexpected consumed claims must prevent activation.

The local drill must restore a post-backup revocation and control change, prove the
old provisioning/configuration cannot start an executing service, prove the
current state still denies the revoked device, and preserve previously consumed
claims without any tool replay. Also exercise missing WAL and uncertainty paths.

This work does not itself select independent backup custody, prove absence of
later acknowledgements, fence old infrastructure, restore Keycloak, supply secret
versions or approve activation. Those remain mandatory whole-organization gates.
Recovery procedures must account for provider account disablement and credential
rotation separately; old provider state can be unsafe even with correct XEIP state.

## Completion evidence

Closure of A12 requires runtime-level regression evidence for the reproduced case,
same-counter forks, omitted entities, stale configuration, uncertain commits,
concurrent reload/claim/dispatch, post-change completion, restart and real physical
WAL recovery. Strict types, affected suites, minimum supported Node/Linux, restricted
role tests, migration preservation, artifact rebuild and independent scoped review
must pass. The original historical probe remains clearly labeled. Production
readiness remains no-go until the separate hosted/operator/security gates pass.


Local action-fence conformance uses a restricted PostgreSQL role and four actions.
It observes a publisher waiting on the action transaction's shared control-head
lock, rolls back a claim invalidated during the wait, rejects a separately cached
old revision, and exercises both sides of the post-validation dispatch gap. The
prevented effect leaves its claim consumed; the already-started synthetic effect
records success after revocation. Actual MCP fixture tests separately verify the
callback wraps `tools/call` fetch and prevents network dispatch when denied.
Single-runtime ownership is now enforced by a dedicated bounded PostgreSQL session
lease, acquired before listeners and retained through drain. Schema maintenance
shares its exclusive key and executes mutations on that same locked connection.
Actual PostgreSQL tests verify competing startup/maintenance refusal, a usable
one-slot work pool, observed backend-loss shutdown and rollback of an interrupted
owner mutation before another runtime takes ownership. Explicit owner enrollment, authority-change and historical inspection commands
are now implemented and tested against owned PostgreSQL through the protected CLI
over verified TLS. Complete legacy records survive enrollment, including removed
entities; populated legacy action ledgers refuse fresh enrollment. Combined recovery
and external infrastructure fencing remain open. The local permit cannot fence a separately restored writer
or an unobserved partition.
