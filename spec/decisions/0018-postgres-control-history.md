# ADR 0018: retain Linux authorization history with actions

Status: accepted for local experimental implementation, 12 October 2026.
Implementation is pending; no migration or deployment is authorized by this
record alone. Repository implementation and disposable verification are within
the user's continuing production-readiness instruction.

## Context

[A12](../audits/2026-10-12-linux-control-recovery.md) reproduces a revoked device
becoming authorized after restoration of old signed provisioning and its old
filesystem checkpoint, with the current PostgreSQL action ledger untouched.
Protected files and local signature checks cannot establish which authorization
state was last accepted when their own high-water evidence is restored backward.

The selected Linux profile already uses one PostgreSQL 18 database and one active
organization process. Cloudflare remains a separate exploration. Independent
storage and failure-domain acceptance are not yet selected.

## Decision

Make PostgreSQL the authoritative store for the Linux organization's accepted
public authorization state, signed trust and retained rollback records. Keep
versioned, append-only control events and a current head in the same database as
actions. Use the action ledger's checked synchronous commit contract for all
control acknowledgements, including idempotent reopen/reconciliation results.

Protected files remain explicit operator inputs. Normal startup must match the
enrolled public configuration and signed provisioning; it cannot enroll an empty
control store or silently accept a configuration change. Initial enrollment and
configuration changes are separate owner commands with an expected prior head.
Trust reload remains an authenticated-by-operating-system local SIGHUP operation,
but persists verified control state before activation and success logging.

The runtime holds a verified immutable snapshot and its control revision. Each
action authorization checks that revision against the authoritative database;
stale processes cannot claim new effects. Serialize control publication with
action authorization/commit. Preserve completion recording for an effect already
attempted. A process with uncertain control persistence must stop authorizing
until an explicit reopen verifies the committed head.

Serialize actual tool-fetch invocation with trust publication through a local
dispatch barrier; an asynchronous boolean check is insufficient. Owner authority
changes require a drained runtime and a conflicting database maintenance lease.
Retain immutable mappings from each target ID/revision to its execution settings,
requiring a new revision for changed endpoints or OAuth authority. Re-adding a
removed trust entity requires an explicit expected-head owner operation; SIGHUP
cannot silently undo removal. Verify bounded current state at startup and complete
history during offline recovery verification.

The existing filesystem trust implementation remains for the loopback relay.
Existing organization enrollment must preserve every retained checkpoint entry,
including removed entities. A legacy database with actions and no control history
cannot be automatically certified from current files: its history requires an
explicit operator reconciliation workflow, recorded as such.

See the [contract](../postgres-control-recovery.md) for state, ordering and limits.

## Alternatives

- **Coordinated file backups only:** useful operationally but cannot prevent the
  reproduced mixed restore, unrecorded changes after the backup cut, or restoration
  of an older permission configuration. Rejected as the application-level fix.
- **Independent remote control journal:** can protect a larger disaster boundary,
  but adds an unselected service and distributed publication/reconciliation to
  the Linux profile. Keep independent evidence as an acceptance requirement;
  do not import the experimental Cloudflare journal by default.
- **PostgreSQL control history:** shares transaction ordering, WAL recovery and
  privilege enforcement with existing actions. Selected for local implementation.

## Consequences

Requires a forward migration, restricted runtime grants, explicit owner enrollment,
an asynchronous PostgreSQL trust adapter, revision checks, upgraded recovery tests
and rebuilt artifacts. Runtime schema migration remains prohibited. Secret values
and bearer tokens are excluded from control records. Retention must preserve
rollback records, current authorization and evidence needed to reconcile actions.

This refines ADR 0016's Linux trust persistence; its single-process, TLS, owner
maintenance, drain and effect reconciliation boundaries remain in force. No wire
signature format, Cloudflare schema, hosting choice or production storage policy
changes. A consistently rolled-back PostgreSQL database still needs independent
evidence and old-writer fencing; Keycloak and secrets remain separately recovered.
