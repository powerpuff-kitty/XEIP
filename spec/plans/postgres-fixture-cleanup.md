# PostgreSQL fixture ownership after ambiguous creation

The archive recovery review identified a shared fixture gap: `withPostgres` recorded `created = true` only after `docker create` returned. Docker can create a container and anonymous volume even when its client fails to return a successful response. In that case the existing finally cleanup omitted both resources.

Register the generated name before requesting creation, add a unique `xeip.postgres-fixture` label, and require exact label confirmation before removal. Use the same removal boundary for ordinary cleanup and explicit source destruction. Only the exact Docker missing-object response permits treating a candidate as absent. Foreign labels or unavailable inspection must preserve the candidate and protected credential file for explicit investigation, report the generated candidate name and fail cleanup. Never enumerate or remove unrelated resources.

Verification: reproduce the real daemon-side leak with a temporary wrapper that executes only the fixture's actual create and then returns failure; remove the RED fixture explicitly from its recorded exact resource identity. Add process-level tests using a private Docker shim that never invokes Docker for created/absent/foreign/uninspectable cases. Verify normal startup, destructive source recovery paths, protected-file cleanup and existing signal coordination. No application, schema or production configuration changes belong to this fix.

## Evidence

The actual Docker fault reproduces the leak against the saved baseline (`/tmp/xeip-postgres-before-create-cleanup.mjs`): `/tmp/xeip-primary-create-cleanup-red.log` fails because the fixture container still exists. The probe explicitly removes that generated fixture and its volume afterward. Four process-level tests also fail before the fix (`/tmp/xeip-primary-cleanup-tests-red.log`).

The corrected implementation passes the same actual Docker probe (`/tmp/xeip-primary-create-cleanup-green.log`): the fixture reports failure, its generated container is absent, and its one anonymous data volume is absent. The probe uses `/tmp/xeip-primary-create-fault.py`; its temporary wrapper forwards Docker calls, lets only the uniquely generated fixture primary create succeed, then returns exit 77. It never targets unrelated containers.

Permanent process-level regression cases now cover a daemon-side create with lost response, an absent candidate, foreign ownership, unavailable inspection and confirmed ownership followed by failed removal. The latter case was a review suggestion and verifies retained credentials and failure reporting. All five cases also check that diagnostics do not disclose the generated secret. No real Docker calls are made by those unit-test shims.

Final verification completed with exit 0:

| Check | Result | Local log |
| --- | --- | --- |
| Five creation/cleanup cases plus signal coordinator cases | 8 passed | `/tmp/xeip-primary-cleanup-tests-final.log` |
| Real ordinary PostgreSQL fixture | Upgrade, ledger, abrupt restart, logical restore, restricted runtime and signed service cases pass | `/tmp/xeip-primary-cleanup-postgres.log` |
| Actual physical archive recovery | 9 actions, 23 audit events, 4 consumed claims and zero repeated effects; missing-segment refusal and paused comparison pass | `/tmp/xeip-primary-cleanup-archive.log` |
| Held-container WAL mode | Startup, checksums and cleanup pass | `/tmp/xeip-primary-cleanup-wal-mode.log` |
| Organization suite including new regressions | 216 passed | `/tmp/xeip-primary-cleanup-organization-final.log` |
| Node/TypeScript/Rust interoperability including conformance regressions | 41 passed | `/tmp/xeip-primary-cleanup-interop-final.log` |

Scoped review reports no remaining Critical, Important or Minor findings. It independently ran the original seven lightweight cases; final eight-case evidence includes the added removal-failure case. Syntax/diff checks pass. This corrects fixture resource ownership, not application durability or production disaster recovery. The existing Node and Rust CI paths include the new tests, but hosted CI execution is unverified. No application, schema, deployment or release changed.
