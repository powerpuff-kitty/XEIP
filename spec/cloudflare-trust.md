# Persistent signed trust for the experimental Cloudflare backend

Status: implementation within the user-selected Cloudflare exploration. This advances G1/G2/G3; it does not select a production backend or certify provider recovery. Keep the Linux/PostgreSQL/Keycloak path and its acceptance targets.

## Intended outcome

The Durable Object must authorize only currently endorsed, unrevoked entity keys, remember accepted generations/status serials across restart, and reject rollback, forks and silent anchor replacement. A signed provisioning update must not become usable before its persistence succeeds. Removed entities lose active access but retain historical checkpoints. This is the persistent trust part of the authority integration; actual Keycloak authentication, protected policy/binding updates and signed Worker ingress remain separate required work.

## Shared verification

Extract the existing synchronous provisioning preparation and checkpoint-merge rules into a shared pure identity module. Reuse the current Ed25519/key-document/status/envelope verifiers; do not create a new cryptographic implementation or change the 0.2 carrier. The existing filesystem-backed trust classes consume the same helpers and preserve their interfaces, limits and durability ordering. The Cloudflare adapter uses the helpers without opening a filesystem checkpoint.

Preparation takes a complete `{keyDocuments,statusDocuments}` snapshot, `maxAgeSeconds`, understood extensions and an explicit verification time. It returns isolated verified bundles, per-entity checkpoint candidates and generation→chain-digest maps. Checkpoint merging retains omitted entities, rejects lower generation/serial, same-counter differing digests, changed anchors and historical forks below a higher chain tip. Retain the existing 4096-record and 8 MiB checkpoint limits; bound durable provisioning to 8 MiB as well. These are prototype safeguards, not rollout retention/capacity acceptance.

## Storage and migration

Extend the checked ledger schema through an explicit version-1→version-2 migration. Verify the old version/checksum/catalog before applying the new SQL atomically. Preserve action/audit rows and their protections. Do not silently replace a version-1 checksum or reinitialize an incompatible schema.

Add one trust-state row containing the immutable trust configuration, active canonical provisioning, accepted-at time, monotonically increasing revision, checkpoint-set digest and a content checksum. Add retained checkpoint rows keyed by entity containing anchor digest, generation/key digest and status serial/digest. SQL rejects deletion/replacement, anchor changes, decreasing counters and differing digests at unchanged counters. Application verification additionally checks signed chains and their historical continuity. Include all new objects in the catalog fingerprint.

Initialization is explicit through the trusted owner-only adapter interface; a missing trust row on ordinary reopen fails closed. Empty initialized trust authorizes nobody. Bind trust configuration to the persisted snapshot; changing maximum age or understood extensions on reopen requires a separately designed migration. Initial/new-entity anchors are explicitly supplied by the trusted owner; already accepted anchors cannot be replaced. No untrusted enrollment or public administration endpoint is introduced.

## DurableEntityTrust behavior

Expose asynchronous open/update and synchronous `allows`, `verify`, revision/status and close boundaries. One trust adapter owns one live object. Open validates canonical storage/checksums, re-verifies active provisioning at its recorded acceptance time, checks active candidates against retained checkpoints, and waits for durability before enabling use. Expired stored provisioning may open in stale state so that the trusted owner can replace it; it cannot authorize activity.

Update snapshots and verifies the full candidate before touching active authority. Invalid candidates leave the current snapshot usable. Once persistence begins, gate all trust-authorized activity and make the revision token differ from any earlier snapshot. Atomically write the candidate, merged historical checkpoints and next revision, then await storage synchronization before publishing the active in-memory state. Reject concurrent updates rather than queue or retry them. Any SQL/synchronization failure quarantines the instance; reopen must validate persisted state before recovery. No method resets checkpoint history.

`allows` checks current entity/key membership, revocation and freshness. `verify` additionally verifies the exact signed envelope and critical extensions. Track the maximum observed time within the live instance, starting at no earlier than its persisted acceptance time, matching the existing profile's clock assumption. Host clock integrity and whole-database rollback remain recovery gates; do not claim this local checkpoint detects restoration of every persisted copy to an older version.

The ledger's `LocalAuthority.revision()` must incorporate the trust revision/state along with all policy, membership and provider-binding revisions. During trust persistence or quarantine, it must not return usable authority. Pending authorization/claim/effect operations must observe revocation or a changed revision at their late check. Internal completion remains recordable after trust is revoked. The actual provider/policy composition is a subsequent integration step; tests must clearly label synthetic provider callbacks.

## Verification and limits

Run shared-helper regressions and all affected Linux trust/organization tests. Test the actual local workerd/SQLite engine for explicit initialization, checked upgrade preserving consumed claims, tampered/missing state, invalid signatures, stale/future documents, rollback, same-counter and historical forks, removed/re-added entities, anchor changes, immutable input, concurrent update, SQL rollback, sync ambiguity, pending-ledger revocation, and complete runtime restart. Use real signed fixtures and fake effect counters, never real tool calls. Keep the conformance worker's public ingress disabled.

Verify strict adapter types, container packaging for the shared helper, and existing ledger tests. One fresh-context final review covers the batch, followed by one regression-backed correction pass. No Cloudflare resources, credentials, production deployment, anchor reset or backend adoption is authorized by this implementation.

Provisioning snapshots permit at most 262,144 JSON nodes and depth 32 so the 700-identity rollout fixture fits within the existing byte/checkpoint caps. Individual action snapshots keep the default 8,192-node limit. The Worker owner boundary adds a stricter 2 MiB transport cap; these are bounds, not hosted throughput certification.
