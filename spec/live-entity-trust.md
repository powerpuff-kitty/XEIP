# Live entity trust — local implementation contract

Target: single-organization self-hosting, with Keycloak selected for the later production OIDC boundary. The first intended pilot is a human-approved agent calling an internal MCP tool; user/device count and operator SLOs still require confirmation. This contract advances G1; it does not certify production readiness.

## Atomic updates

The owner calls `server.updateEntityTrust({ keyDocuments, statusDocuments })` synchronously with a complete replacement of active provisioning. No network administration endpoint is added. Configuration (anchors through documents, maximum age and understood extensions) is still explicitly provisioned. Updates validate every chain/status before persistence, then advance the existing exclusive checkpoint, then publish the new in-memory snapshot. Omitted entities lose active authorization while their historical checkpoint remains. Previously accepted anchors, counters and exact chain history cannot change or decrease. A rejected candidate leaves active state intact.

`TrustCheckpoint.update(candidates, chainDigests)` retains its lock across updates. Validation/rollback/fork rejection does not poison the writer. An attempted persistence failure marks the writer unusable until reopen, retains the lock and prevents all identity-authorized activity: disk success may be ambiguous. Successful restart must provide same-or-newer provisioning. The on-disk version remains 1.

## Device credentials and live enforcement

Local admission accepts optional `kid` in each credential. The entity-signing profile requires this device/root-key binding for sends, subscriptions, receipts and WebSocket upgrades. The signing carrier's key must equal the authenticated credential's key. The credential key must be currently endorsed, unrevoked and backed by fresh status. Legacy authentication profiles keep optional key binding and existing behavior. Credential rotation preserves its binding unless a new canonical key is explicitly supplied; the old principal immediately becomes invalid.

Successful updates immediately prune invalid subscriptions and idle WebSockets. Every new operation and message fan-out rechecks current trust; expiry is also swept at least once per second while the event loop is running, including otherwise idle connections. A frozen or blocked process cannot promise a wall-clock shutdown deadline. Wall time is nondecreasing within the process. The relay rejects reconnects with removed/revoked keys and denies receiving retained history after expiry. Health exposes aggregate readiness/failure state without keys or document contents.

## Recovery boundary

There is no live anchor reset, automatic lock stealing, or silent trust-directory deletion. Disk failure requires controlled stop/reopen with verified provisioning; missing/corrupt checkpoints require recovery investigation. Backups cannot independently prove they are the newest trusted state. Emergency re-enrollment after loss of all trustworthy state remains a separately authorized operator procedure and release gate.

## Threats and verification

Test partial/invalid replacements, mutable input, same-counter forks, historical forks below a higher tip, removed entities, revoked keys, expiry during streams and request-body reads, idle WebSocket shutdown, failed write/rename/fsync, update after close and durable restart rollback. No invalid update may disconnect valid clients merely because validation failed. Storage failure must disable all trusted activity before returning an error. Existing signing vectors and legacy relay tests must remain green.
