# Worker recovery configuration

Architectural integration of the verified [recovery HTTPS boundary](cloudflare-recovery-transport.md) into the existing experimental organization Worker. This advances the approved exploration and no-acknowledged-action-loss goal without selecting a hosted failure domain or deploying resources. Retain Keycloak and the Linux deployment.

## Configuration and activation

The public profile optionally accepts `recovery:{url,stream,maxEntries?,maxBytes?,timeoutMs?}`. Organization comes only from the profile's organization; an inner organization override, credentials, unknown fields, nulls and insecure/ambiguous URLs are invalid. Reuse the journal's UUID/capacity/timeout validation and exact HTTPS URL rules. Keep both public profile and secret binding bounded at5 KiB.

When recovery is present, `XEIP_CREDENTIALS` requires exactly one additional `recoveryToken` field:32 random bytes encoded as64 lowercase hex characters. Reject a missing/malformed token and reject a token without a recovery profile. Public profile/build inputs cannot carry it. Runtime configuration and the service constructor validate the pairing independently. Service construction creates the verified HTTPS client; a simultaneously injected recovery capability is rejected to avoid an alternate unchecked endpoint.

Persist the normalized recovery descriptor (organization, stream, capacity, genesis) and exact URL in lifecycle intent before initial activation. Credential and timeout remain runtime-only so a fresh instance can rotate the credential or tune deadlines without changing identity. Existing programmatically injected adapters retain their existing descriptor format; no implicit migration from injected/unconfigured service intent to configured HTTPS is allowed. Removing recovery, changing URL/stream/caps or configuring recovery on any initialized unconfigured source fails closed on reopen. Namespace/name/class remain unchanged. No source schema migration is needed.

Public requests to an empty source do not initialize storage or call the journal. Explicit owner initialize enrolls only through the existing source/journal reconciliation: an already initialized empty journal with matching scope/capacity is required. The Worker cannot initialize/reset the remote journal. Unreachable/wrong-credential/divergent journal state prevents initialized activation; preserve local intent/evidence and reconcile on fresh open rather than bypassing the gate. Same-public-config credential correction can resume an interrupted explicit setup. Existing receipts, claims, late authorization and consumed-claim protections remain unchanged.

## Evidence

Profile tests cover secret separation, missing/extra/malformed credential, all endpoint/cursor/capacity errors, normalized defaults and unknown fields. Native service tests inspect persisted lifecycle/binding rows for public identity and absence of the credential, reject simultaneous injected capability, and check omitted/changed settings and credential rotation. Actual production Worker exports with separate local journal runtime and real provider/MCP fixture exercise owner initialization, signed proposal/approval/claim/completion, durable receipt ordering, journal failure before claim, lost receipt reconciliation, runtime restart and no repeated effect. Local HTTPS routing is a fixture translation, not hosted TLS evidence.

Build a recovery-enabled exact Worker artifact with an optional trust scheduler. Public manifest/config includes only recovery identity, never the credential. Validate actual local Wrangler startup/private owner status, exact packaged native workerd private initialization and signed recovery flow with fixture outbound mapping, and both dry-runs. Hosted TLS journal initialization remains separate acceptance. Existing unconfigured profiles and all447 baseline tests must continue to pass; final full macOS/Linux suites and strict types are required. No dependency update is planned.

## Remaining gates

This makes the source Worker configurable. It does not build/deploy a hosted journal, perform provider enrollment, choose independent storage/IAM, implement full restore/other-state recovery/retention, or certify workload, recovery SLOs, security or operator acceptance. Existing populated services cannot gain a zero-loss guarantee simply by adding this field. Production adoption remains unapproved.
