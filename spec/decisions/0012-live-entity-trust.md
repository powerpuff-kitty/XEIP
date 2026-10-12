# ADR 0012: Atomic owner-driven trust refresh and device-bound activity

Status: Accepted for implementation, 2026-10-11. Authorized by the user's instruction to continue toward single-organization production readiness.

Restart-only provisioning cannot promptly apply revocation or retain active connections safely after status expiry. An entity-only bearer credential also cannot identify which revoked signing key should lose receiving access.

Adopt the [live trust contract](../live-entity-trust.md). Retain one exclusive checkpoint owner across atomic updates; validate all candidates, persist monotonic chain/status history, then publish active snapshots. Validation failures preserve state. Ambiguous persistence failures disable identity-authorized activity until reopen. Removed active entities retain historical rollback checkpoints.

For the experimental entity-signing mode, require local credentials to name a canonical key ID and require messages to use that same key. Recheck trust for operations and fan-out, close affected streams immediately after update, and sweep idle connections each second for expiry. An in-process owner API is preferable to a new network administration endpoint before the production authentication/authorization boundary exists. Requiring key binding changes provisioning of the unreleased opt-in 0.2 profile; legacy local profiles are unchanged.

This extends ADR 0011's first restart-only implementation. It does not provide automated status distribution, automatic anchor recovery, whole-disk rollback detection or a production deployment. Keycloak is the selected later OIDC provider; authorization of a concrete action remains G2.
