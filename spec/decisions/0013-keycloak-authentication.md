# ADR 0013: Keycloak access-token authentication for one organization

Status: Accepted for implementation, 2026-10-11. The user selected self-hosted Keycloak and authorized continued production-readiness work.

Use one pinned Keycloak realm and API audience with the exact-version `jose` dependency for RS256 JWT verification. Explicit subject-to-entity/key bindings prevent token attributes from enrolling identities. Confidential-client introspection follows JWT verification and is not positively cached. Inactive tokens fail authentication; provider failures make the authentication boundary unavailable. Keep credentials private and return immutable principals with only the configured API's client roles.

Offline JWT verification alone would permit revoked access tokens until expiration. A general pluggable identity framework would add unneeded variation before the first organization deployment. The selected approach trades provider availability and request latency for a straightforward active-token check. Load and outage tests must measure that cost; this is not an availability claim.

This decision is limited to [authentication](../organization-auth.md). Entity trust, membership, approval of exact action content and durable single-use execution claims are separate checks. The existing demo relay is unchanged. Production TLS/Keycloak/database configuration and external acceptance remain release gates.
