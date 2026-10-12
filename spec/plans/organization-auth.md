# Organization authentication implementation plan

Use inline executing-plans and one final fresh-context review. Scope is accepted by the continued production-readiness instruction and explicit Keycloak selection.

**Spec:** [organization-auth.md](../organization-auth.md).
**Goal:** implement and verify the Keycloak authentication adapter before building action execution.
**Architecture:** separate `services/organization/` module with pinned issuer/JWKS/introspection; reuse typed identity SDK validation; keep relay authentication unchanged.

- [x] Inspect exact current `jose` package API/engine/release metadata; pin dependency and lockfile. Record dependency provenance; no lifecycle install scripts.
- [x] Write real signed-token/JWKS/introspection fixture tests in `services/organization/auth.test.mjs`, observe missing-adapter failure; implement `auth.mjs` with explicit config validation, bounded requests, principal mapping, claim checks and revalidation. Add strict JSDoc types and a dedicated TypeScript check.
- [x] Verify invalid/expired/wrong-subject inputs, API-role filtering and provider failures; ensure no token/secret leaves the adapter through results or errors. Integrate test/static commands and run the full suites. Role authorization follows in the action policy.
- [x] Add isolated Keycloak integration fixture with ephemeral credentials, loopback-only ports and cleanup. Execute it where a container daemon is available; record unavailable environment as missing evidence, not a passing integration.
- [x] Document configuration and claim mapping, update G2 readiness, perform fresh-context review and regression fixes. Continue to persistent deny-by-default action authorization and approval binding; this adapter alone does not complete G2.

Ruling: use one pinned Keycloak issuer and confidential introspection with no active-token cache for the first organization profile. Cost: provider availability/latency is on the authorization path; workload tests must measure it.
Ruling: keep real-world capacity and pilot sign-off open until an operator supplies/accepts workload targets. Synthetic tests do not substitute for that acceptance.

## Execution record

Pinned `jose` 6.2.12 (MIT, upstream panva/jose, no transitive runtime dependencies or lifecycle scripts) with npm integrity verification. `npm audit --audit-level=high` reports zero vulnerabilities. The adapter is strict-JSDoc checked, and initial tests were observed failing before implementation. Thirty focused tests now pass, including RSA-signed tokens, unknown/rotated JWKS keys, provider timeout/redirect/body bounds, active introspection, mappings and credential lifecycle.

Fresh review found token release/expiration cleanup missing, optional `nbf` validation incomplete, flaky 200ms normal fixture timeouts and swallowed Docker cleanup errors. Token release and invalid timestamp regressions failed before fixes and now pass; release during asynchronous revalidation is also covered. Normal test deadlines now use 3 seconds with a separate 100ms timeout case. Container cleanup failures are surfaced instead of reporting success.

Ruling: treat the review's timestamp, fixture reliability and cleanup findings as required quality fixes for this production-bound adapter, despite their low security severity — they affect the declared contract and trustworthy CI evidence — cost: slightly larger validation/lifecycle API and test surface.

Early provider runs exposed slow cold startup on the heavily loaded Docker Desktop host and a real configuration defect: Keycloak 26.8.0 requires the introspection client in the token audience. The fixture originally mapped only the API audience. Configure both audiences, retain provider enforcement and reject missing introspection audiences locally. The new regression failed before the adapter check and passes after it. No validation bypass was enabled.

Final provider evidence: `npm run test:keycloak` exited 0 against pinned Keycloak 26.8.0, verifying real JWT/JWKS, subject/entity/key mapping, API roles, confidential introspection and immediate denial after access-token revocation. Owned containers and temporary credentials were cleaned up. The cold-start deadline is bounded at 15 minutes; production request deadlines remain unchanged. This development fixture is not a production deployment.

Authentication now has 31 unit tests. The combined organization unit suite (auth, policy, authorization composition and store regressions) passed 59 tests; strict organization checking passed. The existing relay/tools suite passed all 365 tests, and npm audit reports zero vulnerabilities. Dedicated Node 22/Linux CI jobs now include the provider and PostgreSQL fixtures; configuring those jobs is not evidence that remote CI has run.
