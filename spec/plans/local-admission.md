# Local admission implementation checkpoints

Scope: implement ADR 0001 as a loopback-only, opt-in authorization profile for the existing relay. Preserve all existing 0.1 fixtures and shared-token behavior. Do not add a public administration endpoint or invent cryptography.

1. Write the separately versioned profile contract: credential provisioning/binding, closed memberships, subscription/message authorization, generic denial behavior, revocation/rotation, resource bounds and assumptions. Verify it agrees with the current envelope/session schemas and the ADR.
2. Add a policy module with private credential/session state, validated input snapshots, deny-by-default authorization and administrator-only mutation methods. Tests must cover invalid/ambiguous provisioning, stale authentication records, atomic invalid updates and caller mutation isolation.
3. Connect the policy to the existing relay's authentication, subscription and POST paths. Recheck authenticated records after body reads; derive routing entities from credentials; close invalidated streams. Real HTTP tests must reject spoofing, wrong subscriptions, unauthorized sessions/recipients, and revoked reconnects. Preserve shared-token regression checks.
4. Exercise TypeScript and Rust peers with separate credentials in the same real transport harness. Add a standalone simulated admission demo with ephemeral credentials and no token output. Verify both supported Rust toolchains and Node 22.
5. Request read-only review of policy, races, stream cleanup and documentation. Fix all important findings; update roadmap/security truth with exact implemented scope and remaining production controls.

Rollback: remove use of the admission option and run the explicit shared-token development profile. Do not silently fall back on an authorization failure. Policy state is in memory and has no migration or persistent data to roll back.

Done means the new profile and old profile both pass their positive/negative transport checks, revocation stops new writes/reconnects, copied inputs cannot bypass policy, the demo cleans up its processes/streams, and documentation does not claim portable identities or production security. Issue 1 remains incomplete until its full identity, trust-root, adapter and recovery criteria are satisfied.

Execution result, 2026-10-09: all five checkpoints implemented locally. Node 22 passes 153 combined relay/schema/SDK tests, including 17 admission tests. Rust 1.81.0 and 1.94.1 each pass 13 core/example tests and 17 real HTTP/SSE interoperability tests. JSON Schema validation passes five fixtures and 100 vectors; TypeScript typecheck/build, Clippy with warnings denied, both simulated demos and relative documentation links pass. CI includes the admission demo and both credential modes in interoperability.

Read-only review found two native embedding lifecycle defects, both fixed with failing-then-passing HTTP regressions: throwing owner observers must not prevent relay cleanup, and closing/reusing a server must reattach its policy observer. The copied descriptor is also revalidated after serialization hooks. Final review reports no remaining findings in this slice. The work is committed as an experimental prototype; no release, deployment or issue closure is implied.
