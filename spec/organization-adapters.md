# Organization adapter boundaries

Status: implementation refactor; the PostgreSQL/Keycloak/MCP production candidate remains the only composed organization runtime. Related: [service](organization-service.md), [actions](organization-actions.md), [Cloudflare exploration](audits/2026-10-11-cloudflare-feasibility.md).

The signed controller currently imports `StoreConflict` from `store.mjs`, which imports and reads PostgreSQL migration files during module evaluation. The generic execution coordinator imports `ConnectorFailure` from `mcp.mjs`, loading the MCP implementation merely to classify an error. Those dependencies prevent reuse with another adapter even though the controller already accepts a store factory and the executor accepts a connector.

Move the three shared error classes into `errors.mjs`. Preserve their constructors, names, messages and `sent` property, and re-export the same class objects from their existing modules. Domain-error identity must stay compatible across existing callers; duplicate classes would turn conflicts into unavailable responses or pre-send failures into indeterminate effects.

Define type-only contracts in `contracts.d.ts` for the immutable organization principal, authentication, live authorization context, action inspection/record/claim, action ledger and effect connector. These describe the existing behavior and are structurally implemented by the existing adapters. Controller and executor types must no longer refer to concrete PostgreSQL or MCP classes. Keep implementation-only database rows and SQL types in `store.mjs`.

The contracts preserve these obligations:

- Authenticate explicitly; revalidate at use time and release request-local bearer authority.
- Commit each action mutation and its audit atomically; late live authorization and policy checks precede commit.
- Inspection returns no execution capability. Only a newly committed claim can initiate an effect; ambiguity never authorizes a retry.
- The connector must call the supplied guard immediately before its effect and never retry an uncertain effect automatically.
- Internal finish records the outcome even if caller authority expires/disconnects; repeated finish must match the immutable outcome/result.

No SQL, wire format, policy, deadline, cryptography, HTTP mapping or effect ordering changes are part of this refactor. No new storage provider or authentication choice is introduced. Cloudflare remains a proposed design.

Verify that importing the real controller and executor works when database/migration/POSIX filesystem and MCP adapter imports are prohibited. Existing behavior tests must still exercise the old exports through the new controller/executor consumers. Strict checking must validate the adapters against their contracts. The explicit container file list must include the new runtime error module, and the rebuilt artifact must pass its actual isolated smoke checks.
