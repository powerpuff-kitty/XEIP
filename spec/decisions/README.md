# Protocol implementation decisions

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-local-admission.md) | Accepted for local prototype | Opt-in credential binding and session admission |
| [0002](0002-local-replay-window.md) | Accepted for local prototype | Bounded suppression of authenticated retries |
| [0003](0003-local-delivery-resume.md) | Accepted for local prototype | Bounded per-session sequencing and reconnect resume |
| [0004](0004-verifiable-identity.md) | Proposed (design only) | Verifiable entity identity and per-entity authentication |
| [0005](0005-local-receipts.md) | Accepted for local prototype | Bounded per-principal recipient receipts |
| [0006](0006-durable-delivery.md) | Accepted for local prototype (first slice) | Restart-surviving bounded delivery store |
| [0007](0007-crypto-dependencies.md) | Proposed (design only) | Audited crypto library selection and dependency policy |
| [0008](0008-local-limits.md) | Accepted for local prototype | Opt-in request-rate and connection/subscription limits |
| [0009](0009-local-signed-envelopes.md) | Accepted for local prototype | Detached Ed25519 signed-envelope verification slice |
| [0010](0010-identity-key-lifecycle.md) | Proposed (design only) | Identity key documents, rotation, revocation and recovery |
| [0011](0011-entity-signed-envelopes.md) | Accepted for experimental implementation | Entity-bound signatures, protected extensions and persistent relay trust |
| [0012](0012-live-entity-trust.md) | Accepted for implementation | Atomic owner-driven trust refresh and device-bound revocation |
| [0013](0013-keycloak-authentication.md) | Accepted for implementation | Pinned Keycloak JWT verification and live confidential introspection |
| [0014](0014-organization-action-ledger.md) | Accepted for experimental implementation | Exact action approvals and transactional single-use execution claims |
| [0015](0015-signed-organization-service.md) | Accepted for experimental implementation | Signed HTTPS operations, durable results and non-retrying MCP effects |
| [0016](0016-organization-runtime.md) | Accepted for experimental implementation | Protected configuration, restricted database roles, direct TLS, drain and private metrics |
| [0017](0017-cloudflare-native-exploration.md) | Proposed (design only) | Evaluate Workers and Durable Objects while preserving authorization and recovery requirements |
| [0018](0018-postgres-control-history.md) | Accepted for local experimental implementation; pending | Retain Linux authorization history with actions and refuse stale runtime authority |

Records preserve rationale; profile specifications describe current wire/API behavior. Future production identity and admission decisions must address the remaining requirements in `spec/security.md`.
