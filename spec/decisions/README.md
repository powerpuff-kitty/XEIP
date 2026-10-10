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

Records preserve rationale; profile specifications describe current wire/API behavior. Future production identity and admission decisions must address the remaining requirements in `spec/security.md`.
