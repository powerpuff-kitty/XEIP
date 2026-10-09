# Protocol implementation decisions

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-local-admission.md) | Accepted for local prototype | Opt-in credential binding and session admission |
| [0002](0002-local-replay-window.md) | Accepted for local prototype | Bounded suppression of authenticated retries |
| [0003](0003-local-delivery-resume.md) | Accepted for local prototype | Bounded per-session sequencing and reconnect resume |
| [0004](0004-verifiable-identity.md) | Proposed (design only) | Verifiable entity identity and per-entity authentication |
| [0005](0005-local-receipts.md) | Proposed (design only) | Bounded per-principal recipient receipts |

Records preserve rationale; profile specifications describe current wire/API behavior. Future production identity and admission decisions must address the remaining requirements in `spec/security.md`.
