# Protocol implementation decisions

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-local-admission.md) | Accepted for local prototype | Opt-in credential binding and session admission |
| [0002](0002-local-replay-window.md) | Accepted for local prototype | Bounded suppression of authenticated retries |

Records preserve rationale; profile specifications describe current wire/API behavior. Future production identity and admission decisions must address the remaining requirements in `spec/security.md`.
