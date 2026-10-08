# HTTP + SSE development transport — XEIP draft 0.1

**Experimental reference transport only.** Intended for loopback demonstrations, not untrusted or public deployment.

- `GET /health`: returns JSON health status.
- `GET /events?session=<encoded-session-URI>`: sends a text/event-stream. Header `Authorization: Bearer <XEIP_DEV_TOKEN>` required. Send via `fetch()`; standard `EventSource` does not allow custom bearer headers.
- `POST /messages`: accepts a JSON XEIP message, requires the same bearer token, validates its basic structure and broadcasts to current subscribers for that session.
- SSE event type is `xeip.message`. Each data line is a JSON envelope. Heartbeat lines begin with `:`.
- Accepted messages return HTTP 202 and JSON `{ accepted: true, delivered: number }`. This only counts **writes to active SSE connections**, not consumption or durability.

Restrictions: local loopback bind, request-body limit, no store-and-forward, no independent sender authentication, no verified session membership, no offline queues, no federation, no E2EE, and no per-entity permissions. For production, use authenticated identities, session admission, transport encryption and replay protection.
