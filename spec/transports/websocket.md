# WebSocket development transport — XEIP draft 0.1

**Experimental reference transport only.** Intended for loopback demonstrations, not untrusted or public deployment. It carries the same XEIP 0.1 envelopes as [HTTP + SSE](http-sse.md) and reuses the same validation, admission and optional [local replay](../local-replay.md) path; it is an additional transport, not a separate protocol version.

The reference implementation is a dependency-free server role in `services/relay/websocket.mjs`, exercised by `services/relay/websocket.test.mjs`. It is a partial slice of issue #7: reconnect/resume, a Rust client adapter, compression and production hardening are **not** implemented.

## Endpoint and handshake

- `GET /ws` with `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13` and a valid `Sec-WebSocket-Key` (16 random bytes, base64). The server replies `101 Switching Protocols` with the RFC 6455 `Sec-WebSocket-Accept`.
- The same authority and browser gates as HTTP apply before the upgrade: a loopback socket peer, exactly one literal loopback `Host`, and an `Origin` (when present) exactly equal to the serialized `http://` origin of the `Host`. Failures return an ordinary HTTP error response and close the socket.
- `Authorization: Bearer <credential>` is required on the upgrade request. Admission mode uses provisioned entity credentials; shared-token mode uses `XEIP_DEV_TOKEN`. A browser `WebSocket` cannot set an `Authorization` header, so browser clients are not supported without a future authenticated subprotocol; native clients are.
- No subprotocol is negotiated. An upgrade to any other path returns `404`; a malformed upgrade returns `400`.

## Control protocol

Every data frame is a masked client / unmasked server **text** frame containing one JSON object. Envelopes are enclosed, never redefined.

Client → server:

- `{ "type": "subscribe", "session": "<session-URI>", "entity": "<entity-URI>" }` — both selectors required. Admission mode requires the entity to equal the authenticated principal and the session to admit it. Success replies `{ "type": "subscribed", "session": "..." }`. Re-subscribing the same session on one connection replaces the previous subscription.
- `{ "type": "send", "message": { <XEIP envelope> } }` — the envelope is validated, authorized and routed exactly as an HTTP `POST /messages` (including the optional replay profile). Success replies `{ "type": "accepted", "delivered": <integer> }` and, when the replay profile is selected, an explicit boolean `duplicate`.

Server → client:

- `{ "type": "message", "message": { <XEIP envelope> } }` — one per live delivery. This is a write to a current connection, **not** a recipient receipt.
- `{ "type": "error", "status": <HTTP-like code>, "error": "<diagnostic>" }` — the diagnostic is not a stable typed code.

An unknown `type`, a non-object frame, a non-URI selector or invalid JSON yields `400`; an invalid envelope yields `422`; a denied subscription or send yields `403`; a revoked credential yields `401` and closes the connection with code `1008`; a subscription quota denial yields `429`.

## Framing, limits and close codes

- Only text messages are supported. A binary frame closes with `1003`.
- Client frames MUST be masked; an unmasked frame closes with `1002`.
- Fragmented text messages are reassembled; a message exceeding 128 KiB closes with `1009`. Each individual frame is also bounded to 128 KiB.
- A text message that is not valid UTF-8 closes with `1007`. Control frames must be final and at most 125 bytes, and reserved bits must be clear (`1002` otherwise).
- The outbound queue per connection is bounded to 256 KiB. A write that would exceed it closes the connection with `1013` and does not block other subscribers.
- The server sends a protocol ping every 15 seconds. Two consecutive missed pongs close the connection with `1013`.
- Close codes: `1000` normal, `1002` protocol error, `1003` unsupported data, `1007` invalid payload, `1008` policy violation, `1009` message too big, `1013` try again later.

## Delivery, authorization and resource notes

- Routing, replay equality, expiry and admission are the transport-independent path shared with HTTP; see [http-sse.md](http-sse.md) for acceptance-versus-acknowledgment and expiry semantics.
- `delivered` counts writes to active WebSocket **and** HTTP/SSE subscribers of the session, because both transports share one routing table. A single POST or `send` can therefore deliver to a mix of transports.
- Admission subscription quotas (total and per-entity) are shared across transports.
- No offline queue, resume cursor, ordering guarantee, federation, TLS or end-to-end encryption is provided. Encryption and identity verification remain required for production.

Remaining risks and the reviewed controls are recorded in [../threat-model.md](../threat-model.md).
