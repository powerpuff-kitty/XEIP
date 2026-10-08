# @xeip/protocol — experimental TypeScript SDK

A zero-runtime-dependency reference client and model validator for XEIP 0.1. Works with modern browser/Node fetch and Web Streams. **Not published or production-ready**; does not implement cryptographic identity or authorization.

From repository root:

```sh
npm ci --ignore-scripts
npm run build:ts
npm run test:ts
```

```js
import { XeipHttpSseClient, makeMessage } from "./sdks/typescript/dist/index.js";
const client = new XeipHttpSseClient({
  baseUrl: "http://127.0.0.1:8787",
  token: process.env.XEIP_DEV_TOKEN
});
const message = makeMessage({
  kind: "message",
  sender: "urn:xeip:entity:human-01",
  recipient: "urn:xeip:entity:agent-01",
  session: "urn:xeip:session:demo",
  body: { contentType: "text/plain", data: "Hello" }
});
await client.send(message);
```

`events(session, entity, signal?, after?)` requires HTTP 200 and is an async iterator over validated XEIP envelopes delivered by the development SSE relay. The entity selector is required. Establish subscribers before sending messages. When the optional [local delivery profile](../../spec/local-delivery.md) is enabled, pass `after` to resume from a sequence within the relay's bounded in-memory window; there is no durable replay, and a cursor older than the window yields a gap rather than silent loss. Pass an abort signal to close a subscription, or end iteration to cancel the stream.

`send(message)` returns `SendAcceptance`, requiring HTTP 202 and `{ accepted: true, delivered: <nonnegative safe integer> }`. The count includes writes to individual active streams, not verified recipient consumption; zero is a valid result. If the optional [local replay profile](../../spec/local-replay.md) is selected by the relay, the SDK preserves its `duplicate` boolean; true requires zero new writes. If the optional [local delivery profile](../../spec/local-delivery.md) is selected, the SDK preserves its per-session `seq`. A malformed flag, sequence or inconsistent count is rejected. There is no automatic POST retry: an explicit retry must reuse the unchanged envelope and stay within the selected profile's current instance/window. 409/503 responses remain HTTP errors, not successful acceptances.

URI selectors are compared exactly by the relay. Session descriptors are declarations; model validation does not authorize members or deduplicate repeated IDs. Relay admission/replay are separate opt-in profiles. See [../../spec/core.md](../../spec/core.md) for correlation, timestamps and JSON interoperability limits.

`assertEnvelope`, `assertEntity`, `assertSession`, and `assertCapability` reject malformed versions, URIs, UTC timestamps, duplicate kinds/members, invalid enum values, extra fields, and schema length violations. JSON body data and extensions must contain finite JSON values without cycles. Validation checks wire structure, not identity or authorization.

The incremental SSE parser supports LF, CRLF, and CR across arbitrary chunk boundaries, including split UTF-8 characters. Each unfinished frame is limited to 128 Ki UTF-16 code units; exceeding the limit closes iteration with an error. This is not a production messaging transport.
