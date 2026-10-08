# @xeip/protocol — experimental TypeScript SDK

A zero-runtime-dependency reference client and model validator for XEIP 0.1. Works with modern browser/Node fetch and Web Streams. **Not published or production-ready**; does not implement cryptographic identity or authorization.

From repository root:

```sh
npm install
npm run build:ts
npm run test:ts
```

```js
import { XeipHttpSseClient, makeMessage } from "./dist/index.js";
const client = new XeipHttpSseClient({
  baseUrl: "http://127.0.0.1:8787",
  token: process.env.XEIP_DEV_TOKEN
});
const message = makeMessage({
  sender: "urn:xeip:entity:human-01",
  recipient: "urn:xeip:entity:agent-01",
  session: "urn:xeip:session:demo",
  body: { contentType: "text/plain", data: "Hello" }
});
await client.send(message);
```

`events(session, entity?, signal?)` is an async iterator over validated XEIP envelopes delivered by the development SSE relay. Call it in the background before sending messages. This is not a production messaging transport.
