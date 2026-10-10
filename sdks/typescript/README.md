# @xeip/protocol — experimental TypeScript SDK

A zero-runtime-dependency reference client and model validator for XEIP 0.1. Works with modern browser/Node fetch and Web Streams. **Not published or production-ready**; authorization stays out of scope, and the optional cryptographic identity profiles are portable reference implementations, not an audited identity stack.

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

`acknowledge(session, target, signal?)` requires the optional [local-receipts profile](../../spec/local-receipts.md) and POSTs to `/receipts`, requiring HTTP 202 and `{ acknowledged: true, session, seq, duplicate }`. The `target` MUST carry at least one selector: `seq` (a non-negative safe integer) and/or `id` (a URI); the optional `status` is only `"received"`. Unknown target keys, a missing selector, a malformed `seq`/`id`/`status`, or a malformed acceptance are rejected. `duplicate: true` means the relay already remembered an identical receipt and recorded nothing new; a receipt is advisory, in-memory and never an acknowledgment of processing or of a transport write.

URI selectors are compared exactly by the relay. Session descriptors are declarations; model validation does not authorize members or deduplicate repeated IDs. Relay admission/replay are separate opt-in profiles. See [../../spec/core.md](../../spec/core.md) for correlation, timestamps and JSON interoperability limits.

`assertEnvelope`, `assertEntity`, `assertSession`, and `assertCapability` reject malformed versions, URIs, UTC timestamps, duplicate kinds/members, invalid enum values, extra fields, and schema length violations. JSON body data and extensions must contain finite JSON values without cycles. Validation checks wire structure, not identity or authorization.

The incremental SSE parser supports LF, CRLF, and CR across arbitrary chunk boundaries, including split UTF-8 characters. Each unfinished frame is limited to 128 Ki UTF-16 code units; exceeding the limit closes iteration with an error. This is not a production messaging transport.

## Detached signed envelopes (`xeip.local-signed-envelopes/0.1`)

The SDK also ships a portable, dependency-free implementation of the detached Ed25519 signed-envelope profile in [`src/identity.ts`](src/identity.ts), matching [`tools/signed-envelope.mjs`](../../tools/signed-envelope.mjs) byte-for-byte over the shared vectors in [`conformance/fixtures/identity-signed/`](../../conformance/fixtures/identity-signed/signed.vectors.json). It uses only WebCrypto (`crypto.subtle`) and plain JavaScript, so JS/Node, Rust and TypeScript consume the same conformance vectors.

```js
import { signEnvelope, verifySignedEnvelope, encodeKeyId } from "./sdks/typescript/dist/index.js";

// Sign: the input is UTF-8(RFC 8785(envelope without extensions)).
const signed = await signEnvelope(message, { privateKey: seed32Bytes, kid });
// `signed.extensions["xeip.sig"] = { v: "0.1", alg: "EdDSA", kid, sig }`

// Verify: accepts a JSON string (strict pre-parse gate) or a parsed object.
const result = await verifySignedEnvelope(json); // { valid: true }
// or { valid: false, reason: "..." }
```

- `signEnvelope(envelope, { privateKey, kid })` — Ed25519-signs the canonical bytes with WebCrypto and returns a shallow copy with `extensions["xeip.sig"]` set. `privateKey` is a 32-byte seed (`Uint8Array`/`ArrayBuffer`), an Ed25519 private `CryptoKey`, or a PKCS#8 DER key. Sender binding is not enforced here.
- `verifySignedEnvelope(envelope)` — async, never throws; returns `{ valid: true }` or `{ valid: false, reason }` with the reference reasons: `malformed envelope`, `missing signature`, `malformed signature`, `unsupported algorithm`, `sender binding`, `signature mismatch`. Given a string it applies the strict pre-parse gate (rejects duplicate keys, lone surrogates, non-finite and unsafe integers); given an object it skips that gate. It enforces `entityUrn(kid) === envelope.sender` and derives the key from `kid` only.
- `canonicalize(value)` — RFC 8785 JCS string.
- `encodeKeyId` / `decodeKeyId` — `z`+base58btc `ed25519-pub` (`0xed01`) key-id codec; `entityUrn` / `deviceUrn` expand it.
- `strictParse(json)` — the strict pre-parse gate; `bytesToBase64Url` / `base64UrlToBytes` handle canonical unpadded base64url; `base58btcEncode` / `base58btcDecode` are the base conversion helpers; constants `SIG_EXTENSION`, `SIG_VERSION`, `SIG_ALG`, `ED25519_SIGNATURE_LENGTH`.

**WebCrypto caveat.** Signing and verification require a runtime with Ed25519 in WebCrypto (`crypto.subtle`): Node.js ≥22 (as declared in the monorepo `engines`) and current evergreen browsers. Runtimes whose WebCrypto lacks Ed25519 reject `importKey`/`sign`/`verify`; the signing and key-id helpers remain usable, but the identity test will fail. A pre-parsed envelope object bypasses the strict pre-parse gate, so callers that require it must pass JSON text.

The identity implementation also exposes `ed25519PrivateKeyFromSeed(seed)` for importing a seed as a non-extractable WebCrypto signing key.

## Identity key lifecycle (`xeip.keydoc/0.1` and `xeip.status/0.1`)

The SDK also ships a portable, dependency-free implementation of the signed key-document and identity-status profiles in [`src/keydoc.ts`](src/keydoc.ts), reproducing the grammar, verification order and stable reason strings of [`tools/key-document.mjs`](../../tools/key-document.mjs) and [`tools/identity-status.mjs`](../../tools/identity-status.mjs) over the shared vectors in [`conformance/fixtures/identity-keydoc/`](../../conformance/fixtures/identity-keydoc/keydoc.vectors.json) and [`identity-status/`](../../conformance/fixtures/identity-status/status.vectors.json). It reuses the `identity.ts` JCS canonicalization, key-id codec, strict pre-parse gate, weak-key blacklist and Ed25519 WebCrypto primitive; SHA-256 linking uses `crypto.subtle.digest`.

```js
import {
  verifyKeyDocument,
  verifyStatusDocument,
  KeyDocumentChain,
  KeyDocumentTrust,
  StatusTracker,
  entityUrn,
} from "./sdks/typescript/dist/index.js";

// Single signed key document (JSON text or a parsed object).
await verifyKeyDocument(json); // { valid: true } | { valid: false, reason }

// Generation linking, rollback/fork detection.
const chain = new KeyDocumentChain();
await chain.ingest(genesis); // { valid: true }
await chain.ingest(rotation); // { valid: false, reason: "chain gap" }

// Anchor resolution (pinned or bounded, unverified TOFU).
const trust = new KeyDocumentTrust({
  entity: entityUrn(genesisKid),
  anchor: { genesisKid, genesisDigest },
  maxGeneration: 3,
});
await trust.ingest(genesis); // { valid: true, trust: "pinned" }

// Single signed status document against a trusted key document.
await verifyStatusDocument(status, trustedKeydoc); // { valid: true } | { valid: false, reason }

// Serial rollback and staleness.
const tracker = new StatusTracker();
await tracker.ingest(status, { trustedKeyDocument: trustedKeydoc, now, maxAgeSeconds: 604800 });
tracker.isRevoked(entity, kid, generation);
```

- `verifyKeyDocument(doc)` — async, never throws; strict structural validation, `entity == entityUrn(genesis)`, non-weak root/device kids and at least one valid Ed25519 root signature. Reasons: `malformed document`, `unknown field`, `unsupported version`, `entity binding`, `weak key`, `unknown signer`, `signature mismatch`.
- `signKeyDocument(doc, { privateKey, kid })` / `signStatusDocument(doc, { privateKey, kid })` — Ed25519-sign the document without its `signatures` member and append `{ kid, sig }`; `privateKey` is a 32-byte seed (`Uint8Array`/`ArrayBuffer`) or an Ed25519 private `CryptoKey`.
- `KeyDocumentChain.ingest(doc)` — single-document verification first, then generation linking, `previous == keyDocumentChainDigest(predecessor)` and retiry authorization (a signature by a key in the predecessor's root set); adds `rollback`, `fork`, `chain gap`, `root rotation not dual-signed`. `clone()` copies the accepted per-entity state.
- `KeyDocumentTrust` — `new KeyDocumentTrust({ entity, anchor?, maxGeneration?, tofu? })`; fails closed (`no anchor`), and adds `untrusted anchor` and `generation exceeds maximum`. A `{ valid: true, trust: "tofu" }` result is **not verified identity**.
- `verifyStatusDocument(status, trustedKeyDoc, options?)` — async; the `entity` must equal the trusted key document's `entity`, and at least one signature must be by a current root. The optional `options` argument is reserved; stateless verification ignores it. Reasons: the shared structural set plus `unknown signer`.
- `StatusTracker.ingest(status, { trustedKeyDocument, now?, maxAgeSeconds? })` — adds `serial rollback` (a serial at or below the accepted one) and `stale status` (older than `maxAgeSeconds`, when supplied). `isRevoked(entity, kid, generation)` applies a revoked entry to its generation and later; a missing status is reported as not revoked (unknown, never proof of life).
- `keyDocumentSigningInput` / `statusSigningInput` (canonical string without `signatures`), `keyDocumentDigest` (SHA-256 of the signing input) and `keyDocumentChainDigest` (SHA-256 of the full signed document, the `previous` link), plus the `KEYDOC_REASONS` / `STATUS_REASONS` tables.

**WebCrypto caveat.** Every operation that hashes or verifies is `async` because it uses `crypto.subtle`; the Node reference is synchronous. Ed25519 and SHA-256 are required (Node.js ≥22 and current evergreen browsers). Runtimes whose WebCrypto lacks Ed25519 reject key import/sign/verify; the key-id and canonicalization helpers still work, but the keydoc test will fail.

