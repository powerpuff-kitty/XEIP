# Local signed envelopes profile — xeip.local-signed-envelopes/0.1

Experimental profile for a detached Ed25519 signature over a XEIP
[envelope](core.md#5-message-envelope). It fixes the exact canonical bytes and
the carrier that binds a signature to the envelope `sender`. It is the first
verification slice of [issue #1](https://github.com/powerpuff-kitty/XEIP/issues/1).
Verification is implemented in
[`tools/signed-envelope.mjs`](../tools/signed-envelope.mjs) and is now available
as an **opt-in relay profile**: a relay constructed with `signatures: {}`
rejects envelopes that do not carry a valid, `sender`-bound signature. When the
option is absent, relay behavior is unchanged and envelopes are still accepted
on the self-asserted `sender` field. The decision is recorded in
[ADR 0009](decisions/0009-local-signed-envelopes.md).

This profile is the concrete, local analogue of the authentication profile
proposed in [identity.md](identity.md) §5 (Ed25519 + JCS + `extensions`). It
adds no dependency and no custom primitive: Ed25519 comes from Node's
OpenSSL-backed `node:crypto`, as selected in
[ADR 0007](decisions/0007-crypto-dependencies.md). It carries the unchanged
`"0.1"` envelope and does not modify any schema.

## Carrier

The signature travels in a versioned `extensions` member so a v0.1 parser keeps
rejecting unknown first-class fields:

```json
"extensions": {
  "xeip.sig": {
    "v": "0.1",
    "alg": "EdDSA",
    "kid": "<key-id>",
    "sig": "<unpadded base64url of the 64-byte Ed25519 signature>"
  }
}
```

- `v` is the carrier version (`"0.1"`).
- `alg` MUST be exactly `"EdDSA"`; `alg: "none"`, algorithm substitution and any
  other value MUST be rejected before verification.
- `kid` is the canonical key-id of §2 of [identity.md](identity.md) — the
  `z`+base58btc `ed25519-pub` (`0xed01`) encoding produced by
  [`tools/derive-keyid.mjs`](../tools/derive-keyid.mjs). A verifier derives the
  public key from `kid`; a key supplied in the header or elsewhere is never
  trusted.
- `sig` is canonical, unpadded base64url of exactly 64 bytes. Padding, invalid
  characters and non-canonical spellings are rejected.

## Signing input

The bytes signed are:

```
UTF-8( RFC8785( envelope_without_extensions ) )
```

Concretely:

1. Take the parsed envelope object and remove the `extensions` property in its
   entirety. `extensions` is **not covered by the signature**; only the other
   envelope fields are.
2. Canonicalize the remaining value with RFC 8785 (JSON Canonicalization
   Scheme): object keys sorted by UTF-16 code units, no insignificant
   whitespace, ECMAScript number formatting, strings escaped as JSON, arrays in
   order.
3. Encode the result as UTF-8 and sign those bytes with Ed25519 (RFC 8032).

The signature is therefore deterministic for a given key and envelope.

## Strict pre-parse gate

[core.md](core.md#5-message-envelope) states the JSON wire format is not a
canonical signing serialization. Before canonicalization, a signed envelope
MUST be parsed with rules stricter than `JSON.parse`, rejecting:

- duplicate object member names,
- lone (unpaired) surrogate escapes and raw lone surrogates,
- non-finite numbers (for example `1e999`),
- integers outside the interoperable ±(2^53-1) range.

No Unicode normalization is performed. A verifier MUST NOT sign or verify
"whatever a parser happened to produce". `tools/signed-envelope.mjs` exposes
`strictParse` for exactly this gate; `verifySignedEnvelope` applies it whenever
it is given JSON text. Passing an already-parsed object skips the gate, so
callers that care about the gate must hand the verifier bytes, not objects.

## Sender binding

Verification requires:

```
entityUrn(kid) === envelope.sender
```

That is, the signing key's key-id must expand to the entity URN in `sender`
using the same codec as [identity.md](identity.md) §2. A mismatch MUST be
rejected and MUST NOT be routed. This is the local, cryptographic form of the
principal-to-`sender` binding in [identity.md](identity.md) §4, generalizing the
sender-spoof denial in [local-admission.md](local-admission.md#authentication-and-authorization).
The key is always taken from `kid`; `sender` is only cross-checked against it.

## Opt-in relay enforcement

The development-only relay can enforce this profile locally. Enforcement is
**opt-in** and off by default:

```js
createRelay({ token, signatures: {} });      // shared-token mode
createRelay({ admission, signatures: {} });  // local admission mode
```

`signatures` is a bare opt-in: it MUST be an empty object. `null`, an array, a
primitive or any unknown member is a construction error, and no other profile is
required to enable it. It is orthogonal to the authentication mode, so shared
token and local admission both work; when combined with local admission **both**
the signature check and the admission check apply.

When enabled, every accepted envelope — HTTP `POST /messages` and the WebSocket
`{ "type": "send" }` control — MUST pass `verifySignedEnvelope` and the
`entityUrn(kid) === sender` binding before it is authorized, recorded or routed.
A failed envelope is never routed and never enters the replay or delivery
ledgers. Failures map to stable transport responses:

| `verifySignedEnvelope` reason | HTTP | WebSocket `type:"error"` |
| --- | --- | --- |
| `missing signature` | 422 `{"error":"invalid signature"}` | `{"status":422,"error":"invalid signature"}` |
| `malformed signature` | 422 `{"error":"invalid signature"}` | `{"status":422,"error":"invalid signature"}` |
| `unsupported algorithm` | 422 `{"error":"invalid signature"}` | `{"status":422,"error":"invalid signature"}` |
| `malformed envelope` | 422 `{"error":"invalid signature"}` | `{"status":422,"error":"invalid signature"}` |
| `signature mismatch` | 422 `{"error":"invalid signature"}` | `{"status":422,"error":"invalid signature"}` |
| `sender binding` | 403 `{"error":"forbidden"}` | `{"status":403,"error":"forbidden"}` |

Only `sender binding` is an authorization denial; every other verification
failure is reported uniformly as `invalid signature`. Connection authentication
is still ambient: in shared-token mode any holder of the token may present a
signed envelope, and in local admission mode the verified `sender` must also
equal the authenticated principal entity.

When enabled, `/health` advertises the profile as
`signatureProfile: "xeip.local-signed-envelopes/0.1"`; the field is absent
otherwise.

Enforcement is per-relay and local-only. It changes no wire format, provides no
key distribution, freshness or revocation, and does not make `extensions` —
including the signature carrier itself — part of the signed bytes.

## Verification result

`verifySignedEnvelope` returns a structured result rather than throwing, so
each failure maps to a stable reason:

| Reason | Meaning |
| --- | --- |
| `malformed envelope` | Not a JSON object, invalid JSON, or a duplicate key / surrogate / unsafe number under the strict gate |
| `missing signature` | No `extensions["xeip.sig"]` carrier |
| `malformed signature` | Carrier is not an object, `kid`/`sig` missing or wrong type, or `sig` is not canonical 64-byte base64url |
| `unsupported algorithm` | `alg` is not `EdDSA` |
| `sender binding` | `kid` is not a canonical key-id, or `entityUrn(kid) !== sender` |
| `signature mismatch` | Canonical bytes do not verify under the key in `kid` |

`{ valid: true }` is returned only when every step succeeds.

## What a signature does and does not prove

A valid signature proves only that the holder of the private key whose public
key is identified by `kid` signed **exactly** the canonical bytes of the
envelope fields other than `extensions`.

It proves:

- integrity of every signed envelope field,
- possession of the private key for the key-id in `kid`,
- the signer's claim to be the entity whose key-id is `kid`, because the
  verifier requires `entityUrn(kid) === sender`.

It does **not** prove:

- that the body is true, authorized or meaningful,
- that the entity or device is trusted, endorsed, unrevoked or current,
- that the envelope is fresh or un-replayed,
- anything about `extensions`, including whether the carrier itself is
  authentic,
- that the recipient is authorized for the session,
- non-repudiation beyond possession of the key.

## Non-goals

This profile deliberately does not define or claim:

- **Key distribution, discovery, trust roots, rotation or recovery.** A
  verifier must already know or otherwise trust that `kid` belongs to
  `sender`; this profile only proves the signature and the key-id-to-`sender`
  binding. Trust anchors and signed key documents remain
  [identity.md](identity.md) §3/§6 work.
- **Revocation or status.** A revoked key still verifies until a separate
  status check rejects it.
- **Replay or freshness.** There is no nonce, `expiresAt` bound or replay
  cache here.
- **End-to-end encryption, forward secrecy or metadata protection.** Envelope
  contents are plaintext.
- **Signing `extensions`.** Extensions, including the signature carrier
  itself, are outside the signed bytes and are not protected by the signature.
- **Mandatory or network-wide enforcement.** Only a relay explicitly
  constructed with `signatures: {}` enforces this profile, and only for the
  envelopes it accepts; it is local-only and off by default. Signing remains a
  verifier-side primitive and delivery over any other path is unchanged.

## Conformance and usage

Deterministic vectors live in
[`conformance/fixtures/identity-signed/signed.vectors.json`](../conformance/fixtures/identity-signed/signed.vectors.json)
(one positive and five negative cases). They are checked by
`node --test tools/signed-envelope.test.mjs` and by `npm run validate:fixtures`.

```sh
node tools/signed-envelope.mjs verify envelope.json   # -> {"valid":true} or {"valid":false,"reason":"..."}
node tools/signed-envelope.mjs keygen                 # -> seedHex, publicKeyHex, keyId, entityUrn
```

The JavaScript module is the reference; a Rust or TypeScript implementation
MUST produce byte-identical signing input and the same `valid`/`reason` results
for these vectors before this profile can be considered interoperable.
