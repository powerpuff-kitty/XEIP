# Entity-bound signed envelopes — xeip.entity-signed-envelopes/0.2

Experimental opt-in successor to the local 0.1 signing profile, accepted for implementation by the user's continuation of the identity/signing plan. Not a production security certification. [ADR 0011](decisions/0011-entity-signed-envelopes.md) records the decision.

## Wire contract

Base envelopes remain `xeip: "0.1"`. `extensions["xeip.sig"]` is exactly `{ v: "0.2", alg: "EdDSA", kid, crit, sig }`. `crit` is a unique array of extension names; each must exist, must not be `xeip.sig`, and must be explicitly understood by the verifier. Unknown noncritical extensions are allowed and authenticated. Unknown carrier members, malformed keys/signatures and other carrier versions are rejected. No automatic downgrade or unsigned fallback is permitted.

Signing bytes are UTF-8 of `XEIP entity-bound envelope v0.2\n` followed by RFC 8785 canonical JSON of `{ envelope, proof }`. Here `envelope` is the complete base envelope with only the `xeip.sig` extension removed (an empty extensions object remains); `proof` is `{ v, alg, kid, crit }`. Thus all application extensions and carrier metadata are authenticated. No new cryptographic algorithm is introduced: use existing Ed25519 implementations, key encoding, strict JSON parsing, weak-key rejection and canonicalization.

## Trust contract

Verification requires a complete ordered key-document chain from generation 1, an explicit nonempty genesis key/digest anchor, one signed current status document, a reference time `nowSeconds`, and `maxAgeSeconds` (integer 1–86400). Documents and `nowSeconds` use nonnegative epoch seconds; document timestamps must be real whole-second UTC instants. Every chain document must belong to `sender`, pass anchored chain verification and not be future-issued. The signature key must appear in the latest root/device set. The current status must be signed by a current root, belong to the same entity, not be future-issued or older than the age bound, and not list the signing key as revoked. Revocation is conservative across generations; removing a device immediately removes authorization. Root overlap is not enabled in this profile.

Stateless JS/TS/Rust verification validates the supplied chain and current status but cannot remember earlier observations. The relay additionally requires a persistent checkpoint before serving. It records each entity's anchor, highest generation plus document digest, and highest status serial plus status digest. A lower generation/serial or different content at the same counter fails startup. Every newer chain must contain the exact checkpointed document at the previously accepted generation; a higher tip cannot conceal an earlier fork. Omitted entities retain their checkpoint, so later re-enrollment cannot silently reset trust. The relay uses the maximum previously observed time within its process.

## Relay selection and migration

Use `entitySignatures: { trustDir, maxAgeSeconds, knownExtensions?: string[] }` with local admission, `keyDocuments` and `statusDocuments`. This option is mutually exclusive with legacy `signatures`. Provision key-document entries as `{ document, anchor? }`, with a mandatory anchor on the entity's first entry. Supply exactly one `{ document }` status entry per provisioned entity. Never accept an unanchored/TOFU identity. The local relay remains loopback-only.

A new `trustDir` is initialized once. An existing directory must contain a valid checkpoint; missing/corrupt state fails closed. An exclusive lock prevents concurrent writers; atomic replacement and file/directory sync precede serving. A failed write aborts startup and preserves recovery evidence. Newer verified provisioning advances checkpoints at restart or through the trusted owner API `server.updateEntityTrust({ keyDocuments, statusDocuments })`; replaying older provisioning fails. No network refresh endpoint, anchor-reset command, public discovery or private-key storage is added. A stale status denies activity and closes streams until fresh provisioning is supplied. See [live-entity-trust.md](live-entity-trust.md) for atomic updates and failure behavior.

Migration is explicit per relay/client configuration. Old 0.1 signatures remain unchanged and cannot verify under 0.2. In this experimental profile, local credentials must bind both the stable entity and its canonical `kid`; device signatures must use that same key and authorize the entity through its pinned current chain. Legacy credential profiles remain unchanged.

## Threat model and residual risk

| Threat | Control / required negative test |
| --- | --- |
| Device impersonates unrelated entity | Sender-bound anchored chain and current key membership |
| Extension/critical flag tampering | Entire payload and proof are signed |
| Removed/revoked device or stale status | Current membership, root-signed fresh status, per-send verification |
| Restart rollback or same-counter fork | Persisted counters and content digests checked before serving |
| Downgrade / parser ambiguity | Explicit profile; strict JSON and exact carrier; no fallback |
| Lost checkpoint / concurrent writer / I/O failure | Refuse startup, exclusive ownership, durable atomic replacement |

The operator and local filesystem are trusted. A hostile operator or whole-disk snapshot rollback can replace both checkpoint and configuration; local state alone cannot detect that attack. Backup rollback requires a deliberate trust-recovery procedure outside this profile. Status distribution and operator identity-provider/action authorization remain separate gates. Envelope replay still needs the replay profile and application idempotency. No encryption or exactly-once execution is promised. Independent cryptographic review, production filesystem certification, automated status distribution and certified recovery remain required before production designation.

## Local integration and operation

The relay is configured through its programmatic API; the shared-token CLI does not enable this profile.

```js
import { createRelay } from "../services/relay/server.mjs";
import { LocalAdmission } from "../services/relay/admission.mjs";

const server = createRelay({
  admission: new LocalAdmission({ credentials, sessions }),
  entitySignatures: {
    trustDir: "/private/xeip/trust",
    maxAgeSeconds: 60,
    knownExtensions: ["app.action"]
  },
  keyDocuments: [
    { document: genesisDocument, anchor: { genesisKid: pinnedGenesisKeyId } },
    ...laterDocuments.map(document => ({ document }))
  ],
  statusDocuments: [{ document: freshRootSignedStatus }]
});
server.listen(8787, "127.0.0.1");
```

Credentials use `{ entity, token, kid }` to bind the stable parent entity and signing key; sessions explicitly list members. `admission.rotateCredential(entity, newToken)` preserves the key, while an explicit third argument `{ kid: newKid }` changes it. Populate the documents and pins through trusted provisioning; do not use test fixture keys for real identities. Only list extensions the application understands; signing an `approved` field does not grant permission to execute an action.

At startup the relay validates all provisioning, checks prior trust history, durably checkpoints it, then can begin listening. Each send passes local admission, signature/trust verification and the selected replay/delivery policies. Trust failures return 403; malformed or invalid signatures return 422. HTTP and WebSocket share enforcement. Successful transport acceptance is not proof of execution.

For a status update, obtain a newer current-root-signed status with an increasing serial and call `server.updateEntityTrust({ keyDocuments, statusDocuments })` with the complete active provisioning. Restart with the same or newer provisioning remains supported. A key update supplies the complete chain extending the accepted tip, together with a status signed by a current root. Confirm aggregate trust health and exercise an allowed and denied send after updating. Revoked, removed or stale bound keys cannot reconnect, subscribe, acknowledge or send. Idle WebSockets and SSE streams are swept every second while the event loop runs. Checkpoint advancement is durable even if later relay initialization fails; retry with the same or newer provisioning.

Back up trust state together with provisioning while the relay is stopped. Missing/corrupt state, a stale lock, an anchor change or a rollback error requires investigation; deleting the directory would discard rollback protection. There is no automatic lock stealing, checkpoint reset or certified recovery workflow. An operator may remove a stale lock only after establishing that no writer owns it. Whole-filesystem rollback cannot be detected by this local checkpoint. Production backup/restore and emergency recovery drills remain release gates.
