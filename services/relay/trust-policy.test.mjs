import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { createRelayCore } from "./relay-core.mjs";
import { encodeKeyId, entityUrn } from "../../tools/derive-keyid.mjs";
import { ed25519PrivateKeyFromSeed, signEnvelope } from "../../tools/signed-envelope.mjs";
import { signKeyDocument } from "../../tools/key-document.mjs";
import { signStatusDocument } from "../../tools/identity-status.mjs";

const vectors = JSON.parse(readFileSync(new URL("../../conformance/fixtures/identity-status/status.vectors.json", import.meta.url)));
const trusted = vectors.trusted["keydoc.entity"];
const root = ed25519PrivateKeyFromSeed(Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"));
const device = ed25519PrivateKeyFromSeed(Buffer.from("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f", "hex"));
const at = Date.parse("2026-10-10T00:00:00Z");
const token = "trust-policy-test-token";
const keyEntry = document => ({ document, anchor: { genesisKid: document.genesis } });
const status = (patch = {}) => signStatusDocument({ ...vectors.statuses["status.revoke.1"], ...patch },
  { privateKey: root, kid: trusted.genesis });
const coreFor = (statusDocuments, keyDocuments = [keyEntry(trusted)]) => createRelayCore({ token, signatures: {}, keyDocuments, statusDocuments });
const message = (privateKey = root, kid = trusted.genesis) => signEnvelope({ xeip: "0.1", id: "urn:test:message", kind: "message",
  sender: entityUrn(kid), session: "urn:test:session", timestamp: "2026-10-10T00:00:00Z",
  body: { contentType: "text/plain", data: "test" } }, { privateKey, kid });
const send = (core, raw = message()) => core.routeMessage(core.authenticate("Bearer " + token), raw);

test("configured status age is checked on each send and clock rollback cannot revive it", t => {
  let now = at;
  t.mock.method(Date, "now", () => now);
  const core = coreFor([{ document: status(), maxAgeSeconds: 1 }]);
  assert.equal(send(core).status, 202);
  now += 1000;
  assert.equal(send(core).status, 202);
  now += 1;
  assert.equal(send(core).status, 403);
  now = at;
  assert.equal(send(core).status, 403);
});

test("enabled status policy denies an endorsed key whose entity has no status", () => {
  const key = ed25519PrivateKeyFromSeed(Buffer.alloc(32, 7));
  const kid = encodeKeyId(createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32));
  const other = signKeyDocument({ ...trusted, entity: entityUrn(kid), genesis: kid, roots: [kid], devices: [] },
    { privateKey: key, kid });
  const core = coreFor([{ document: status() }], [keyEntry(trusted), keyEntry(other)]);
  assert.equal(send(core, message(key, kid)).status, 403);
});

test("mutating provisioning objects cannot erase an accepted revocation", () => {
  const document = status();
  const core = coreFor([{ document }]);
  const raw = message(device, trusted.devices[0]);
  assert.equal(send(core, raw).status, 403);
  document.revoked.length = 0;
  assert.equal(send(core, raw).status, 403);
});

test("a future status is not evidence of a currently live key", t => {
  t.mock.method(Date, "now", () => at);
  const core = coreFor([{ document: status({ issuedAt: "2026-10-10T00:00:01Z" }), maxAgeSeconds: 60 }]);
  assert.equal(send(core).status, 403);
});

test("invalid status issuance cannot disable freshness comparisons", () => {
  assert.throws(() => coreFor([{ document: status({ issuedAt: "2026-99-99T00:00:00Z" }), maxAgeSeconds: 60 }]), /issuance/);
});
