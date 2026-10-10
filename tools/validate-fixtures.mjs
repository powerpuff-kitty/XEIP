import { readFileSync, readdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { requireUri } from "../sdks/typescript/src/validation.js";
import { encodeKeyId, entityUrn, deviceUrn, decodeKeyId } from "./derive-keyid.mjs";
import { canonicalize, verifySignedEnvelope } from "./signed-envelope.mjs";

const readJson = path => JSON.parse(readFileSync(path, "utf8"));
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== "--fixtures-dir")) {
  throw new Error("usage: node tools/validate-fixtures.mjs [--fixtures-dir PATH]");
}
const directory = args.length ? resolve(args[1]) : fileURLToPath(new URL("../conformance/fixtures", import.meta.url));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv, { mode: "full" });
// Ajv handles schema structure and other formats independently. Its URI regex
// rejects empty paths and accepts ambiguous IPv4 forms;
// use the reference RFC 3986 syntax checker for this format. Rust checks it independently.
ajv.addFormat("uri", value => { try { requireUri(value); return true; } catch { return false; } });
// Fractional seconds have arbitrary precision on the wire. Avoid floating-point
// rounding to :60/:61 in Ajv while retaining its independent calendar/time checks.
// The schema pattern checks the original fractional digit syntax.
const dateTimeFormat = addFormats.get("date-time", "full");
ajv.addFormat("date-time", value => dateTimeFormat.validate(value.replace(/\.\d+(?=Z$)/, "")));
const validators = {};
for (const name of ["capability", "entity", "message", "session"]) {
  const schema = readJson(new URL("../schemas/" + name + ".schema.json", import.meta.url));
  ajv.addSchema(schema, name);
}
for (const name of ["capability", "entity", "message", "session"]) validators[name] = ajv.getSchema(name);

let fixtureCount = 0;
for (const filename of readdirSync(directory).filter(name => name.endsWith(".json")).sort()) {
  const match = /^(capability|entity|message|session)\.(valid|invalid(?:-[a-z0-9-]+)?)\.json$/.exec(filename);
  if (!match) throw new Error("unrecognized fixture filename: " + filename);
  const validate = validators[match[1]];
  const accepted = validate(readJson(join(directory, filename)));
  if (accepted !== (match[2] === "valid")) {
    throw new Error(filename + ": unexpected schema result: " + ajv.errorsText(validate.errors));
  }
  fixtureCount++;
}
const vectors = readJson(new URL("../conformance/vectors.json", import.meta.url));
for (const vector of vectors) {
  const value = { ...readJson(join(directory, vector.schema + ".valid.json")), ...vector.patch };
  for (const field of vector.remove ?? []) delete value[field];
  const validate = validators[vector.schema];
  if (!validate || validate(value) !== vector.valid) {
    throw new Error(vector.name + ": unexpected schema result: " + ajv.errorsText(validate?.errors));
  }
}
const keyidVectors = readJson(new URL("../conformance/fixtures/identity-keyid/identity-keyid.vectors.json", import.meta.url));
for (const vector of keyidVectors) {
  if (vector.valid === false) {
    let rejected = false;
    try { decodeKeyId(vector.keyId); } catch { rejected = true; }
    if (!rejected) throw new Error("key-id vector " + vector.name + ": expected rejection");
    continue;
  }
  const keyId = encodeKeyId(Uint8Array.from(Buffer.from(vector.publicKeyHex, "hex")));
  if (keyId !== vector.keyId || entityUrn(keyId) !== vector.entityUrn || deviceUrn(keyId) !== vector.deviceUrn) {
    throw new Error("key-id vector mismatch: " + vector.name);
  }
  decodeKeyId(keyId);
}
const signedVectors = readJson(new URL("../conformance/fixtures/identity-signed/signed.vectors.json", import.meta.url));
for (const vector of signedVectors) {
  // A vector carries either a parsed `envelope` or raw JSON `text` (which only
  // reaches the verifier through the strict pre-parse gate).
  if ((vector.envelope === undefined) === (vector.text === undefined)) {
    throw new Error("signed-envelope vector " + vector.name + ": exactly one of `envelope` or `text` is required");
  }
  const result = verifySignedEnvelope(vector.text !== undefined ? vector.text : vector.envelope);
  if (vector.valid === true) {
    if (result.valid !== true) throw new Error("signed-envelope vector " + vector.name + ": expected a valid signature");
  } else if (result.valid !== false || result.reason !== vector.reason) {
    throw new Error("signed-envelope vector " + vector.name + ": expected reason " +
      JSON.stringify(vector.reason) + " but received " + JSON.stringify(result));
  }
}
const canonicalVectors = readJson(new URL("../conformance/fixtures/identity-canonical/canonical.vectors.json", import.meta.url));
for (const vector of canonicalVectors) {
  const actual = canonicalize(JSON.parse(vector.json));
  if (actual !== vector.canonical) {
    throw new Error("canonicalization vector " + vector.name + ": expected " +
      JSON.stringify(vector.canonical) + " but received " + JSON.stringify(actual));
  }
}
console.log("XEIP JSON Schema conformance: " + fixtureCount + " fixtures and " + vectors.length +
  " vectors passed (draft 2020-12, formats enforced); " + keyidVectors.length + " key-id vectors, " +
  signedVectors.length + " signed-envelope vectors and " + canonicalVectors.length +
  " canonicalization vectors passed");
