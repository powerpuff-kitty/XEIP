import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const fixture = name => JSON.parse(readFileSync(new URL("../conformance/fixtures/" + name, import.meta.url), "utf8"));
const schema = name => JSON.parse(readFileSync(new URL("../schemas/" + name + ".schema.json", import.meta.url), "utf8"));

for (const name of ["entity", "message", "session", "capability"]) {
  const s = schema(name);
  assert.equal(s.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(s.type, "object");
  assert.ok(Array.isArray(s.required));
}
const entity = fixture("entity.valid.json");
const message = fixture("message.valid.json");
const session = fixture("session.valid.json");
const invalid = fixture("message.invalid-version.json");

assert.equal(entity.xeip, "0.1");
assert.ok(entity.kinds.includes("machine"));
assert.ok(entity.endpoints.length);
assert.equal(message.xeip, "0.1");
assert.ok(message.id.includes(":"));
assert.equal(message.body.contentType, "text/plain");
assert.ok(message.timestamp.endsWith("Z"));
assert.equal(session.mode, "group");
assert.ok(session.members.length >= 2);
assert.notEqual(invalid.xeip, "0.1");
console.log("XEIP fixtures and schema documents: basic consistency checks passed (NOT full JSON Schema validation)");
