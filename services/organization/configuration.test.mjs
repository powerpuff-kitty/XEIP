import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  chmodSync,
  symlinkSync,
  mkdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import {
  loadConfiguration,
  loadOwnerConfiguration,
  ConfigurationError,
} from "./configuration.mjs";

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "xeip-config-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = (name, text, mode = 0o600) => {
    const path = join(dir, name);
    writeFileSync(path, text, { mode });
    return path;
  };
  const entity =
    "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
  const certificateFile = file(
    "cert.pem",
    readFileSync(new URL("./test-fixtures/tls/cert.pem", import.meta.url)),
    0o644,
  );
  const privateKeyFile = file(
    "key.pem",
    readFileSync(new URL("./test-fixtures/tls/key.pem", import.meta.url)),
  );
  const secretFile = file("secret", "synthetic-secret\n");
  const target = {
    id: "internal",
    revision: "1",
    recipient: entity,
    tools: ["lookup"],
    endpoint: "https://tool.test/mcp",
    resourceMetadataUrl:
      "https://tool.test/.well-known/oauth-protected-resource",
    issuer: "https://auth.test/realm",
    tokenEndpoint: "https://auth.test/token",
    clientId: "xeip",
    clientSecretFile: secretFile,
    scope: "mcp:tools",
  };
  const config = {
    version: 1,
    origin: "https://xeip.test",
    gateway: entity,
    bind: { host: "127.0.0.1", port: 8443 },
    tls: { certificateFile, privateKeyFile },
    database: {
      host: "db.test",
      port: 5432,
      name: "xeip",
      user: "xeip_runtime",
      passwordFile: secretFile,
      caFile: certificateFile,
      max: 6,
    },
    authentication: {
      issuer: "https://id.test/realms/org",
      audience: "xeip",
      clientIds: ["agent", "console"],
      bindings: ["agent", "human"].map((subject) => ({
        subject,
        entity,
        kid: entity.slice("urn:xeip:entity:".length),
      })),
      introspectionClientId: "xeip",
      introspectionClientSecretFile: secretFile,
    },
    policy: {
      targets: [
        {
          id: target.id,
          revision: target.revision,
          recipient: entity,
          tools: ["lookup"],
        },
      ],
      sessions: [
        {
          id: "urn:xeip:session:work",
          agents: ["agent"],
          approvers: ["human"],
          targets: ["internal"],
        },
      ],
    },
    targets: [target],
    trust: {
      directory: join(dir, "trust"),
      provisioningFile: file(
        "trust.json",
        JSON.stringify({ keyDocuments: [], statusDocuments: [] }),
      ),
      maxAgeSeconds: 300,
    },
    management: {
      host: "127.0.0.1",
      port: 9443,
      tokenFile: file("management", "a".repeat(48)),
    },
    shutdownMs: 30000,
  };
  const save = () => file("config.json", JSON.stringify(config));
  return { dir, file, config, save };
}
test("owner maintenance has a separate protected database configuration", (t) => {
  const f = fixture(t);
  const database = { ...f.config.database, user: "postgres" };
  const file = f.file("owner.json", JSON.stringify({ version: 1, database }));
  assert.equal(loadOwnerConfiguration(file).user, "postgres");
  assert.equal(loadOwnerConfiguration(file).ssl.rejectUnauthorized, true);
  f.config.database.user = "postgres";
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  writeFileSync(
    file,
    JSON.stringify({ version: 1, database, authentication: {} }),
  );
  assert.throws(() => loadOwnerConfiguration(file), ConfigurationError);
});
test("console is opt-in and its public client must be explicitly allowed", (t) => {
  const f = fixture(t);
  assert.equal(loadConfiguration(f.save()).console, undefined);
  f.config.console = { clientId: "console" };
  assert.equal(loadConfiguration(f.save()).console.clientId, "console");
  for (const value of [
    { clientId: "unknown" },
    { clientId: "console", secret: "never" },
    { clientId: "" },
    null,
  ]) {
    f.config.console = value;
    assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  }
});

test("loads exact protected configuration with verified database TLS and separate secret files", (t) => {
  const f = fixture(t);
  const loaded = loadConfiguration(f.save());
  assert.equal(loaded.database.password, "synthetic-secret");
  assert.equal(loaded.database.ssl.rejectUnauthorized, true);
  assert.equal(
    loaded.authentication.introspectionClientSecret,
    "synthetic-secret",
  );
  assert.equal(loaded.targets[0].clientSecret, "synthetic-secret");
  assert.equal(Object.isFrozen(loaded.targets[0]), true);
  assert.equal(loaded.tls.key.includes("PRIVATE KEY"), true);
});

for (const [label, change] of [
  [
    "fixture override",
    (c) => {
      c.authentication.allowInsecureLoopback = true;
    },
  ],
  [
    "HTTP issuer",
    (c) => {
      c.authentication.issuer = "http://127.0.0.1/realms/org";
    },
  ],
  [
    "unknown top-level field",
    (c) => {
      c.debug = true;
    },
  ],
  [
    "inline password",
    (c) => {
      c.database.password = "secret";
    },
  ],
  [
    "disabled database TLS",
    (c) => {
      c.database.ssl = false;
    },
  ],
  [
    "relative secret path",
    (c) => {
      c.database.passwordFile = "./secret";
    },
  ],
  [
    "URL credentials",
    (c) => {
      c.targets[0].endpoint = "https://user:secret@tool.test/mcp";
    },
  ],
  [
    "policy/connector mismatch",
    (c) => {
      c.targets[0].revision = "2";
    },
  ],
  [
    "unknown policy subject",
    (c) => {
      c.policy.sessions[0].agents = ["unknown"];
    },
  ],
  [
    "unbounded shutdown",
    (c) => {
      c.shutdownMs = Infinity;
    },
  ],
  [
    "management listener exposed",
    (c) => {
      c.management.host = "0.0.0.0";
    },
  ],
])
  test("configuration rejects " + label, (t) => {
    const f = fixture(t);
    change(f.config);
    assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  });

test("rejects permissive secrets, writable public material, symlinks, unsafe parents and invalid UTF-8", (t) => {
  const f = fixture(t);
  const path = f.save();
  chmodSync(f.config.database.passwordFile, 0o644);
  assert.throws(() => loadConfiguration(path), ConfigurationError);
  chmodSync(f.config.database.passwordFile, 0o600);
  chmodSync(f.config.tls.certificateFile, 0o666);
  assert.throws(() => loadConfiguration(path), ConfigurationError);
  chmodSync(f.config.tls.certificateFile, 0o644);
  symlinkSync(f.config.database.passwordFile, join(f.dir, "symlink"));
  f.config.database.passwordFile = join(f.dir, "symlink");
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  const unsafe = join(f.dir, "unsafe");
  mkdirSync(unsafe);
  chmodSync(unsafe, 0o777);
  writeFileSync(join(unsafe, "secret"), "unsafe", { mode: 0o600 });
  f.config.database.passwordFile = join(unsafe, "secret");
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  writeFileSync(path, Buffer.from([0xff]));
  assert.throws(() => loadConfiguration(path), ConfigurationError);
});

test("rejects duplicate JSON members and redacts secret/path contents in errors", (t) => {
  const f = fixture(t);
  const path = f.file("sensitive-secret-config", '{"version":1,"version":1}');
  assert.throws(
    () => loadConfiguration(path),
    (error) =>
      error instanceof ConfigurationError &&
      !error.stack.includes("sensitive-secret-config"),
  );
});

test("rejects wrong TLS identity, mismatched keys, invalid CA and unsafe trust storage", (t) => {
  const f = fixture(t);
  f.config.origin = "https://wrong.test";
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  f.config.origin = "https://xeip.test";
  const original = f.config.tls.privateKeyFile;
  f.config.tls.privateKeyFile = f.file(
    "other.key",
    generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({
      type: "pkcs8",
      format: "pem",
    }),
  );
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  f.config.tls.privateKeyFile = original;
  f.config.database.caFile = f.file("invalid-ca", "invalid");
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  f.config.database.caFile = f.config.tls.certificateFile;
  mkdirSync(f.config.trust.directory, { mode: 0o755 });
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
});

test("rejects oversized or deeply nested configuration and empty or multiline secrets", (t) => {
  const f = fixture(t);
  const path = f.file("large.json", " ".repeat(4 * 1024 * 1024 + 1));
  assert.throws(() => loadConfiguration(path), ConfigurationError);
  writeFileSync(path, "[".repeat(40) + "]".repeat(40));
  assert.throws(() => loadConfiguration(path), ConfigurationError);
  writeFileSync(f.config.database.passwordFile, "");
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  writeFileSync(f.config.database.passwordFile, "a\nb");
  assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
});

test("signed runtime policy sessions must be absolute URIs", (t) => {
  const f = fixture(t);
  assert.doesNotThrow(() => loadConfiguration(f.save()));
  for (const invalid of ["operations", "123:work"]) {
    f.config.policy.sessions[0].id = invalid;
    assert.throws(() => loadConfiguration(f.save()), ConfigurationError);
  }
});
