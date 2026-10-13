// Disposable PostgreSQL control history, never operator endpoints or credentials.
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import pg from "pg";
import { withPostgres } from "./postgres.mjs";
import {
  ControlStore,
  controlEventDigest,
} from "../services/organization/control-store.mjs";
import { canonicalize } from "../packages/identity/signed-envelope.mjs";
import {
  signKeyDocument,
  keyDocumentChainDigest,
} from "../packages/identity/key-document.mjs";
import {
  publicAuthority,
  prepareControlState,
} from "../services/organization/control-state.mjs";
import {
  StoreConflict,
  StoreUnavailable,
} from "../services/organization/errors.mjs";
import {
  grantRuntime,
  verifyDatabase,
  DatabaseNotReady,
} from "../services/organization/database.mjs";
import {
  configuration,
  provisioning,
  acceptedAt,
  entity,
  fixture,
} from "../services/organization/test-fixtures/control.mjs";
const config = configuration();
const authority = publicAuthority(config);
const input = (serial = 1, revoked = []) => ({
  authority,
  provisioning: provisioning(serial, revoked),
  acceptedAt: acceptedAt + serial,
});
await withPostgres(
  async ({ pool }) => {
    const role = "xeip_control_" + randomBytes(6).toString("hex"),
      password = randomBytes(32).toString("hex");
    let runtime;
    try {
      await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`);
      await grantRuntime(pool, role);
      runtime = new pg.Pool({ ...pool.options, password, user: role });
      runtime.on("error", () => {});
      const owner = new ControlStore(pool),
        restricted = new ControlStore(runtime);
      await assert.rejects(restricted.open(input()), StoreUnavailable);
      await assert.rejects(
        restricted.enroll({ ...input(), retainedRecords: {} }),
        StoreUnavailable,
      );
      const enrolled = await owner.enroll({ ...input(), retainedRecords: {} });
      assert.equal(enrolled.revision, 1);
      assert.deepEqual(await restricted.open(input()), enrolled);
      await assert.rejects(
        owner.enroll({ ...input(), retainedRecords: {} }),
        StoreConflict,
      );
      const wrong = configuration();
      wrong.authentication.audience = "different";
      await assert.rejects(
        restricted.open({ ...input(), authority: publicAuthority(wrong) }),
        StoreConflict,
      );
      const revocations = [{ kid: fixture.kid, generation: 1 }];
      const revoked = await restricted.publishTrust(
        enrolled,
        input(2, revocations),
      );
      assert.equal(revoked.revision, 2);
      assert.equal(revoked.snapshot.state.records[entity].serial, 2);
      await assert.rejects(
        restricted.publishTrust(enrolled, input(3)),
        StoreConflict,
      );
      await assert.rejects(restricted.open(input()), StoreConflict);
      assert.deepEqual(await restricted.open(input(2, revocations)), revoked);
      await assert.rejects(
        restricted.publishTrust(revoked, input(1)),
        StoreUnavailable,
      );
      await assert.rejects(
        restricted.changeAuthority(revoked, {
          ...input(3),
          authority: publicAuthority(wrong),
        }),
        StoreUnavailable,
      );
      const changed = await owner.changeAuthority(revoked, {
        ...input(3),
        authority: publicAuthority(wrong),
      });
      assert.equal(changed.revision, 3);
      const currentInput = { ...input(4), authority: publicAuthority(wrong) };
      const races = await Promise.allSettled([
        restricted.publishTrust(changed, currentInput),
        restricted.publishTrust(changed, currentInput),
      ]);
      assert.equal(races.filter((r) => r.status === "fulfilled").length, 1);
      const loser = races.find((r) => r.status === "rejected");
      assert.ok(loser.reason instanceof StoreConflict);
      const winner = races.find((r) => r.status === "fulfilled").value;
      assert.equal(winner.revision, 4);
      const removedInput = {
        ...currentInput,
        provisioning: { keyDocuments: [], statusDocuments: [] },
      };
      const removed = await restricted.publishTrust(winner, removedInput);
      assert.equal(removed.snapshot.state.records[entity].serial, 4);
      await assert.rejects(
        restricted.publishTrust(removed, currentInput),
        StoreUnavailable,
      );
      const restored = await owner.changeAuthority(removed, currentInput);
      assert.equal(restored.revision, 6);
      // Bypass JS validators using actual restricted SQL credentials. Roll back even
      // unexpected success so a failing regression never contaminates later cases.
      // `expected`, when given, is a RegExp the SQL error message must match, so a
      // case asserts *why* the write was refused rather than merely that it was.
      async function rawRefused(mutate, message, expected) {
        const state = structuredClone(restored.snapshot.state);
        state.operation = "trust";
        mutate(state);
        const canonical = canonicalize(state);
        const stateDigest = createHash("sha256")
          .update("XEIP organization control state v1\n" + canonical)
          .digest("hex");
        const client = await runtime.connect();
        try {
          await client.query("BEGIN");
          await assert.rejects(
            client.query(
              "INSERT INTO xeip_org.control_events(revision,previous_digest,state_canonical,state_digest,digest) VALUES(7,$1,$2,$3,$4)",
              [
                restored.digest,
                canonical,
                stateDigest,
                controlEventDigest(7, restored.digest, stateDigest),
              ],
            ),
            expected === undefined ? undefined : { message: expected },
            message,
          );
        } finally {
          await client.query("ROLLBACK");
          client.release();
        }
      }
      await rawRefused((state) => {
        state.authority.authentication.audience = "foreign";
      }, "SQL refuses authority replacement");
      await rawRefused((state) => {
        state.operation = "authority";
      }, "SQL refuses owner operation");
      await rawRefused((state) => {
        delete state.records[entity];
      }, "SQL preserves removed high-water records");
      await rawRefused((state) => {
        state.records[entity].generation = null;
      }, "SQL refuses null high-water counters");
      await rawRefused((state) => {
        delete state.records[entity].serial;
      }, "SQL refuses omitted high-water counters");
      await rawRefused((state) => {
        state.records[entity].generation = 1.1;
      }, "SQL refuses fractional counters");
      await rawRefused((state) => {
        state.records[entity].serial = 9007199254740992;
      }, "SQL refuses unsafe counters");
      await rawRefused((state) => {
        state.provisioning.keyDocuments[0].document.entity += "foreign";
      }, "SQL refuses runtime entity enrollment");
      await rawRefused((state) => {
        state.targetRevisions = [];
      }, "SQL refuses target history removal");
      // Retained records must be justified by the signed provisioning. A runtime
      // writer cannot freeze forged metadata at the point an entity is removed.
      await rawRefused((state) => {
        state.provisioning.keyDocuments = [];
        state.provisioning.statusDocuments = [];
        state.records[entity].generation += 1;
        state.records[entity].keyDigest = "f".repeat(64);
      }, "SQL binds retained records to signed provisioning on removal", /control removed record change/);
      await rawRefused((state) => {
        state.provisioning.keyDocuments = [];
        state.provisioning.statusDocuments = [];
        state.records[entity].serial += 1;
        state.records[entity].statusDigest = "e".repeat(64);
      }, "SQL refuses removed-record counter forgery", /control removed record change/);
      await rawRefused((state) => {
        state.records["urn:xeip:entity:" + "A".repeat(43)] = structuredClone(
          state.records[entity],
        );
      }, "SQL refuses invented inactive identity", /control record without provisioning/);
      // Active records must match the accepted signed documents, not just
      // advance monotonically.
      await rawRefused((state) => {
        state.records[entity].generation += 1;
        state.records[entity].keyDigest = "d".repeat(64);
      }, "SQL binds active generation to signed key documents", /control active record mismatch/);
      await rawRefused((state) => {
        state.records[entity].serial += 1;
        state.records[entity].statusDigest = "c".repeat(64);
      }, "SQL binds active serial to the signed status document", /control active record mismatch/);
      const signing = {
        privateKey: Buffer.from(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
          "hex",
        ),
        kid: fixture.vectors[0].options.keyDocuments[0].genesis,
      };
      const alternateGenesis = signKeyDocument(
        {
          ...provisioning().keyDocuments[0].document,
          devices: [],
          signatures: [],
        },
        signing,
      );
      const alternateSuccessor = signKeyDocument(
        {
          ...alternateGenesis,
          generation: 2,
          previous: keyDocumentChainDigest(alternateGenesis),
          signatures: [],
        },
        signing,
      );
      const alternateProvisioning = provisioning(5);
      alternateProvisioning.keyDocuments = [
        {
          ...alternateProvisioning.keyDocuments[0],
          document: alternateGenesis,
        },
        { document: alternateSuccessor },
      ];
      // Valid signed standalone history, but incompatible with this organization's
      // previously accepted generation. Increasing counters must not hide a fork.
      const alternate = prepareControlState({
        authority: currentInput.authority,
        provisioning: alternateProvisioning,
        acceptedAt: acceptedAt + 5,
        retainedRecords: {},
        operation: "enroll",
      });
      assert.throws(() =>
        prepareControlState({
          authority: currentInput.authority,
          provisioning: alternateProvisioning,
          acceptedAt: acceptedAt + 5,
          previous: restored.snapshot.canonical,
          operation: "trust",
        }),
      );
      await rawRefused((state) => {
        state.provisioning = alternate.state.provisioning;
        state.records = alternate.state.records;
        state.acceptedAt = alternate.state.acceptedAt;
      }, "SQL refuses signed alternate predecessor despite increasing counters");
      const audit = await pool.query(
        "SELECT revision::text, digest FROM xeip_org.control_events ORDER BY revision",
      );
      assert.equal(audit.rows.length, 6);
      const client = await runtime.connect();
      try {
        await client.query("BEGIN");
        await restricted.assertCurrent(client, restored);
        await assert.rejects(
          restricted.assertCurrent(client, enrolled),
          StoreConflict,
        );
        await client.query("ROLLBACK");
      } finally {
        client.release();
      }
      for (const sql of [
        "UPDATE xeip_org.control_events SET digest=digest",
        "DELETE FROM xeip_org.control_events",
        "TRUNCATE xeip_org.control_events CASCADE",
        "DELETE FROM xeip_org.control_head",
        "TRUNCATE xeip_org.control_head",
        "ALTER TABLE xeip_org.control_events DISABLE TRIGGER ALL",
      ])
        await assert.rejects(runtime.query(sql), { code: "42501" });
      await assert.rejects(
        runtime.query("UPDATE xeip_org.control_head SET revision=1"),
      );
      await assert.rejects(
        pool.query("UPDATE xeip_org.control_events SET digest=digest"),
      );
      await assert.rejects(pool.query("DELETE FROM xeip_org.control_head"));
      await verifyDatabase(runtime);
      await pool.query(`GRANT UPDATE ON xeip_org.control_events TO ${role}`);
      await assert.rejects(verifyDatabase(runtime), DatabaseNotReady);
      await grantRuntime(pool, role);
      await verifyDatabase(runtime);
      assert.deepEqual(
        (
          await pool.query(
            "SELECT revision::text, digest FROM xeip_org.control_events ORDER BY revision",
          )
        ).rows,
        audit.rows,
      );
      // Current snapshot corruption after owner-only trigger bypass must fail closed.
      await pool.query(
        "ALTER TABLE xeip_org.control_events DISABLE TRIGGER protect_control_event",
      );
      const original = (
        await pool.query(
          "SELECT state_canonical FROM xeip_org.control_events WHERE revision=6",
        )
      ).rows[0].state_canonical;
      // The checksum constraint refuses damage even with the trigger disabled.
      await assert.rejects(
        pool.query(
          "UPDATE xeip_org.control_events SET state_canonical='{}' WHERE revision=6",
        ),
      );
      await pool.query(
        "ALTER TABLE xeip_org.control_events ENABLE TRIGGER protect_control_event",
      );
      assert.equal(
        (await restricted.open(currentInput)).snapshot.canonical,
        original,
      );
      // Only the fixture owner can bypass protection. A damaged head must never be
      // treated as an empty organization or as a usable older authorization state.
      await pool.query(
        "ALTER TABLE xeip_org.control_head DISABLE TRIGGER protect_control_head",
      );
      try {
        await pool.query(
          "UPDATE xeip_org.control_head SET revision=5,digest=(SELECT digest FROM xeip_org.control_events WHERE revision=5)",
        );
        await assert.rejects(restricted.open(removedInput), StoreUnavailable);
        await pool.query("DELETE FROM xeip_org.control_head");
        await assert.rejects(restricted.open(currentInput), StoreUnavailable);
        await assert.rejects(
          owner.enroll({ ...input(), retainedRecords: {} }),
          StoreUnavailable,
        );
        await pool.query(
          "INSERT INTO xeip_org.control_head(singleton,revision,digest) VALUES(true,6,$1)",
          [restored.digest],
        );
      } finally {
        await pool.query(
          "ALTER TABLE xeip_org.control_head ENABLE TRIGGER protect_control_head",
        );
      }
      assert.deepEqual(await restricted.open(currentInput), restored);
      for (const missingRevision of [5, 6]) {
        const saved = (
          await pool.query(
            "SELECT * FROM xeip_org.control_events WHERE revision=$1",
            [missingRevision],
          )
        ).rows[0];
        await pool.query(
          "ALTER TABLE xeip_org.control_events DISABLE TRIGGER ALL",
        );
        try {
          await pool.query(
            "DELETE FROM xeip_org.control_events WHERE revision=$1",
            [missingRevision],
          );
          await assert.rejects(restricted.open(currentInput), StoreUnavailable);
          await pool.query(
            "INSERT INTO xeip_org.control_events(revision,previous_digest,state_canonical,state_digest,digest) VALUES($1,$2,$3,$4,$5)",
            [
              saved.revision,
              saved.previous_digest,
              saved.state_canonical,
              saved.state_digest,
              saved.digest,
            ],
          );
        } finally {
          await pool.query(
            "ALTER TABLE xeip_org.control_events ENABLE TRIGGER ALL",
          );
        }
        assert.deepEqual(await restricted.open(currentInput), restored);
      }
      const extended = provisioning(5);
      const genesis = extended.keyDocuments[0].document;
      extended.keyDocuments.push({
        document: signKeyDocument(
          {
            ...genesis,
            generation: 2,
            previous: keyDocumentChainDigest(genesis),
            signatures: [],
          },
          signing,
        ),
      });
      const extendedInput = {
        ...currentInput,
        provisioning: extended,
        acceptedAt: acceptedAt + 5,
      };
      const extendedHead = await restricted.publishTrust(
        restored,
        extendedInput,
      );
      assert.equal(extendedHead.revision, 7);
      assert.equal(extendedHead.snapshot.state.records[entity].generation, 2);
      assert.deepEqual(await restricted.open(extendedInput), extendedHead);
      console.log(
        JSON.stringify({
          result: "pass",
          events: 7,
          ownerEnrollment: true,
          runtimeTrustOnly: true,
          staleHeadRejected: true,
          concurrentWinners: 1,
          removedEntityRetained: true,
          immutableHistory: true,
          scope:
            "local control storage; runtime integration and independent recovery remain open",
        }),
      );
    } finally {
      if (runtime) await runtime.end();
      // Owned fixture is destroyed by withPostgres; role/objects live only there.
    }
  },
  { baselineChecks: false },
);
