import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { harness } from "./fixtures/cloudflare/lifecycle-harness.mjs";
let runtime;
before(async () => {
  runtime = await harness({
    entryPoint: new URL(
      "./organization-cloudflare-action-restore-worker.mjs",
      import.meta.url,
    ).pathname,
    className: "ActionRestoreFixture",
  });
});
after(async () => {
  await runtime?.close();
});
test("restore fence blocks normal initialization and verification even with corrupt restore intent", async () => {
  const f = await runtime.fixture();
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 200);
  assert.equal((await f.send({ operation: "insertFence" })).status, 200);
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 503);
  assert.equal((await f.send({ operation: "verifyNormal" })).status, 503);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  await runtime.restart();
  const reopened = await runtime.fixture(f.name);
  assert.equal(
    (await reopened.send({ operation: "initializeNormal" })).status,
    503,
  );
});
test("schema7 upgrades without changing existing schema records and old code refuses the current schema", async () => {
  const f = await runtime.fixture();
  assert.equal((await f.send({ operation: "initializeV7" })).status, 200);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    7,
  );
  const before = (
    await f.sql(
      "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' ORDER BY name",
    )
  ).body.rows;
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 200);
  const after = (
    await f.sql(
      "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' AND name NOT GLOB 'xeip_action_restore*' AND name NOT GLOB 'xeip_organization_restore*' ORDER BY name",
    )
  ).body.rows;
  assert.deepEqual(after, before);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  assert.equal((await f.send({ operation: "initializeV7" })).status, 503);
});
test("schema8 migration fault after DDL rolls back completely before retry", async () => {
  const f = await runtime.fixture();
  await f.send({ operation: "initializeV7" });
  await f.send({
    operation: "controls",
    control: { failQuery: "UPDATE xeip_schema SET version=8" },
  });
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 503);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    7,
  );
  assert.equal(
    (
      await f.sql(
        "SELECT name FROM sqlite_master WHERE name GLOB 'xeip_action_restore*'",
      )
    ).body.rows.length,
    0,
  );
  await f.send({ operation: "controls", control: { failQuery: null } });
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 200);
});
test("restore fence cannot be deleted, replaced or advanced backwards through SQL", async () => {
  const f = await runtime.fixture();
  await f.send({ operation: "initializeNormal" });
  await f.send({ operation: "insertFence" });
  for (const query of [
    "DELETE FROM xeip_action_restore",
    "INSERT OR REPLACE INTO xeip_action_restore SELECT * FROM xeip_action_restore",
    "UPDATE xeip_action_restore SET intent='{\"changed\":true}'",
    "UPDATE xeip_action_restore SET sequence=2,total_bytes=1",
  ]) {
    assert.notEqual((await f.sql(query)).status, 200);
  }
  assert.equal(
    (await f.sql("SELECT sequence FROM xeip_action_restore")).body.rows[0]
      .sequence,
    0,
  );
});
import { createHash, randomUUID } from "node:crypto";
import {
  canonicalize,
  genesis,
  recoveryOptions,
} from "../services/organization/cloudflare/recovery-record.mjs";
import {
  actionRecoveryPayload,
  prepareActionRecovery,
} from "../services/organization/cloudflare/action-recovery-record.mjs";
import {
  filesHasher,
  hash,
  recoveryFilename,
  seal,
  sourceCopy,
} from "../services/organization/cloudflare/recovery-archive-record.mjs";
const recoveryOptionsValue = recoveryOptions({
  organization: "fixture-organization",
  stream: "ad319cca-e90f-49aa-bc81-1524d9d65ae4",
});
function bundle(states = ["succeeded"]) {
  const agent =
      "urn:xeip:entity:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
    human = "urn:xeip:entity:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd";
  const actor = { subject: "agent", entity: agent, kid: agent.slice(16) },
    approver = { subject: "human", entity: human, kid: human.slice(16) };
  let head = {
      organization: recoveryOptionsValue.organization,
      stream: recoveryOptionsValue.stream,
      sequence: 0,
      checksum: genesis(recoveryOptionsValue),
    },
    totalBytes = 0;
  const records = [],
    latest = [],
    files = filesHasher();
  for (const [i, state] of states.entries()) {
    const action = {
        id: "action-" + i,
        session: "operations",
        actor,
        expiresAt: 1000,
        arguments: { secret: "recovery argument " + i },
      },
      canonical = canonicalize(action),
      digest = createHash("sha256")
        .update("XEIP organization action v1\n" + canonical)
        .digest("hex");
    let row = {
      session_id: "operations",
      request_id: action.id,
      digest,
      canonical,
      expires_at: 1000,
      state: "pending",
      version: 0,
      approver: null,
      approval_expires_at: null,
      claim_id: null,
      result_canonical: null,
    };
    const history = [];
    const add = (event, who) => {
      history.push({
        sequence: head.sequence + 1,
        session_id: row.session_id,
        request_id: row.request_id,
        digest,
        event,
        actor: canonicalize(who),
        occurred_at: 900 + head.sequence,
      });
      const payload = actionRecoveryPayload(
          recoveryOptionsValue.organization,
          head.sequence + 1,
          { row, history },
        ),
        p = prepareActionRecovery(payload, head, totalBytes),
        record = { entry: p.entry, chunks: p.request.chunks };
      records.push(record);
      head = {
        ...head,
        sequence: p.entry.sequence,
        checksum: p.entry.checksum,
      };
      totalBytes = p.entry.totalBytes;
      files.update(
        canonicalize([
          recoveryFilename(head.sequence),
          hash(canonicalize(record) + "\n"),
        ]),
      );
    };
    add("proposed", actor);
    if (state === "revoked") {
      row = { ...row, state, version: 1 };
      add("revoked", actor);
    } else if (state !== "pending") {
      row = {
        ...row,
        state: state === "rejected" ? "rejected" : "approved",
        version: 1,
        approver: canonicalize({
          ...approver,
          clientId: "console",
          roles: ["approver"],
          expiresAt: 1000,
        }),
        approval_expires_at: 1000,
      };
      add(row.state, approver);
      if (
        ["executing", "succeeded", "failed", "indeterminate"].includes(state)
      ) {
        row = {
          ...row,
          state: "executing",
          version: 2,
          claim_id: randomUUID(),
        };
        add("claimed", actor);
        if (state !== "executing") {
          row = {
            ...row,
            state,
            version: 3,
            result_canonical:
              state === "indeterminate"
                ? null
                : canonicalize({ outcome: state }),
          };
          add(state, { worker: "execution", claimId: row.claim_id });
        }
      }
    }
    latest.push({ row, history });
  }
  const data = {
    schema: "xeip.recovery-archive/1",
    source: sourceCopy({
      url: "https://journal.example/v1/recovery",
      options: recoveryOptionsValue,
    }),
    head,
    totalBytes,
    filesChecksum: files.digest("hex"),
    previous: null,
  };
  return {
    manifest: { ...data, manifestChecksum: seal(data) },
    records,
    latest,
  };
}
test("native reconstruction preserves every outcome and consumed claim but stays fenced", async () => {
  await import("../services/organization/cloudflare/action-restore.mjs");
  const f = await runtime.fixture(),
    b = bundle([
      "pending",
      "approved",
      "rejected",
      "revoked",
      "executing",
      "succeeded",
      "failed",
      "indeterminate",
    ]);
  assert.equal(
    (await f.send({ operation: "restoreInitialize", manifest: b.manifest }))
      .status,
    200,
  );
  for (const value of b.records)
    assert.equal(
      (await f.send({ operation: "restoreApply", value })).status,
      200,
      "sequence " + value.entry.sequence,
    );
  const verified = await f.send({ operation: "restoreVerify" });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.phase, "verified");
  assert.equal(verified.body.blocked, true);
  assert.equal(verified.body.actions, 8);
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_actions ORDER BY request_id")).body.rows,
    b.latest.map((v) => v.row),
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_audit ORDER BY sequence")).body.rows,
    b.latest.flatMap((v) => v.history),
  );
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 503);
  assert.equal((await f.send({ operation: "regularStore" })).status, 503);
});
test("empty bundle verifies but never enables normal runtime", async () => {
  const f = await runtime.fixture(),
    b = bundle([]);
  assert.equal(
    (await f.send({ operation: "restoreInitialize", manifest: b.manifest }))
      .status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "restoreVerify" })).body.phase,
    "verified",
  );
  assert.equal((await f.send({ operation: "regularStore" })).status, 503);
});
test("restart resumes an exact prefix, current-tail retry is idempotent and verified state remains fenced", async () => {
  let f = await runtime.fixture();
  const b = bundle();
  await f.send({ operation: "restoreInitialize", manifest: b.manifest });
  for (const value of b.records.slice(0, 3))
    assert.equal(
      (await f.send({ operation: "restoreApply", value })).status,
      200,
    );
  assert.equal((await f.send({ operation: "restoreVerify" })).status, 409);
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal(
    (await f.send({ operation: "restoreOpen", manifest: b.manifest })).body.head
      .sequence,
    3,
  );
  assert.equal(
    (await f.send({ operation: "restoreApply", value: b.records[2] })).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "restoreApply", value: b.records[0] })).status,
    409,
  );
  assert.equal(
    (await f.send({ operation: "restoreApply", value: b.records[3] })).status,
    200,
  );
  assert.equal(
    (await f.send({ operation: "restoreVerify" })).body.phase,
    "verified",
  );
  await runtime.restart();
  f = await runtime.fixture(f.name);
  assert.equal(
    (await f.send({ operation: "restoreOpen", manifest: b.manifest })).body
      .phase,
    "verified",
  );
  assert.equal((await f.send({ operation: "regularStore" })).status, 503);
  assert.equal(
    (await f.sql("SELECT COUNT(*) AS n FROM xeip_audit")).body.rows[0].n,
    4,
  );
});
test("initialization refuses both initialized ledgers and unrelated user tables without overwriting", async () => {
  const b = bundle();
  for (const existing of ["ledger", "unrelated"]) {
    const f = await runtime.fixture();
    if (existing === "ledger") await f.send({ operation: "initializeNormal" });
    else
      await f.sql(
        "CREATE TABLE other_data(value TEXT); INSERT INTO other_data VALUES('keep')",
      );
    const before = (
      await f.sql("SELECT type,name,sql FROM sqlite_master ORDER BY name")
    ).body.rows;
    assert.equal(
      (await f.send({ operation: "restoreInitialize", manifest: b.manifest }))
        .status,
      409,
    );
    assert.deepEqual(
      (await f.sql("SELECT type,name,sql FROM sqlite_master ORDER BY name"))
        .body.rows,
      before,
    );
  }
});
test("invalid manifest cannot initialize and a changed valid intent cannot adopt restored state", async () => {
  const f = await runtime.fixture(),
    b = bundle();
  assert.equal(
    (
      await f.send({
        operation: "restoreInitialize",
        manifest: { ...b.manifest, manifestChecksum: "0".repeat(64) },
      })
    ).status,
    503,
  );
  assert.equal(
    (await f.sql("SELECT name FROM sqlite_master WHERE name GLOB 'xeip_*'"))
      .body.rows.length,
    0,
  );
  await f.send({ operation: "restoreInitialize", manifest: b.manifest });
  await f.send({ operation: "restoreApply", value: b.records[0] });
  const { manifestChecksum, ...data } = b.manifest;
  data.source = { ...data.source, url: "https://different.example/" };
  const changed = { ...data, manifestChecksum: seal(data) };
  assert.equal(
    (await f.send({ operation: "restoreOpen", manifest: changed })).status,
    503,
  );
  assert.equal(
    (await f.send({ operation: "restoreOpen", manifest: b.manifest })).body.head
      .sequence,
    1,
  );
});
for (const query of [
  "INSERT INTO xeip_actions",
  "INSERT INTO xeip_audit",
  "UPDATE xeip_action_restore SET sequence",
])
  test(`restore transaction rolls back ${query}`, async () => {
    const f = await runtime.fixture(),
      b = bundle();
    await f.send({ operation: "restoreInitialize", manifest: b.manifest });
    await f.send({ operation: "controls", control: { failQuery: query } });
    assert.equal(
      (await f.send({ operation: "restoreApply", value: b.records[0] })).status,
      503,
    );
    assert.equal(
      (await f.sql("SELECT COUNT(*) AS n FROM xeip_actions")).body.rows[0].n,
      0,
    );
    assert.equal(
      (await f.sql("SELECT COUNT(*) AS n FROM xeip_audit")).body.rows[0].n,
      0,
    );
    assert.equal(
      (await f.sql("SELECT sequence FROM xeip_action_restore")).body.rows[0]
        .sequence,
      0,
    );
    await f.send({ operation: "controls", control: { failQuery: null } });
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest: b.manifest })).status,
      200,
    );
    assert.equal(
      (await f.send({ operation: "restoreApply", value: b.records[0] })).status,
      200,
    );
  });
for (const stage of ["initialize", "apply"])
  test(`ambiguous ${stage} commit is recognized on fresh open without rewriting data`, async () => {
    const f = await runtime.fixture(),
      b = bundle();
    if (stage === "apply")
      await f.send({ operation: "restoreInitialize", manifest: b.manifest });
    await f.send({
      operation: "controls",
      control: { failTransaction: "after" },
    });
    assert.equal(
      (
        await f.send(
          stage === "initialize"
            ? { operation: "restoreInitialize", manifest: b.manifest }
            : { operation: "restoreApply", value: b.records[0] },
        )
      ).status,
      503,
    );
    await f.send({ operation: "controls", control: { failTransaction: null } });
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest: b.manifest })).body
        .head.sequence,
      stage === "apply" ? 1 : 0,
    );
    assert.equal((await f.send({ operation: "initializeNormal" })).status, 503);
  });
for (const failSync of [1, 2, 6])
  test(`restore sync failure ${failSync} quarantines and preserves staged evidence`, async () => {
    const f = await runtime.fixture(),
      b = bundle();
    await f.send({ operation: "controls", control: { failSync } });
    if (failSync === 1)
      assert.equal(
        (await f.send({ operation: "restoreInitialize", manifest: b.manifest }))
          .status,
        503,
      );
    else {
      await f.send({ operation: "restoreInitialize", manifest: b.manifest });
      for (const value of b.records) {
        const r = await f.send({ operation: "restoreApply", value });
        if (failSync === 2) {
          assert.equal(r.status, 503);
          break;
        }
        assert.equal(r.status, 200);
      }
      if (failSync === 6)
        assert.equal(
          (await f.send({ operation: "restoreVerify" })).status,
          503,
        );
    }
    await f.send({ operation: "controls", control: { failSync: 0 } });
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest: b.manifest })).status,
      200,
    );
    assert.equal((await f.send({ operation: "regularStore" })).status, 503);
  });
async function syncReached(f, n) {
  for (let i = 0; i < 200; i++) {
    if ((await f.send({ operation: "controls", control: {} })).body.syncs >= n)
      return;
    await new Promise((r) => setTimeout(r, 5));
  }
  assert.fail("sync did not start");
}
for (const outcome of ["timeout", "close", "concurrent"])
  test(`held restore sync handles ${outcome} without late activation`, async () => {
    const f = await runtime.fixture(),
      b = bundle();
    // Exercise the supported deadline without requiring sub-100ms initialization
    // from a cold native runtime on a shared host.
    assert.equal(
      (
        await f.send({
          operation: "restoreInitialize",
          manifest: b.manifest,
          settings: { timeoutMs: 10000 },
        })
      ).status,
      200,
    );
    await f.send({ operation: "controls", control: { holdSync: 2 } });
    const pending = f.send({ operation: "restoreApply", value: b.records[0] });
    try {
      await syncReached(f, 2);
      assert.equal((await f.send({ operation: "regularStore" })).status, 503);
      if (outcome === "close") await f.send({ operation: "restoreClose" });
      if (outcome === "concurrent")
        assert.equal(
          (await f.send({ operation: "restoreApply", value: b.records[0] }))
            .status,
          409,
        );
      if (outcome === "timeout") assert.equal((await pending).status, 503);
    } finally {
      await f.send({ operation: "controls", control: { holdSync: 0 } });
    }
    assert.equal((await pending).status, outcome === "concurrent" ? 200 : 503);
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest: b.manifest })).body
        .head.sequence,
      1,
    );
    assert.equal((await f.send({ operation: "regularStore" })).status, 503);
  });
test("missing recovery binding or altered row content prevents reconstructed-prefix open", async () => {
  for (const mode of ["binding", "count", "result"]) {
    const f = await runtime.fixture(),
      b = bundle();
    await f.send({ operation: "restoreInitialize", manifest: b.manifest });
    for (const value of b.records)
      await f.send({ operation: "restoreApply", value });
    if (mode === "binding") await f.sql("DROP TABLE xeip_action_recovery");
    if (mode === "count")
      await f.sql("UPDATE xeip_metadata SET action_count=0");
    if (mode === "result") {
      const trigger = (
        await f.sql(
          "SELECT sql FROM sqlite_master WHERE name='xeip_action_update'",
        )
      ).body.rows[0].sql;
      await f.sql("DROP TRIGGER xeip_action_update");
      await f.sql(
        "UPDATE xeip_actions SET result_canonical=?",
        canonicalize({ altered: true }),
      );
      await f.sql(trigger);
    }
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest: b.manifest })).status,
      503,
    );
    assert.equal((await f.send({ operation: "initializeNormal" })).status, 503);
  }
});
test("malformed chunks, omitted transitions and forked history never overwrite a staged prefix", async () => {
  const b = bundle();
  for (const mode of ["chunk", "omitted", "fork"]) {
    const f = await runtime.fixture();
    await f.send({ operation: "restoreInitialize", manifest: b.manifest });
    await f.send({ operation: "restoreApply", value: b.records[0] });
    let value = structuredClone(b.records[1]);
    if (mode === "chunk") value.chunks[0] = "AAAA";
    if (mode === "omitted") value = b.records[2];
    if (mode === "fork") {
      const payload = JSON.parse(
        Buffer.from(value.chunks[0], "base64").toString(),
      );
      payload.record.history[0].occurred_at--;
      const prepared = prepareActionRecovery(
        actionRecoveryPayload(
          recoveryOptionsValue.organization,
          2,
          payload.record,
        ),
        {
          ...b.manifest.head,
          sequence: 1,
          checksum: b.records[0].entry.checksum,
        },
        b.records[0].entry.totalBytes,
      );
      value = { entry: prepared.entry, chunks: prepared.request.chunks };
    }
    assert.equal(
      (await f.send({ operation: "restoreApply", value })).status,
      mode === "omitted" ? 409 : 503,
    );
    assert.equal(
      (await f.sql("SELECT sequence FROM xeip_action_restore")).body.rows[0]
        .sequence,
      1,
    );
    assert.equal(
      (await f.sql("SELECT state FROM xeip_actions")).body.rows[0].state,
      "pending",
    );
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest: b.manifest })).body
        .head.sequence,
      1,
    );
  }
});
test("full verification refuses a changed target head or files checksum and keeps normal runtime blocked", async () => {
  for (const field of ["head", "filesChecksum", "previous"]) {
    const f = await runtime.fixture(),
      b = bundle(),
      manifest = structuredClone(b.manifest);
    if (field === "head") manifest.head.checksum = "0".repeat(64);
    if (field === "filesChecksum") manifest.filesChecksum = "0".repeat(64);
    if (field === "previous")
      manifest.previous = {
        head: { ...manifest.head, sequence: 1, checksum: "0".repeat(64) },
        manifestChecksum: "1".repeat(64),
      };
    const { manifestChecksum, ...data } = manifest;
    manifest.manifestChecksum = seal(data);
    assert.equal(
      (await f.send({ operation: "restoreInitialize", manifest })).status,
      200,
    );
    for (const value of b.records)
      assert.equal(
        (await f.send({ operation: "restoreApply", value })).status,
        200,
      );
    assert.equal((await f.send({ operation: "restoreVerify" })).status, 503);
    assert.equal(
      (await f.send({ operation: "restoreOpen", manifest })).status,
      503,
    );
    assert.equal((await f.send({ operation: "regularStore" })).status, 503);
    assert.equal(
      (await f.sql("SELECT phase FROM xeip_action_restore")).body.rows[0].phase,
      "restoring",
    );
  }
});
test("schema7 upgrade preserves completed action, consumed claim, audit and recovery enrollment bytes", async () => {
  const f = await runtime.fixture(),
    b = bundle();
  await f.send({ operation: "initializeV7" });
  const { recoveryDescriptor } = await import(
    "../services/organization/cloudflare/action-recovery.mjs"
  );
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_action_recovery(singleton,canonical) VALUES(1,?)",
        canonicalize(recoveryDescriptor(recoveryOptionsValue)),
      )
    ).status,
    200,
  );
  for (const value of b.records) {
    const { row, history } = JSON.parse(
        Buffer.from(value.chunks[0], "base64").toString(),
      ).record,
      keys = Object.keys(row),
      values = Object.values(row),
      event = history.at(-1);
    const write =
      history.length === 1
        ? await f.sql(
            "INSERT INTO xeip_actions(" +
              keys.join(",") +
              ") VALUES(" +
              keys.map(() => "?").join(",") +
              ")",
            ...values,
          )
        : await f.sql(
            "UPDATE xeip_actions SET " + keys.map((k) => k + "=?").join(","),
            ...values,
          );
    assert.equal(write.status, 200);
    assert.equal(
      (
        await f.sql(
          "INSERT INTO xeip_audit(sequence,session_id,request_id,digest,event,actor,occurred_at) VALUES(?,?,?,?,?,?,?)",
          event.sequence,
          event.session_id,
          event.request_id,
          event.digest,
          event.event,
          event.actor,
          event.occurred_at,
        )
      ).status,
      200,
    );
  }
  const tables = [
      "xeip_actions",
      "xeip_audit",
      "xeip_metadata",
      "xeip_action_recovery",
    ],
    before = await Promise.all(
      tables.map(
        async (table) => (await f.sql("SELECT * FROM " + table)).body.rows,
      ),
    );
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 200);
  for (let i = 0; i < tables.length; i++)
    assert.deepEqual(
      (await f.sql("SELECT * FROM " + tables[i])).body.rows,
      before[i],
    );
  assert.equal(
    (await f.sql("SELECT claim_id FROM xeip_actions")).body.rows[0].claim_id,
    b.latest[0].row.claim_id,
  );
});

test("schema8 staged action restore upgrades atomically and resumes without dropping its fence", async () => {
  const f = await runtime.fixture(),
    b = bundle();
  await f.send({ operation: "initializeV8" });
  const { recoveryDescriptor } = await import(
    "../services/organization/cloudflare/action-recovery.mjs"
  );
  await f.sql(
    "INSERT INTO xeip_action_recovery(singleton,canonical) VALUES(1,?)",
    canonicalize(recoveryDescriptor(recoveryOptionsValue)),
  );
  const row = {
    intent: canonicalize(b.manifest),
    sequence: 0,
    head_checksum: genesis(recoveryOptionsValue),
    total_bytes: 0,
    phase: "restoring",
  };
  const checksum = createHash("sha256")
    .update("XEIP staged action restore v1\n" + canonicalize(row))
    .digest("hex");
  assert.equal(
    (
      await f.sql(
        "INSERT INTO xeip_action_restore(singleton,intent,sequence,head_checksum,total_bytes,phase,checksum) VALUES(1,?,?,?,?,?,?)",
        ...Object.values(row),
        checksum,
      )
    ).status,
    200,
  );
  assert.equal((await f.send({ operation: "initializeNormal" })).status, 503);
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    8,
  );
  const before = (await f.sql("SELECT * FROM xeip_action_restore")).body.rows;
  assert.equal(
    (await f.send({ operation: "restoreOpen", manifest: bundle([]).manifest }))
      .status,
    503,
  );
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    8,
  );
  assert.deepEqual(
    (await f.sql("SELECT * FROM xeip_action_restore")).body.rows,
    before,
  );
  const opened = await f.send({
    operation: "restoreOpen",
    manifest: b.manifest,
  });
  assert.equal(opened.status, 200, JSON.stringify(opened));
  assert.equal(
    (await f.sql("SELECT version FROM xeip_schema")).body.rows[0].version,
    9,
  );
  for (const value of b.records)
    assert.equal(
      (await f.send({ operation: "restoreApply", value })).status,
      200,
    );
  assert.equal(
    (await f.send({ operation: "restoreVerify" })).body.phase,
    "verified",
  );
  assert.equal((await f.send({ operation: "regularStore" })).status, 503);
});
