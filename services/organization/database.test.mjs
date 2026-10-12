import test from "node:test";
import assert from "node:assert/strict";
import { verifyDatabase, grantRuntime, DatabaseNotReady } from "./database.mjs";

test("database checks require bounded acquisition/query waits before connecting", async () => {
  for (const options of [
    {},
    { connectionTimeoutMillis: 0, query_timeout: 3000 },
    { connectionTimeoutMillis: 3000, query_timeout: 10001 },
  ]) {
    await assert.rejects(
      verifyDatabase({
        options,
        connect: () => assert.fail("must not connect"),
      }),
      DatabaseNotReady,
    );
  }
});

test("runtime grant refuses unsafe or reserved role names before SQL", async () => {
  for (const name of [
    "PUBLIC",
    "public",
    "pg_owner",
    "role; DROP TABLE x",
    "",
    "a".repeat(64),
    null,
  ]) {
    await assert.rejects(
      grantRuntime({ connect: () => assert.fail("must not connect") }, name),
      DatabaseNotReady,
    );
  }
});

test("database failure destroys the uncertain connection and redacts its diagnostics", async () => {
  let released;
  const client = {
    query: async () => {
      throw new Error("password=sensitive");
    },
    release: (value) => {
      released = value;
    },
  };
  const pool = {
    options: { connectionTimeoutMillis: 3000, query_timeout: 3000 },
    connect: async () => client,
  };
  await assert.rejects(
    verifyDatabase(pool),
    (error) =>
      error instanceof DatabaseNotReady &&
      !JSON.stringify(error).includes("sensitive") &&
      !error.stack.includes("sensitive"),
  );
  assert.equal(released, true);
});

// Real server cases live in conformance/organization-corruption.mjs; these keep
// fail-closed setting validation fast and cover missing/unrecognized values too.
const safeSettings = {
  version: 180006,
  fsync: "on",
  full_page_writes: "on",
  data_checksums: "on",
  ignore_checksum_failure: "off",
  zero_damaged_pages: "off",
  recovering: false,
};
async function settingsPool(settings) {
  const { migrations } = await import("./schema.mjs");
  return {
    options: { connectionTimeoutMillis: 3000, query_timeout: 3000 },
    connect: async () => ({
      release: () => {},
      query: async (sql) => ({
        rows: sql.includes("server_version_num")
          ? [settings]
          : sql.includes("FROM xeip_org.migrations")
            ? migrations.map((migration, index) => ({
                version: index + 1,
                checksum: migration.checksum,
              }))
            : sql.includes("FROM pg_trigger")
              ? [
                  "protect_action",
                  "protect_audit",
                  "protect_control_event",
                  "protect_control_event_truncate",
                  "protect_control_head",
                  "protect_control_head_truncate",
                  "publish_control_head",
                ].map((tgname) => ({
                  tgname,
                  tgenabled: "O",
                  prosecdef: false,
                }))
              : [],
      }),
    }),
  };
}
for (const [setting, safe] of [
  ["data_checksums", "on"],
  ["ignore_checksum_failure", "off"],
  ["zero_damaged_pages", "off"],
]) {
  test("readiness requires safe " + setting, async () => {
    for (const value of [safe === "on" ? "off" : "on", undefined, "unknown"]) {
      await assert.rejects(
        verifyDatabase(
          await settingsPool({ ...safeSettings, [setting]: value }),
          { runtime: false },
        ),
        DatabaseNotReady,
      );
    }
  });
}
test("safe checksum configuration reaches schema readiness", async () => {
  await verifyDatabase(await settingsPool(safeSettings), { runtime: false });
});
