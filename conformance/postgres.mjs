import { registerFixtureCleanup } from "./fixture-cleanup.mjs";
// Disposable real PostgreSQL fixture. Never connects to an operator database.
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import pg from "pg";
import { pathToFileURL } from "node:url";
import { verifyUpgrade } from "./organization-upgrade.mjs";
const image =
  "postgres:18.6-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873";
export async function withPostgres(
  verify,
  { baselineChecks = true, walFault = false } = {},
) {
  if (walFault && baselineChecks)
    throw new TypeError(
      "WAL fault mode requires its dedicated verification path",
    );
  const name =
    "xeip-postgres-fixture-" +
    process.pid +
    "-" +
    randomBytes(4).toString("hex");
  const secret = randomBytes(32).toString("hex");
  const directory = mkdtempSync(join(tmpdir(), "xeip-postgres-"));
  const file = join(directory, "password");
  writeFileSync(file, secret, { mode: 0o444 });
  const docker = (args) =>
    execFileSync("docker", args, {
      encoding: "utf8",
      timeout: 30000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  let createAttempted = false;
  let pool;
  const removePrimary = () => {
    if (createAttempted) {
      try {
        const ownership = spawnSync(
          "docker",
          [
            "inspect",
            "--format",
            '{{ index .Config.Labels "xeip.postgres-fixture" }}',
            name,
          ],
          {
            encoding: "utf8",
            timeout: 10000,
          },
        );
        if (
          ownership.status === 1 &&
          ownership.stderr.trim() === "Error: No such object: " + name
        ) {
          createAttempted = false;
          return;
        }
        if (ownership.status !== 0 || ownership.stdout.trim() !== name)
          throw new Error("fixture ownership is unconfirmed");
        docker(["rm", "-f", "-v", name]);
      } catch {
        throw new Error(
          "PostgreSQL fixture cleanup failed; inspect candidate " + name,
        );
      }
      createAttempted = false;
    }
  };
  const cleanup = () => {
    removePrimary();
    rmSync(directory, { recursive: true, force: true });
  };
  const unregisterCleanup = registerFixtureCleanup(cleanup);
  try {
    docker(["image", "inspect", image]);
    // A failed client response can still leave a daemon-side container/volume.
    // Track before creation and require the unique label before any removal.
    createAttempted = true;
    docker([
      "create",
      "--name",
      name,
      "--label",
      "xeip.postgres-fixture=" + name,
      "--memory",
      "512m",
      "--cpus",
      "1",
      "-p",
      "127.0.0.1::5432",
      "--mount",
      "type=bind,src=" + file + ",dst=/run/fixture-password,readonly",
      "-e",
      "POSTGRES_PASSWORD_FILE=/run/fixture-password",
      "-e",
      "POSTGRES_DB=xeip_fixture",
      ...(walFault
        ? [
            "--mount",
            "type=tmpfs,destination=/xeip-wal,tmpfs-size=67108864,tmpfs-mode=0700",
            "-e",
            "POSTGRES_INITDB_WALDIR=/xeip-wal",
            "--entrypoint",
            "sh",
          ]
        : []),
      image,
      ...(walFault
        ? [
            "-c",
            'docker-entrypoint.sh postgres -c restart_after_crash=off & server=$!; wait "$server"; touch /tmp/xeip-postgres-exited; exec sleep infinity',
          ]
        : []),
    ]);
    docker(["start", name]);
    let port = Number(
      JSON.parse(
        docker([
          "inspect",
          "--format",
          "{{json .NetworkSettings.Ports}}",
          name,
        ]),
      )["5432/tcp"][0].HostPort,
    );
    pool = new pg.Pool({
      host: "127.0.0.1",
      port,
      user: "postgres",
      password: secret,
      database: "xeip_fixture",
      max: 6,
      connectionTimeoutMillis: 3000,
      query_timeout: 10000,
    });
    pool.on("error", () => {}); // Deliberate restart tests close idle backend connections.
    let ready = false;
    for (let i = 0; i < 180; i++) {
      try {
        await pool.query("SELECT 1");
        ready = true;
        break;
      } catch {
        await delay(500);
      }
    }
    if (!ready) throw new Error("PostgreSQL fixture did not become ready");
    if (baselineChecks) {
      const { verifyStore } = await import("./organization-store-cases.mjs");
      await verifyUpgrade(pool);
      await verifyStore({
        pool,
        restart: async () => {
          docker(["kill", "--signal", "KILL", name]);
          docker(["start", name]);
          // Docker may assign a new ephemeral host port after stop/start.
          port = Number(
            JSON.parse(
              docker([
                "inspect",
                "--format",
                "{{json .NetworkSettings.Ports}}",
                name,
              ]),
            )["5432/tcp"][0].HostPort,
          );
          pool.options.port = port;
          for (let i = 0; i < 120; i++) {
            try {
              await pool.query("SELECT 1");
              return;
            } catch {
              await delay(500);
            }
          }
          throw new Error("PostgreSQL fixture did not recover");
        },
        backupRestore: async () => {
          const dump = execFileSync(
            "docker",
            [
              "exec",
              name,
              "pg_dump",
              "-U",
              "postgres",
              "-d",
              "xeip_fixture",
              "-Fc",
            ],
            { timeout: 30000, maxBuffer: 16 * 1024 * 1024 },
          );
          await pool.query("CREATE DATABASE xeip_restored");
          execFileSync(
            "docker",
            [
              "exec",
              "-i",
              name,
              "pg_restore",
              "-U",
              "postgres",
              "-d",
              "xeip_restored",
              "--exit-on-error",
            ],
            { input: dump, timeout: 30000, stdio: ["pipe", "pipe", "pipe"] },
          );
          return new pg.Pool({
            host: "127.0.0.1",
            port,
            user: "postgres",
            password: secret,
            database: "xeip_restored",
            max: 3,
            connectionTimeoutMillis: 3000,
            query_timeout: 10000,
          });
        },
      });
      const { verifyRuntimeDatabase } = await import(
        "./organization-database.mjs"
      );
      await verifyRuntimeDatabase(pool);
    } else {
      const { migrate } = await import("../services/organization/store.mjs");
      await migrate(pool);
    }
    if (verify)
      await verify({
        pool,
        container: name,
        image,
        destroyPrimary: removePrimary,
      });
    else {
      const { verifyOrganizationService } = await import(
        "./organization-service-cases.mjs"
      );
      await verifyOrganizationService({ pool });
    }
  } finally {
    try {
      if (pool) await pool.end();
    } finally {
      try {
        cleanup();
      } finally {
        unregisterCleanup();
      }
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await withPostgres();
