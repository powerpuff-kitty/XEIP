/** Offline-verifiable administrative archives. Never deletes or restores source state. */
import * as fs from "node:fs/promises";
import { constants } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { join, resolve, dirname } from "node:path";
import {
  canonicalize,
  strictParse,
} from "../../../sdks/typescript/dist/identity.js";
import { snapshot } from "../actions.mjs";
import { validateAuditPage } from "./admin-audit.mjs";
import { validateOperatorConfig, withOwnerSession } from "./owner.mjs";
/** @typedef {import('./owner.mjs').OperatorConfiguration} Source */
/** @typedef {{records:import('./admin-audit.mjs').RecordEntry[],next:number,headSequence:number,headChecksum:string}} Page */
/** @typedef {{headSequence:number,headChecksum:string,manifestChecksum:string}} Witness */
/** @typedef {{schema:string,source:Source,headSequence:number,headChecksum:string,pages:number,records:number,filesChecksum:string,previous:Witness|null,manifestChecksum:string}} Manifest */
const zero = "0".repeat(64);
const hash = (/** @type {string|Uint8Array} */ value) =>
  createHash("sha256").update(value).digest("hex");
const digest = (/** @type {unknown} */ value) =>
  typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const integer = (/** @type {unknown} */ value) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
/** @param {unknown} value @param {string[]} keys @returns {value is Record<string,unknown>} */
const exact = (value, keys) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).sort().join(",") === [...keys].sort().join(",");
/** @param {unknown} value @returns {Source} */
export function sourceCopy(value) {
  const raw = canonicalize(value);
  if (Buffer.byteLength(raw) > 8192) throw Error();
  const copy = /** @type {Source} */ (
    /** @type {unknown} */ (snapshot(strictParse(raw), 8192))
  );
  return validateOperatorConfig(copy, copy.services?.[0]?.remote);
}
/** @param {Omit<Manifest,'manifestChecksum'>} value */
const manifestHash = (value) =>
  hash("XEIP owner archive v1\n" + canonicalize(value));
/** @param {number} index */
const filename = (index) => String(index).padStart(6, "0") + ".json";
/** @param {unknown} value @returns {Manifest} */
function manifestValue(value) {
  if (
    !exact(value, [
      "schema",
      "source",
      "headSequence",
      "headChecksum",
      "pages",
      "records",
      "filesChecksum",
      "previous",
      "manifestChecksum",
    ]) ||
    value.schema !== "xeip.owner-archive/1" ||
    !integer(value.headSequence) ||
    Number(value.headSequence) > 100000 ||
    value.records !== value.headSequence ||
    value.pages !== Math.max(1, Math.ceil(Number(value.records) / 16)) ||
    !digest(value.headChecksum) ||
    !digest(value.filesChecksum) ||
    !digest(value.manifestChecksum)
  )
    throw Error();
  sourceCopy(value.source);
  if (
    value.previous !== null &&
    (!exact(value.previous, [
      "headSequence",
      "headChecksum",
      "manifestChecksum",
    ]) ||
      !integer(value.previous.headSequence) ||
      Number(value.previous.headSequence) > Number(value.headSequence) ||
      !digest(value.previous.headChecksum) ||
      !digest(value.previous.manifestChecksum))
  )
    throw Error();
  const manifest = /** @type {Manifest} */ (/** @type {unknown} */ (value));
  const { manifestChecksum, ...data } = manifest;
  if (manifestChecksum !== manifestHash(data)) throw Error();
  return manifest;
}
class Chain {
  sequence = 0;
  checksum = zero;
  time = 0;
  /** @type {Map<string,{checksum:string,time:number,finished:boolean}>} */ attempts =
    new Map();
  /** @param {number} head @param {string} checksum @param {Witness|null} previous */
  constructor(head, checksum, previous) {
    this.head = head;
    this.final = checksum;
    this.observedHead = head;
    this.observedChecksum = checksum;
    this.previous = previous;
    if (previous?.headSequence === 0 && previous.headChecksum !== zero)
      throw Error();
  }
  /** @param {unknown} raw @param {number} limit @returns {Page} */
  accept(raw, limit) {
    const page = /** @type {Page} */ (
      /** @type {unknown} */ (
        validateAuditPage(raw, { after: this.sequence, limit })
      )
    );
    if (
      page.headSequence < this.observedHead ||
      (page.headSequence === this.observedHead &&
        page.headChecksum !== this.observedChecksum) ||
      page.next > this.head
    )
      throw Error();
    this.observedHead = page.headSequence;
    this.observedChecksum = page.headChecksum;
    for (const row of page.records) {
      if (row.previous !== this.checksum || row.event.occurredAt < this.time)
        throw Error();
      const event = row.event,
        prior = this.attempts.get(event.attemptId);
      if (event.outcome === "started") {
        if (prior) throw Error();
        this.attempts.set(event.attemptId, {
          checksum: hash(canonicalize(event)),
          time: event.occurredAt,
          finished: false,
        });
      } else {
        if (!prior || prior.finished) throw Error();
        const { after, ...start } = event;
        if (
          hash(
            canonicalize({
              ...start,
              outcome: "started",
              occurredAt: prior.time,
            }),
          ) !== prior.checksum
        )
          throw Error();
        prior.finished = true;
      }
      this.sequence = row.sequence;
      this.checksum = row.checksum;
      this.time = event.occurredAt;
      if (
        this.previous?.headSequence === this.sequence &&
        this.previous.headChecksum !== this.checksum
      )
        throw Error();
    }
    return page;
  }
  finish() {
    if (this.sequence !== this.head || this.checksum !== this.final)
      throw Error();
  }
}
/** @param {string} path @param {number} max @param {typeof fs} io
 * @param {(value:unknown)=>unknown} [validate] */
export async function readJson(
  path,
  max,
  io,
  validate = (value) => snapshot(value, max),
) {
  const handle = await io.open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > max || (stat.mode & 0o077) !== 0)
      throw Error();
    const bytes = Buffer.alloc(max + 1);
    let size = 0;
    while (size < bytes.length) {
      const r = await handle.read(bytes, size, bytes.length - size, null);
      if (!r.bytesRead) break;
      size += r.bytesRead;
    }
    if (size > max) throw Error();
    const raw = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes.subarray(0, size));
    const value = validate(strictParse(raw));
    if (canonicalize(value) + "\n" !== raw) throw Error();
    return { value, raw };
  } finally {
    await handle.close();
  }
}
/** @param {string} path @param {typeof fs} io */
export async function syncDirectory(path, io) {
  const h = await io.open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
  );
  try {
    await h.sync();
  } finally {
    await h.close();
  }
}
/** @param {string} path @param {string} text @param {typeof fs} io */
export async function writeDurable(path, text, io) {
  const h = await io.open(path, "wx", 0o600);
  try {
    await h.writeFile(text, "utf8");
    await h.sync();
  } finally {
    await h.close();
  }
}
/** Offline content verification, not proof of an external failure domain or historic fsync.
 * @param {string} directory @returns {Promise<Manifest>} */
export async function verifyArchive(directory) {
  try {
    const path = resolve(directory),
      stat = await fs.lstat(path);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.mode & 0o077) !== 0
    )
      throw Error();
    const manifest = manifestValue(
      (await readJson(join(path, "manifest.json"), 16384, fs)).value,
    );
    const allowed = new Set([
      "manifest.json",
      ...Array.from({ length: manifest.pages }, (_, i) => filename(i + 1)),
    ]);
    const dir = await fs.opendir(path);
    let count = 0;
    for await (const entry of dir) {
      if (
        ++count > manifest.pages + 1 ||
        !entry.isFile() ||
        !allowed.delete(entry.name)
      )
        throw Error();
    }
    if (allowed.size) throw Error();
    const chain = new Chain(
        manifest.headSequence,
        manifest.headChecksum,
        manifest.previous,
      ),
      files = createHash("sha256").update("XEIP archive pages v1\n");
    for (let i = 1; i <= manifest.pages; i++) {
      const name = filename(i),
        { value, raw } = await readJson(join(path, name), 65536, fs);
      if (
        i === 1 &&
        /** @type {Page} */ (/** @type {unknown} */ (value)).headSequence !==
          manifest.headSequence
      )
        throw Error();
      chain.accept(
        value,
        Math.min(16, Math.max(1, manifest.headSequence - chain.sequence)),
      );
      files.update(canonicalize([name, hash(raw)]));
    }
    chain.finish();
    if (files.digest("hex") !== manifest.filesChecksum) throw Error();
    return manifest;
  } catch {
    throw new Error("invalid archive");
  }
}
/** Each call must be a read-only page request. No action or owner mutation is emitted here.
 * @param {{directory:string,source:unknown,readPage:(options:{after:number,limit:number})=>Promise<unknown>,previous?:string,io?:typeof fs,timeoutMs?:number}} options
 * @returns {Promise<Manifest>} */
export async function collectArchive({
  directory,
  source,
  readPage,
  previous,
  io = fs,
  timeoutMs = 30000,
}) {
  try {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000)
      throw Error();
    const request = async (
      /** @type {{after:number,limit:number}} */ options,
    ) => {
      let timer;
      try {
        return await Promise.race([
          Promise.resolve().then(() => readPage(options)),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error()), timeoutMs);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    };
    const config = sourceCopy(source),
      prior = previous === undefined ? null : await verifyArchive(previous);
    if (prior && canonicalize(prior.source) !== canonicalize(config))
      throw Error();
    const witness = prior
      ? {
          headSequence: prior.headSequence,
          headChecksum: prior.headChecksum,
          manifestChecksum: prior.manifestChecksum,
        }
      : null;
    const path = resolve(directory);
    await io.mkdir(path, { mode: 0o700 });
    await syncDirectory(dirname(path), io);
    const first = /** @type {Page} */ (
      /** @type {unknown} */ (
        validateAuditPage(await request({ after: 0, limit: 16 }), {
          after: 0,
          limit: 16,
        })
      )
    );
    if (witness && first.headSequence < witness.headSequence) throw Error();
    const chain = new Chain(first.headSequence, first.headChecksum, witness),
      files = createHash("sha256").update("XEIP archive pages v1\n");
    let index = 0,
      page = first;
    do {
      const remaining = chain.head - chain.sequence;
      chain.accept(page, index === 0 ? 16 : Math.min(16, remaining));
      const name = filename(++index),
        raw = canonicalize(page) + "\n";
      if (Buffer.byteLength(raw) > 65536) throw Error();
      await writeDurable(join(path, name), raw, io);
      files.update(canonicalize([name, hash(raw)]));
      if (chain.sequence === chain.head) break;
      page = /** @type {Page} */ (
        await request({
          after: chain.sequence,
          limit: Math.min(16, chain.head - chain.sequence),
        })
      );
    } while (index < 6250);
    chain.finish();
    await syncDirectory(path, io);
    const data = {
      schema: "xeip.owner-archive/1",
      source: config,
      headSequence: chain.head,
      headChecksum: chain.final,
      pages: index,
      records: chain.sequence,
      filesChecksum: files.digest("hex"),
      previous: witness,
    };
    const manifest = manifestValue({
      ...data,
      manifestChecksum: manifestHash(data),
    });
    await writeDurable(
      join(path, "manifest.json"),
      canonicalize(manifest) + "\n",
      io,
    );
    await syncDirectory(path, io);
    await syncDirectory(dirname(path), io);
    return manifest;
  } catch {
    throw new Error("archive collection failed");
  }
}

/** CLI collection uses only auditExport, on a single isolated validated session.
 * @param {{configPath:string,directory:string,remote?:boolean,previous?:string}} options */
export async function collectOwnerArchive({
  configPath,
  directory,
  remote = false,
  previous,
}) {
  try {
    return await withOwnerSession(
      { configPath, remote },
      ({ configuration, send }) =>
        collectArchive({
          directory,
          source: configuration,
          previous,
          readPage: async ({ after, limit }) => {
            const result = await send(
              JSON.stringify({
                operation: "auditExport",
                requestId: randomUUID(),
                after,
                limit,
              }),
            );
            if (result.ok !== true) throw Error();
            return result.audit;
          },
        }),
    );
  } catch {
    throw new Error("archive collection failed");
  }
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const [operation, first, second, mode, previous, ...extra] =
      process.argv.slice(2);
    let result;
    if (
      operation === "verify" &&
      first &&
      !second &&
      !mode &&
      !previous &&
      !extra.length
    )
      result = await verifyArchive(first);
    else if (
      operation === "collect" &&
      first &&
      second &&
      ["--local", "--remote"].includes(mode) &&
      !extra.length
    )
      result = await collectOwnerArchive({
        configPath: first,
        directory: second,
        remote: mode === "--remote",
        previous,
      });
    else throw Error();
    console.log(
      JSON.stringify({
        ok: true,
        operation,
        headSequence: result.headSequence,
        headChecksum: result.headChecksum,
        manifestChecksum: result.manifestChecksum,
        records: result.records,
        pages: result.pages,
      }),
    );
  } catch {
    console.error(
      "Archive failed; output may be incomplete or uncertain. Usage: node archive.mjs collect OPERATOR_CONFIG.json NEW_DIRECTORY --local|--remote [PREVIOUS_ARCHIVE], or verify DIRECTORY",
    );
    process.exitCode = 1;
  }
}
