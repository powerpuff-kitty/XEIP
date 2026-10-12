/** Complete read-only journal bundles. Content evidence never authorizes restore or replay. */
import * as fs from "node:fs/promises";
import { join, resolve, dirname } from "node:path";
import { readJson, writeDurable, syncDirectory } from "./archive.mjs";
import {
  canonicalize,
  exact,
  integer,
  recoveryOptions,
  genesis,
  validateHead,
  validateEntry,
  validateAppend,
} from "./recovery-record.mjs";
/** @typedef {import('./recovery-record.mjs').Head} Head */
/** @typedef {import('./recovery-record.mjs').Entry} Entry */
/** @typedef {{url:string,options:Omit<import('./recovery-record.mjs').Options,'timeoutMs'>}} Source */
/** @typedef {{head:Head,manifestChecksum:string}} Witness */
/** @typedef {{schema:string,source:Source,head:Head,totalBytes:number,filesChecksum:string,previous:Witness|null,manifestChecksum:string}} Manifest */
/** @typedef {{head:()=>Promise<unknown>,entry:(sequence:number)=>Promise<unknown>,part:(sequence:number,index:number)=>Promise<unknown>}} Reader */
import {
  RECOVERY_FILE_BYTES,
  recoveryFilename,
  hash,
  filesHasher,
  seal,
  sourceCopy,
  manifestValue,
} from "./recovery-archive-record.mjs";
export {
  RECOVERY_FILE_BYTES,
  recoveryFilename,
} from "./recovery-archive-record.mjs";
/** Immutable archive reads fail on growth and allocate only the observed size.
 * @param {string} path */
export async function readRecoveryFile(path) {
  const size = integer((await fs.lstat(path)).size, 1, RECOVERY_FILE_BYTES);
  return readJson(path, size, fs);
}
class Chain {
  total = 0;
  ids = new Set();
  /** @param {Source} source @param {Head} target @param {Witness|null} previous */
  constructor(source, target, previous) {
    this.options = recoveryOptions(source.options);
    this.target = target;
    this.previous = previous;
    this.head = {
      organization: this.options.organization,
      stream: this.options.stream,
      sequence: 0,
      checksum: genesis(this.options),
    };
    if (
      previous?.head.sequence === 0 &&
      canonicalize(previous.head) !== canonicalize(this.head)
    )
      throw Error();
  }
  /** @param {unknown} value */
  accept(value) {
    const v = exact(value, ["entry", "chunks"]),
      entry = validateEntry(v.entry, this.options);
    if (
      entry.sequence !== this.head.sequence + 1 ||
      entry.sequence > this.target.sequence ||
      entry.previous !== this.head.checksum ||
      entry.totalBytes !== this.total + entry.bytes ||
      this.ids.has(entry.id)
    )
      throw Error();
    const { chunks } = validateAppend(
      {
        expected: this.head,
        id: entry.id,
        bytes: entry.bytes,
        payloadDigest: entry.payloadDigest,
        chunks: v.chunks,
      },
      this.options,
    );
    this.ids.add(entry.id);
    this.total = entry.totalBytes;
    this.head = {
      organization: entry.organization,
      stream: entry.stream,
      sequence: entry.sequence,
      checksum: entry.checksum,
    };
    if (
      this.previous?.head.sequence === entry.sequence &&
      canonicalize(this.previous.head) !== canonicalize(this.head)
    )
      throw Error();
    return { entry, chunks };
  }
  finish() {
    if (canonicalize(this.head) !== canonicalize(this.target)) throw Error();
  }
}
/** @param {string} directory @param {{previous?:string}} [settings] @returns {Promise<Manifest>} */
export async function verifyRecoveryArchive(directory, { previous } = {}) {
  try {
    const path = resolve(directory),
      stat = await fs.lstat(path);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (stat.mode & 0o077) !== 0
    )
      throw Error();
    const m = manifestValue(
      (await readJson(join(path, "manifest.json"), 16384, fs)).value,
    );
    if (previous !== undefined) {
      const prior = await verifyRecoveryArchive(previous);
      if (
        canonicalize(prior.source) !== canonicalize(m.source) ||
        canonicalize({
          head: prior.head,
          manifestChecksum: prior.manifestChecksum,
        }) !== canonicalize(m.previous)
      )
        throw Error();
    }
    let count = 0;
    for await (const entry of await fs.opendir(path)) {
      if (!entry.isFile() || ++count > m.head.sequence + 1) throw Error();
      if (entry.name === "manifest.json") continue;
      const n = Number(entry.name.slice(0, -5));
      if (
        !Number.isSafeInteger(n) ||
        n < 1 ||
        n > m.head.sequence ||
        recoveryFilename(n) !== entry.name
      )
        throw Error();
    }
    if (count !== m.head.sequence + 1) throw Error();
    const chain = new Chain(m.source, m.head, m.previous),
      files = filesHasher();
    for (let sequence = 1; sequence <= m.head.sequence; sequence++) {
      const name = recoveryFilename(sequence),
        { value, raw } = await readRecoveryFile(join(path, name));
      chain.accept(value);
      files.update(canonicalize([name, hash(raw)]));
    }
    chain.finish();
    if (chain.total !== m.totalBytes || files.digest("hex") !== m.filesChecksum)
      throw Error();
    return m;
  } catch {
    throw Error("invalid recovery archive");
  }
}
/** @param {{directory:string,source:unknown,client:Reader,previous?:string,io?:typeof fs,timeoutMs?:number}} settings @returns {Promise<Manifest>} */
export async function collectRecoveryArchive({
  directory,
  source,
  client,
  previous,
  io = fs,
  timeoutMs = 30000,
}) {
  try {
    integer(timeoutMs, 100, 30000);
    const config = sourceCopy(source),
      options = recoveryOptions(config.options);
    if (
      !client ||
      ["head", "entry", "part"].some(
        (k) => typeof client[/** @type {keyof Reader} */ (k)] !== "function",
      )
    )
      throw Error();
    /** @template T @param {()=>Promise<T>} work @returns {Promise<T>} */
    const request = async (work) => {
      let timer;
      const expires = performance.now() + timeoutMs;
      try {
        const value = await Promise.race([
          Promise.resolve().then(work),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error()), timeoutMs);
          }),
        ]);
        if (performance.now() >= expires) throw Error();
        return /** @type {T} */ (value);
      } finally {
        clearTimeout(timer);
      }
    };
    const prior =
      previous === undefined ? null : await verifyRecoveryArchive(previous);
    if (prior && canonicalize(prior.source) !== canonicalize(config))
      throw Error();
    const head = Object.freeze({
      ...validateHead(await request(() => client.head()), options),
    });
    if (head.sequence === 0 && head.checksum !== genesis(options))
      throw Error();
    if (prior && prior.head.sequence > head.sequence) throw Error();
    const witness = prior
      ? { head: prior.head, manifestChecksum: prior.manifestChecksum }
      : null;
    const chain = new Chain(config, head, witness),
      files = filesHasher(),
      path = resolve(directory);
    await io.mkdir(path, { mode: 0o700 });
    await syncDirectory(dirname(path), io);
    for (let sequence = 1; sequence <= head.sequence; sequence++) {
      const entry = validateEntry(
          await request(() => client.entry(sequence)),
          options,
        ),
        chunks = [];
      if (entry.sequence !== sequence) throw Error();
      for (let index = 0; index < entry.parts; index++) {
        const part = exact(await request(() => client.part(sequence, index)), [
          "entry",
          "part",
          "data",
        ]);
        if (
          part.part !== index ||
          canonicalize(part.entry) !== canonicalize(entry)
        )
          throw Error();
        chunks.push(part.data);
      }
      const record = chain.accept({ entry, chunks }),
        name = recoveryFilename(sequence),
        raw = canonicalize(record) + "\n";
      if (Buffer.byteLength(raw) > RECOVERY_FILE_BYTES) throw Error();
      await writeDurable(join(path, name), raw, io);
      files.update(canonicalize([name, hash(raw)]));
    }
    chain.finish();
    const final = validateHead(await request(() => client.head()), options);
    if (
      final.sequence < head.sequence ||
      (final.sequence === head.sequence && final.checksum !== head.checksum)
    )
      throw Error();
    if (head.sequence) {
      const entry = validateEntry(
        await request(() => client.entry(head.sequence)),
        options,
      );
      if (entry.sequence !== head.sequence || entry.checksum !== head.checksum)
        throw Error();
    }
    await syncDirectory(path, io);
    const data = {
      schema: "xeip.recovery-archive/1",
      source: config,
      head,
      totalBytes: chain.total,
      filesChecksum: files.digest("hex"),
      previous: witness,
    };
    const manifest = { ...data, manifestChecksum: seal(data) };
    await writeDurable(
      join(path, "manifest.json"),
      canonicalize(manifest) + "\n",
      io,
    );
    await syncDirectory(path, io);
    await syncDirectory(dirname(path), io);
    return manifest;
  } catch {
    throw Error("recovery archive collection failed");
  }
}
