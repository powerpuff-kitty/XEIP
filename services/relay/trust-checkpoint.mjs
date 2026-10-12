/** Owner-only, single-writer checkpoint for experimental entity trust. */
import * as fs from "node:fs";
import * as path from "node:path";
import { strictParse } from "../../packages/identity/signed-envelope.mjs";
import {
  validateTrustRecords as records,
  mergeTrustRecords,
} from "../../packages/identity/trust-state.mjs";
const object = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
function writeAll(fd, data) {
  const bytes = Buffer.from(data);
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (count <= 0) throw new Error("trust checkpoint write made no progress");
    offset += count;
  }
}
function syncDirectory(dir) {
  const fd = fs.openSync(dir, "r");
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}
export class TrustCheckpoint {
  #lock;
  #owned = false;
  #previous = Object.create(null);
  #dir;
  #failed = false;
  constructor(directory, candidates, chainDigests = {}) {
    if (typeof directory !== "string" || !directory)
      throw new TypeError("trustDir is required");
    records(candidates);
    const dir = path.resolve(directory);
    this.#dir = dir;
    this.#lock = path.join(dir, "LOCK");
    fs.mkdirSync(path.dirname(dir), { recursive: true, mode: 0o700 });
    let fresh = false;
    try {
      fs.mkdirSync(dir, { mode: 0o700 });
      fresh = true;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    try {
      let lockFd;
      try {
        lockFd = fs.openSync(this.#lock, "wx", 0o600);
      } catch (error) {
        if (error.code === "EEXIST")
          throw new Error("trust checkpoint is locked");
        throw error;
      }
      this.#owned = true;
      try {
        writeAll(lockFd, String(process.pid) + "\n");
      } finally {
        fs.closeSync(lockFd);
      }
      const file = path.join(dir, "trust.json");
      let previous = Object.create(null);
      if (!fresh) {
        try {
          if (fs.statSync(file).size > 8 * 1024 * 1024)
            throw new Error("oversize");
          const checkpoint = strictParse(fs.readFileSync(file, "utf8"));
          if (
            !object(checkpoint) ||
            checkpoint.version !== 1 ||
            Object.keys(checkpoint).sort().join(",") !== "entities,version"
          )
            throw new Error("shape");
          previous = records(checkpoint.entities);
        } catch (error) {
          throw new Error("missing or invalid trust checkpoint", {
            cause: error,
          });
        }
      }
      this.#previous = previous;
      this.update(candidates, chainDigests);
      if (fresh) syncDirectory(path.dirname(dir));
    } catch (error) {
      this.close();
      throw error;
    }
  }
  get healthy() {
    return this.#owned && !this.#failed;
  }
  update(candidates, chainDigests = {}) {
    if (!this.#owned) throw new Error("trust checkpoint is closed");
    if (this.#failed)
      throw new Error("trust checkpoint failed; reopen required");
    const merged = mergeTrustRecords(this.#previous, candidates, chainDigests);
    const data = JSON.stringify({ version: 1, entities: merged });
    if (Buffer.byteLength(data) > 8 * 1024 * 1024)
      throw new Error("oversize trust checkpoint");
    const file = path.join(this.#dir, "trust.json");
    try {
      const fd = fs.openSync(file + ".tmp", "w", 0o600);
      try {
        writeAll(fd, data);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(file + ".tmp", file);
      syncDirectory(this.#dir);
      this.#previous = merged;
    } catch (error) {
      this.#failed = true;
      throw error;
    }
  }
  close() {
    if (!this.#owned) return;
    this.#owned = false;
    try {
      fs.unlinkSync(this.#lock);
    } catch {
      /* stale ownership is operator-visible on reopen */
    }
  }
}
