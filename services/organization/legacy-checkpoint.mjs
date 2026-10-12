/** Read-only import of retained legacy trust while holding its existing lock. */
import * as fs from "node:fs";
import { join } from "node:path";
import {
  validateTrustDirectory,
  readLegacyTrustRecords,
} from "./configuration.mjs";
class CheckpointUnavailable extends Error {
  constructor() {
    super("legacy checkpoint unavailable");
  }
}
/** @param {string} directory */
export function openLegacyCheckpoint(directory) {
  let created = false;
  /** @type {number|undefined} */ let fd;
  /** @type {fs.Stats|undefined} */ let directoryInfo;
  /** @type {fs.Stats|undefined} */ let lockInfo;
  const lock = join(directory, "LOCK");
  let closed = false;
  const assertOwned = () => {
    if (closed || fd === undefined || !directoryInfo || !lockInfo)
      throw new CheckpointUnavailable();
    try {
      if (!validateTrustDirectory(directory)) throw new CheckpointUnavailable();
      const currentDirectory = fs.lstatSync(directory),
        currentLock = fs.lstatSync(lock);
      if (
        currentDirectory.dev !== directoryInfo.dev ||
        currentDirectory.ino !== directoryInfo.ino ||
        currentLock.dev !== lockInfo.dev ||
        currentLock.ino !== lockInfo.ino ||
        !currentLock.isFile()
      )
        throw new CheckpointUnavailable();
    } catch {
      throw new CheckpointUnavailable();
    }
  };
  const close = () => {
    if (closed) return;
    try {
      assertOwned();
      fs.unlinkSync(lock);
      if (created) fs.rmdirSync(directory);
    } catch {
      throw new CheckpointUnavailable();
    } finally {
      closed = true;
      if (fd !== undefined) fs.closeSync(fd);
    }
  };
  try {
    if (!validateTrustDirectory(directory)) {
      fs.mkdirSync(directory, { mode: 0o700 });
      created = true;
    }
    if (!validateTrustDirectory(directory)) throw new CheckpointUnavailable();
    directoryInfo = fs.lstatSync(directory);
    fd = fs.openSync(
      lock,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600,
    );
    lockInfo = fs.fstatSync(fd);
    fs.writeFileSync(fd, String(process.pid) + "\n");
    const records = created
      ? Object.freeze(Object.create(null))
      : readLegacyTrustRecords(directory);
    assertOwned();
    return Object.freeze({ records, assertOwned, close });
  } catch {
    if (fd !== undefined) {
      try {
        close();
      } catch {
        /* Retain an unconfirmed lock for operator inspection. */
      }
    }
    // Never remove a lock or directory created by another participant.
    throw new CheckpointUnavailable();
  }
}
