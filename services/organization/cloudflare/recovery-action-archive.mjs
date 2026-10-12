/** Interpret a complete journal bundle as historical action evidence, never live capabilities. */
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import { recoveryOptions } from "./recovery-record.mjs";
import {
  verifyRecoveryArchive,
  recoveryFilename,
  readRecoveryFile,
} from "./recovery-archive.mjs";
import { decodeActionRecovery } from "./action-recovery-record.mjs";
import { projectAction } from "./action-export.mjs";
/** @param {string} value */
const hash = (value) => createHash("sha256").update(value).digest("hex");
/** @param {string} directory @param {{previous?:string}} [settings] */
export async function verifyRecoveryActions(directory, settings = {}) {
  try {
    const manifest = await verifyRecoveryArchive(directory, settings),
      path = resolve(directory),
      options = recoveryOptions(manifest.source.options);
    /** @type {Map<string,{sequence:number,digest:string,state:string,claim:string|null}>} */
    const actions = new Map();
    /** @type {Record<string,number>} */
    const states = {
      pending: 0,
      approved: 0,
      rejected: 0,
      revoked: 0,
      executing: 0,
      succeeded: 0,
      failed: 0,
      indeterminate: 0,
    };
    const claims = new Set();
    // Recheck the manifest-bound file digest on this interpretation pass too.
    const files = createHash("sha256").update(
      "XEIP recovery archive files v1\n",
    );
    for (let sequence = 1; sequence <= manifest.head.sequence; sequence++) {
      const name = recoveryFilename(sequence),
        { value, raw } = await readRecoveryFile(join(path, name));
      files.update(canonicalize([name, hash(raw)]));
      const { entry, record } = decodeActionRecovery(value, options);
      if (entry.sequence !== sequence) throw Error();
      const key = canonicalize([record.row.session_id, record.row.request_id]),
        prior = actions.get(key);
      if (prior) {
        if (
          record.history.length < 2 ||
          Number(record.history.at(-2)?.sequence) !== prior.sequence ||
          hash(
            canonicalize(
              projectAction(record.row, record.history, prior.sequence),
            ),
          ) !== prior.digest
        )
          throw Error();
        states[prior.state]--;
      } else if (record.history.length !== 1 || actions.size >= 10000)
        throw Error();
      if (
        record.row.claim_id !== null &&
        prior?.claim !== record.row.claim_id
      ) {
        if (claims.has(record.row.claim_id)) throw Error();
        claims.add(record.row.claim_id);
      }
      states[record.row.state]++;
      actions.set(key, {
        sequence,
        digest: hash(canonicalize(record)),
        state: record.row.state,
        claim: record.row.claim_id,
      });
    }
    if (files.digest("hex") !== manifest.filesChecksum) throw Error();
    return {
      head: manifest.head,
      manifestChecksum: manifest.manifestChecksum,
      actions: actions.size,
      states,
      consumedClaims: claims.size,
    };
  } catch {
    throw Error("invalid recovery action history");
  }
}
