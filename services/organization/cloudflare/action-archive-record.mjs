/** Portable historical action sequence verification; no filesystem or operator access. */
import { canonicalize } from "../../../sdks/typescript/dist/identity.js";
import {
  validateActionEvidence,
  actionSnapshotHasher,
  projectAction,
} from "./action-export.mjs";
/** @typedef {import('./action-export.mjs').ActionSnapshot} Snapshot */
/** @typedef {{cut:number,actions:number,digest:string,manifestChecksum:string}} Witness */
export class ActionArchiveVerifier {
  count = 0;
  after = 0;
  priorCount = 0;
  keys = new Set();
  sequences = new Set();
  /** @param {Snapshot} snapshot @param {Witness|null} previous */
  constructor(snapshot, previous) {
    this.snapshot = snapshot;
    this.previous = previous;
    const { digest, ...header } = snapshot;
    this.current = actionSnapshotHasher(header);
    this.prior = previous
      ? actionSnapshotHasher({
          schema: snapshot.schema,
          organization: snapshot.organization,
          cut: previous.cut,
          actions: previous.actions,
        })
      : null;
  }
  /** @param {unknown} value */
  accept(value) {
    const record = validateActionEvidence(value, this.snapshot.cut),
      first = Number(record.history[0].sequence),
      key = canonicalize([record.row.session_id, record.row.request_id]);
    if (
      ++this.count > this.snapshot.actions ||
      first <= this.after ||
      this.keys.has(key)
    )
      throw Error();
    this.keys.add(key);
    this.after = first;
    for (const event of record.history) {
      if (this.sequences.has(event.sequence)) throw Error();
      this.sequences.add(event.sequence);
    }
    this.current.update(canonicalize(record) + "\n");
    if (this.previous && first <= this.previous.cut) {
      this.priorCount++;
      this.prior?.update(
        canonicalize(
          projectAction(record.row, record.history, this.previous.cut),
        ) + "\n",
      );
    }
  }
  finish() {
    if (
      this.count !== this.snapshot.actions ||
      this.current.digest("hex") !== this.snapshot.digest
    )
      throw Error();
    if (
      this.previous &&
      (this.priorCount !== this.previous.actions ||
        this.prior?.digest("hex") !== this.previous.digest)
    )
      throw Error();
  }
}
