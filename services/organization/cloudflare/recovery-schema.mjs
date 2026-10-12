/** Isolated immutable journal schema; never installed in the action database. */
import { canonicalize, genesis, hash } from "./recovery-record.mjs";
import { StoreConflict, StoreUnavailable } from "../errors.mjs";
/** @typedef {import('./contracts.js').LedgerStorage} Storage */
/** @typedef {import('./recovery-record.mjs').Options} Options */
const ddl = `
CREATE TABLE xeip_recovery_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), canonical TEXT NOT NULL CHECK(length(canonical)<=2048)) STRICT;
CREATE TABLE xeip_recovery_entries(sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 1000000), id TEXT NOT NULL UNIQUE CHECK(length(id)=36), previous TEXT NOT NULL CHECK(length(previous)=64), bytes INTEGER NOT NULL CHECK(bytes BETWEEN 1 AND 16777216), parts INTEGER NOT NULL CHECK(parts BETWEEN 1 AND 64 AND parts=(bytes+262143)/262144), total_bytes INTEGER NOT NULL CHECK(total_bytes BETWEEN bytes AND 1073741824), checksum TEXT NOT NULL CHECK(length(checksum)=64), canonical TEXT NOT NULL CHECK(length(canonical)<=2048 AND json_valid(canonical)),
 CHECK(json_extract(canonical,'$.sequence') IS sequence AND json_extract(canonical,'$.id') IS id AND json_extract(canonical,'$.previous') IS previous AND json_extract(canonical,'$.bytes') IS bytes AND json_extract(canonical,'$.parts') IS parts AND json_extract(canonical,'$.totalBytes') IS total_bytes AND json_extract(canonical,'$.checksum') IS checksum)) STRICT;
CREATE TABLE xeip_recovery_chunks(sequence INTEGER NOT NULL REFERENCES xeip_recovery_entries(sequence), part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 63), data TEXT NOT NULL CHECK(length(CAST(data AS BLOB)) BETWEEN 4 AND 349528), PRIMARY KEY(sequence,part)) STRICT;
CREATE TRIGGER xeip_recovery_meta_insert BEFORE INSERT ON xeip_recovery_meta BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM xeip_recovery_meta) THEN RAISE(ABORT,'immutable metadata') END; END;
CREATE TRIGGER xeip_recovery_entry_insert BEFORE INSERT ON xeip_recovery_entries BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM xeip_recovery_meta) OR EXISTS(SELECT 1 FROM xeip_recovery_entries WHERE id=NEW.id) OR
 NEW.sequence != COALESCE((SELECT MAX(sequence)+1 FROM xeip_recovery_entries),1) OR
 NEW.previous IS NOT COALESCE((SELECT checksum FROM xeip_recovery_entries ORDER BY sequence DESC LIMIT 1),(SELECT json_extract(canonical,'$.genesis') FROM xeip_recovery_meta)) OR
 NEW.total_bytes != COALESCE((SELECT total_bytes FROM xeip_recovery_entries ORDER BY sequence DESC LIMIT 1),0)+NEW.bytes OR
 NEW.sequence > (SELECT json_extract(canonical,'$.maxEntries') FROM xeip_recovery_meta) OR NEW.total_bytes > (SELECT json_extract(canonical,'$.maxBytes') FROM xeip_recovery_meta)
 THEN RAISE(ABORT,'invalid recovery append') END; END;
CREATE TRIGGER xeip_recovery_chunk_insert BEFORE INSERT ON xeip_recovery_chunks BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM xeip_recovery_entries WHERE sequence=NEW.sequence AND NEW.part<parts) OR EXISTS(SELECT 1 FROM xeip_recovery_chunks WHERE sequence=NEW.sequence AND part=NEW.part) THEN RAISE(ABORT,'invalid recovery part') END; END;
${["meta", "entries", "chunks"].flatMap((table) => ["UPDATE", "DELETE"].map((op) => `CREATE TRIGGER xeip_recovery_${table}_${op.toLowerCase()} BEFORE ${op} ON xeip_recovery_${table} BEGIN SELECT RAISE(ABORT,'immutable recovery data'); END;`)).join("\n")}
`;
/** @param {Storage} storage */
const catalog = (storage) =>
  storage.sql
    .exec(
      "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name GLOB 'xeip_*' OR tbl_name GLOB 'xeip_*' ORDER BY type,name",
    )
    .toArray();
/** @param {Storage} storage @param {Options} o */
function metadata(storage, o) {
  return canonicalize({
    schemaVersion: 1,
    organization: o.organization,
    stream: o.stream,
    maxEntries: o.maxEntries,
    maxBytes: o.maxBytes,
    genesis: genesis(o),
    schemaChecksum: hash(ddl),
    catalogChecksum: hash(canonicalize(catalog(storage))),
  });
}
/** @param {Storage} storage @param {Options} o */
export function initializeRecoverySchema(storage, o) {
  if (catalog(storage).length) throw new StoreConflict();
  storage.transactionSync(() => {
    storage.sql.exec(ddl);
    storage.sql.exec(
      "INSERT INTO xeip_recovery_meta(singleton,canonical) VALUES(1,?)",
      metadata(storage, o),
    );
  });
}
/** @param {Storage} storage @param {Options} o */
export function verifyRecoverySchema(storage, o) {
  const rows = storage.sql
    .exec("SELECT singleton,canonical FROM xeip_recovery_meta")
    .toArray();
  if (
    rows.length !== 1 ||
    rows[0].singleton !== 1 ||
    rows[0].canonical !== metadata(storage, o)
  )
    throw new StoreUnavailable();
}
