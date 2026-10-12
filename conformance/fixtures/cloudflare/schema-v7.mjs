/** Experimental SQLite schema. Only the owning Durable Object may access it. */
import { createHash } from "node:crypto";
import { StoreUnavailable } from "../../../services/organization/errors.mjs";
const migration = `
CREATE TABLE xeip_metadata (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  organization_id TEXT NOT NULL,
  action_count INTEGER NOT NULL DEFAULT 0 CHECK(action_count BETWEEN 0 AND 10000)
) STRICT;
CREATE TABLE xeip_actions (
  session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 1 AND 128),
  request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 1 AND 128),
  digest TEXT NOT NULL CHECK(length(digest)=64 AND digest NOT GLOB '*[^0-9a-f]*'),
  canonical TEXT NOT NULL CHECK(json_valid(canonical) AND length(CAST(canonical AS BLOB))<=69632),
  expires_at INTEGER NOT NULL CHECK(expires_at BETWEEN 0 AND 9007199254740991),
  state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','revoked','executing','succeeded','failed','indeterminate')),
  version INTEGER NOT NULL DEFAULT 0 CHECK(version BETWEEN 0 AND 7),
  approver TEXT CHECK(approver IS NULL OR (json_valid(approver) AND length(CAST(approver AS BLOB))<=4096)),
  approval_expires_at INTEGER,
  claim_id TEXT UNIQUE CHECK(claim_id IS NULL OR length(claim_id)=36),
  result_canonical TEXT,
  PRIMARY KEY(session_id,request_id),
  CHECK(json_type(canonical,'$.session') IS 'text' AND json_extract(canonical,'$.session') IS session_id),
  CHECK(json_type(canonical,'$.id') IS 'text' AND json_extract(canonical,'$.id') IS request_id),
  CHECK(json_type(canonical,'$.expiresAt') IS 'integer' AND json_extract(canonical,'$.expiresAt') IS expires_at),
  CHECK((approver IS NULL)=(approval_expires_at IS NULL)),
  CHECK(approver IS NULL OR (json_type(approver,'$.expiresAt') IS 'integer' AND json_extract(approver,'$.expiresAt') IS approval_expires_at)),
  CHECK(state!='pending' OR approver IS NULL),
  CHECK(state NOT IN ('approved','executing','succeeded','failed','indeterminate') OR approver IS NOT NULL),
  CHECK((state IN ('executing','succeeded','failed','indeterminate'))=(claim_id IS NOT NULL)),
  CHECK(approval_expires_at IS NULL OR approval_expires_at BETWEEN 0 AND expires_at),
  CHECK(result_canonical IS NULL OR (state IN ('succeeded','failed') AND json_valid(result_canonical) AND length(CAST(result_canonical AS BLOB))<=131072))
) STRICT;
CREATE TABLE xeip_audit (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  event TEXT NOT NULL CHECK(event IN ('proposed','approved','rejected','revoked','claimed','succeeded','failed','indeterminate')),
  actor TEXT NOT NULL CHECK(json_valid(actor) AND length(CAST(actor AS BLOB))<=4096),
  occurred_at INTEGER NOT NULL,
  FOREIGN KEY(session_id,request_id) REFERENCES xeip_actions(session_id,request_id)
) STRICT;
CREATE INDEX xeip_audit_action ON xeip_audit(session_id,request_id,sequence);
CREATE TRIGGER xeip_action_new BEFORE INSERT ON xeip_actions BEGIN
  SELECT CASE WHEN NEW.state!='pending' OR NEW.version!=0 OR NEW.approver IS NOT NULL OR NEW.claim_id IS NOT NULL OR
    EXISTS(SELECT 1 FROM xeip_actions WHERE session_id=NEW.session_id AND request_id=NEW.request_id)
  THEN RAISE(ABORT,'action replacement or non-pending insertion unsupported') END;
END;
CREATE TRIGGER xeip_action_insert AFTER INSERT ON xeip_actions BEGIN
  UPDATE xeip_metadata SET action_count=action_count+1 WHERE singleton=1;
END;
CREATE TRIGGER xeip_action_delete BEFORE DELETE ON xeip_actions BEGIN
  SELECT RAISE(ABORT,'action deletion unsupported');
END;
CREATE TRIGGER xeip_action_update BEFORE UPDATE ON xeip_actions BEGIN
  SELECT CASE WHEN
    NEW.session_id IS NOT OLD.session_id OR NEW.request_id IS NOT OLD.request_id OR
    NEW.digest IS NOT OLD.digest OR NEW.canonical IS NOT OLD.canonical OR NEW.expires_at IS NOT OLD.expires_at OR
    NEW.version != OLD.version+1 OR
    NOT ((OLD.state='pending' AND NEW.state IN ('approved','rejected','revoked')) OR
         (OLD.state='approved' AND NEW.state IN ('executing','revoked')) OR
         (OLD.state='executing' AND NEW.state IN ('succeeded','failed','indeterminate'))) OR
    (NOT (OLD.state='pending' AND NEW.state IN ('approved','rejected')) AND
      (NEW.approver IS NOT OLD.approver OR NEW.approval_expires_at IS NOT OLD.approval_expires_at)) OR
    (NOT (OLD.state='approved' AND NEW.state='executing') AND NEW.claim_id IS NOT OLD.claim_id) OR
    (NEW.claim_id IS NOT NULL AND EXISTS(SELECT 1 FROM xeip_actions WHERE claim_id=NEW.claim_id AND
      (session_id!=OLD.session_id OR request_id!=OLD.request_id))) OR
    (OLD.state!='executing' AND NEW.result_canonical IS NOT OLD.result_canonical)
  THEN RAISE(ABORT,'immutable action or invalid transition') END;
END;
CREATE TRIGGER xeip_audit_digest BEFORE INSERT ON xeip_audit BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM xeip_audit WHERE sequence=NEW.sequence)
  THEN RAISE(ABORT,'audit replacement unsupported') END;
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM xeip_actions WHERE session_id=NEW.session_id AND request_id=NEW.request_id AND digest=NEW.digest)
  THEN RAISE(ABORT,'audit action mismatch') END;
END;
CREATE TRIGGER xeip_audit_update BEFORE UPDATE ON xeip_audit BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER xeip_audit_delete BEFORE DELETE ON xeip_audit BEGIN SELECT RAISE(ABORT,'immutable audit'); END;
CREATE TRIGGER xeip_scope_update BEFORE UPDATE OF organization_id ON xeip_metadata BEGIN SELECT RAISE(ABORT,'immutable organization'); END;
CREATE TRIGGER xeip_scope_delete BEFORE DELETE ON xeip_metadata BEGIN SELECT RAISE(ABORT,'immutable organization'); END;
CREATE TRIGGER xeip_scope_insert BEFORE INSERT ON xeip_metadata BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM xeip_metadata) THEN RAISE(ABORT,'organization replacement unsupported') END;
END;
`;
const trustMigration = `
CREATE TABLE xeip_trust_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  configuration TEXT NOT NULL CHECK(json_valid(configuration) AND length(CAST(configuration AS BLOB))<=65536),
  provisioning TEXT NOT NULL CHECK(json_valid(provisioning) AND length(CAST(provisioning AS BLOB))<=8388608),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),
  accepted_at INTEGER NOT NULL CHECK(accepted_at BETWEEN 0 AND 9007199254740991),
  checkpoints_digest TEXT NOT NULL CHECK(length(checkpoints_digest)=64 AND checkpoints_digest NOT GLOB '*[^0-9a-f]*'),
  checksum TEXT NOT NULL CHECK(length(checksum)=64 AND checksum NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TABLE xeip_trust_checkpoints (
  entity TEXT PRIMARY KEY CHECK(length(entity) BETWEEN 1 AND 2048),
  anchor TEXT NOT NULL CHECK(length(anchor)=64 AND anchor NOT GLOB '*[^0-9a-f]*'),
  generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
  key_digest TEXT NOT NULL CHECK(length(key_digest)=64 AND key_digest NOT GLOB '*[^0-9a-f]*'),
  serial INTEGER NOT NULL CHECK(serial BETWEEN 0 AND 9007199254740991),
  status_digest TEXT NOT NULL CHECK(length(status_digest)=64 AND status_digest NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TRIGGER xeip_trust_state_insert BEFORE INSERT ON xeip_trust_state BEGIN
  SELECT CASE WHEN NEW.revision!=0 OR EXISTS(SELECT 1 FROM xeip_trust_state)
  THEN RAISE(ABORT,'trust state replacement unsupported') END;
END;
CREATE TRIGGER xeip_trust_state_update BEFORE UPDATE ON xeip_trust_state BEGIN
  SELECT CASE WHEN NEW.singleton!=OLD.singleton OR NEW.configuration IS NOT OLD.configuration OR
    NEW.revision!=OLD.revision+1 OR NEW.accepted_at<OLD.accepted_at
  THEN RAISE(ABORT,'invalid trust state update') END;
END;
CREATE TRIGGER xeip_trust_state_delete BEFORE DELETE ON xeip_trust_state BEGIN SELECT RAISE(ABORT,'trust state deletion unsupported'); END;
CREATE TRIGGER xeip_trust_checkpoint_insert BEFORE INSERT ON xeip_trust_checkpoints BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM xeip_trust_checkpoints WHERE entity=NEW.entity) OR
    (SELECT COUNT(*) FROM xeip_trust_checkpoints)>=4096
  THEN RAISE(ABORT,'checkpoint replacement or capacity exceeded') END;
END;
CREATE TRIGGER xeip_trust_checkpoint_update BEFORE UPDATE ON xeip_trust_checkpoints BEGIN
  SELECT CASE WHEN NEW.entity IS NOT OLD.entity OR NEW.anchor IS NOT OLD.anchor OR NEW.generation<OLD.generation OR
    NEW.serial<OLD.serial OR (NEW.generation=OLD.generation AND NEW.key_digest IS NOT OLD.key_digest) OR
    (NEW.serial=OLD.serial AND NEW.status_digest IS NOT OLD.status_digest)
  THEN RAISE(ABORT,'checkpoint rollback or fork') END;
END;
CREATE TRIGGER xeip_trust_checkpoint_delete BEFORE DELETE ON xeip_trust_checkpoints BEGIN SELECT RAISE(ABORT,'checkpoint deletion unsupported'); END;
`;
const authorityMigration = `
CREATE TABLE xeip_authority_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),
  configuration TEXT NOT NULL CHECK(json_valid(configuration) AND length(CAST(configuration AS BLOB))<=1048576),
  checksum TEXT NOT NULL CHECK(length(checksum)=64 AND checksum NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TABLE xeip_authority_events (
  revision INTEGER PRIMARY KEY CHECK(revision BETWEEN 0 AND 9007199254740991),
  configuration_digest TEXT NOT NULL CHECK(length(configuration_digest)=64 AND configuration_digest NOT GLOB '*[^0-9a-f]*'),
  previous_checksum TEXT NOT NULL CHECK(length(previous_checksum)=64 AND previous_checksum NOT GLOB '*[^0-9a-f]*'),
  checksum TEXT NOT NULL CHECK(length(checksum)=64 AND checksum NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TRIGGER xeip_authority_new BEFORE INSERT ON xeip_authority_state BEGIN
  SELECT CASE WHEN NEW.revision!=0 OR EXISTS(SELECT 1 FROM xeip_authority_state) OR EXISTS(SELECT 1 FROM xeip_authority_events)
  THEN RAISE(ABORT,'authority reset unsupported') END;
END;
CREATE TRIGGER xeip_authority_update BEFORE UPDATE ON xeip_authority_state BEGIN
  SELECT CASE WHEN NEW.singleton!=OLD.singleton OR NEW.revision!=OLD.revision+1
  THEN RAISE(ABORT,'invalid authority revision') END;
END;
CREATE TRIGGER xeip_authority_delete BEFORE DELETE ON xeip_authority_state BEGIN SELECT RAISE(ABORT,'authority deletion unsupported'); END;
CREATE TRIGGER xeip_authority_event_new BEFORE INSERT ON xeip_authority_events BEGIN
  SELECT CASE WHEN NEW.revision!=COALESCE((SELECT MAX(revision)+1 FROM xeip_authority_events),0) OR
    NEW.previous_checksum IS NOT COALESCE((SELECT checksum FROM xeip_authority_events ORDER BY revision DESC LIMIT 1),'0000000000000000000000000000000000000000000000000000000000000000') OR
    NOT EXISTS(SELECT 1 FROM xeip_authority_state WHERE revision=NEW.revision AND checksum=NEW.checksum)
  THEN RAISE(ABORT,'invalid authority event') END;
END;
CREATE TRIGGER xeip_authority_event_update BEFORE UPDATE ON xeip_authority_events BEGIN SELECT RAISE(ABORT,'immutable authority event'); END;
CREATE TRIGGER xeip_authority_event_delete BEFORE DELETE ON xeip_authority_events BEGIN SELECT RAISE(ABORT,'immutable authority event'); END;
`;
const serviceMigration = `
CREATE TABLE xeip_service_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  runtime_configuration TEXT NOT NULL CHECK(json_valid(runtime_configuration)),
  initial_authority TEXT NOT NULL CHECK(json_valid(initial_authority)),
  checksum TEXT NOT NULL CHECK(length(checksum)=64 AND checksum NOT GLOB '*[^0-9a-f]*'),
  phase TEXT NOT NULL CHECK(phase IN ('initializing','initialized')),
  CHECK(length(CAST(runtime_configuration AS BLOB))+length(CAST(initial_authority AS BLOB))<=2097152)
) STRICT;
CREATE TRIGGER xeip_service_new BEFORE INSERT ON xeip_service_state BEGIN
  SELECT CASE WHEN NEW.phase!='initializing' OR EXISTS(SELECT 1 FROM xeip_service_state)
  THEN RAISE(ABORT,'service replacement unsupported') END;
END;
CREATE TRIGGER xeip_service_update BEFORE UPDATE ON xeip_service_state BEGIN
  SELECT CASE WHEN NEW.singleton!=OLD.singleton OR
    NEW.runtime_configuration IS NOT OLD.runtime_configuration OR NEW.initial_authority IS NOT OLD.initial_authority OR
    NEW.checksum IS NOT OLD.checksum OR OLD.phase!='initializing' OR NEW.phase!='initialized'
  THEN RAISE(ABORT,'invalid service transition') END;
END;
CREATE TRIGGER xeip_service_delete BEFORE DELETE ON xeip_service_state BEGIN SELECT RAISE(ABORT,'service deletion unsupported'); END;
`;
const ownerMigration = `
CREATE TABLE xeip_owner_events (
  sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 100000),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id)=36),
  outcome TEXT NOT NULL CHECK(outcome IN ('started','completed','conflict','invalid_request','unavailable')),
  canonical TEXT NOT NULL CHECK(json_valid(canonical) AND length(CAST(canonical AS BLOB))<=2048),
  previous TEXT NOT NULL CHECK(length(previous)=64 AND previous NOT GLOB '*[^0-9a-f]*'),
  checksum TEXT NOT NULL CHECK(length(checksum)=64 AND checksum NOT GLOB '*[^0-9a-f]*'),
  CHECK(json_type(canonical,'$.attemptId') IS 'text' AND json_extract(canonical,'$.attemptId') IS attempt_id),
  CHECK(json_type(canonical,'$.outcome') IS 'text' AND json_extract(canonical,'$.outcome') IS outcome)
) STRICT;
CREATE UNIQUE INDEX xeip_owner_start ON xeip_owner_events(attempt_id) WHERE outcome='started';
CREATE UNIQUE INDEX xeip_owner_finish ON xeip_owner_events(attempt_id) WHERE outcome!='started';
CREATE TRIGGER xeip_owner_new BEFORE INSERT ON xeip_owner_events BEGIN
  SELECT CASE WHEN NEW.sequence!=(SELECT COALESCE(MAX(sequence),0)+1 FROM xeip_owner_events) OR
    NEW.previous!=COALESCE((SELECT checksum FROM xeip_owner_events ORDER BY sequence DESC LIMIT 1),'0000000000000000000000000000000000000000000000000000000000000000') OR
    (NEW.outcome='started' AND EXISTS(SELECT 1 FROM xeip_owner_events WHERE attempt_id=NEW.attempt_id AND outcome='started')) OR
    (NEW.outcome!='started' AND EXISTS(SELECT 1 FROM xeip_owner_events WHERE attempt_id=NEW.attempt_id AND outcome!='started')) OR
    (NEW.outcome!='started' AND NOT EXISTS(SELECT 1 FROM xeip_owner_events WHERE attempt_id=NEW.attempt_id AND outcome='started'))
  THEN RAISE(ABORT,'invalid owner journal insertion') END;
END;
CREATE TRIGGER xeip_owner_update BEFORE UPDATE ON xeip_owner_events BEGIN SELECT RAISE(ABORT,'immutable owner journal'); END;
CREATE TRIGGER xeip_owner_delete BEFORE DELETE ON xeip_owner_events BEGIN SELECT RAISE(ABORT,'immutable owner journal'); END;
`;
const trustChunkMigration = `
CREATE TABLE xeip_trust_chunks (
  revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991),
  part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 31),
  data TEXT NOT NULL CHECK(length(CAST(data AS BLOB)) BETWEEN 1 AND 349528 AND data NOT GLOB '*[^A-Za-z0-9+/=]*'),
  PRIMARY KEY(revision,part)
) STRICT;
CREATE TRIGGER xeip_trust_chunk_new BEFORE INSERT ON xeip_trust_chunks BEGIN
  SELECT CASE WHEN NEW.revision IS NOT (SELECT revision FROM xeip_trust_state WHERE singleton=1) OR
    (SELECT json_extract(provisioning,'$.schema') FROM xeip_trust_state WHERE singleton=1) IS NOT 'xeip.trust-chunks/1' OR
    NEW.part >= COALESCE((SELECT json_extract(provisioning,'$.parts') FROM xeip_trust_state WHERE singleton=1),0) OR
    EXISTS(SELECT 1 FROM xeip_trust_chunks WHERE revision=NEW.revision AND part=NEW.part)
  THEN RAISE(ABORT,'invalid trust chunk insertion') END;
END;
CREATE TRIGGER xeip_trust_chunk_update BEFORE UPDATE ON xeip_trust_chunks BEGIN SELECT RAISE(ABORT,'immutable trust chunk'); END;
CREATE TRIGGER xeip_trust_chunk_delete BEFORE DELETE ON xeip_trust_chunks BEGIN
  SELECT CASE WHEN OLD.revision >= COALESCE((SELECT revision FROM xeip_trust_state WHERE singleton=1),-1)
  THEN RAISE(ABORT,'current trust chunk deletion unsupported') END;
END;
`;
const actionRecoveryMigration = `
CREATE TABLE xeip_action_recovery (singleton INTEGER PRIMARY KEY CHECK(singleton=1), canonical TEXT NOT NULL CHECK(length(canonical)<=2048 AND json_valid(canonical))) STRICT;
CREATE TRIGGER xeip_action_recovery_insert BEFORE INSERT ON xeip_action_recovery BEGIN
 SELECT CASE WHEN EXISTS(SELECT 1 FROM xeip_action_recovery) OR EXISTS(SELECT 1 FROM xeip_actions) OR EXISTS(SELECT 1 FROM xeip_audit)
 THEN RAISE(ABORT,'recovery enrollment requires empty source') END; END;
CREATE TRIGGER xeip_action_recovery_update BEFORE UPDATE ON xeip_action_recovery BEGIN SELECT RAISE(ABORT,'immutable recovery binding'); END;
CREATE TRIGGER xeip_action_recovery_delete BEFORE DELETE ON xeip_action_recovery BEGIN SELECT RAISE(ABORT,'immutable recovery binding'); END;
`;
const actionRecoveryChecksum = createHash("sha256")
  .update(
    migration +
      trustMigration +
      authorityMigration +
      serviceMigration +
      ownerMigration +
      trustChunkMigration +
      actionRecoveryMigration,
  )
  .digest("hex");
const trustChunkChecksum = createHash("sha256")
  .update(
    migration +
      trustMigration +
      authorityMigration +
      serviceMigration +
      ownerMigration +
      trustChunkMigration,
  )
  .digest("hex");
const ownerChecksum = createHash("sha256")
  .update(
    migration +
      trustMigration +
      authorityMigration +
      serviceMigration +
      ownerMigration,
  )
  .digest("hex");
const serviceChecksum = createHash("sha256")
  .update(migration + trustMigration + authorityMigration + serviceMigration)
  .digest("hex");
const authorityChecksum = createHash("sha256")
  .update(migration + trustMigration + authorityMigration)
  .digest("hex");
const checksum = createHash("sha256").update(migration).digest("hex");
const trustChecksum = createHash("sha256")
  .update(migration + trustMigration)
  .digest("hex");
/** @param {import('./contracts.js').LedgerStorage} storage */
const catalog = (storage) =>
  createHash("sha256")
    .update(
      JSON.stringify(
        storage.sql
          .exec(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE (name GLOB 'xeip_*' OR tbl_name GLOB 'xeip_*') AND sql IS NOT NULL ORDER BY type,name",
          )
          .toArray(),
      ),
    )
    .digest("hex");
/** Read-only schema check for journal access; never initializes or upgrades storage.
 * @param {import('./contracts.js').LedgerStorage} storage */
export function verifyLedgerSchema(storage) {
  try {
    const rows = storage.sql
      .exec("SELECT version,checksum,catalog_checksum FROM xeip_schema")
      .toArray();
    if (
      rows.length !== 1 ||
      rows[0].version !== 7 ||
      rows[0].checksum !== actionRecoveryChecksum ||
      rows[0].catalog_checksum !== catalog(storage)
    )
      throw new StoreUnavailable();
  } catch {
    throw new StoreUnavailable();
  }
}
/** Must run inside object construction before accepting any operation.
 * @param {import('./contracts.js').LedgerStorage} storage @param {string} organization
 */
export function initializeLedger(storage, organization) {
  if (
    typeof organization !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(organization)
  )
    throw new StoreUnavailable();
  try {
    storage.transactionSync(() => {
      storage.sql.exec(
        "CREATE TABLE IF NOT EXISTS xeip_schema(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,catalog_checksum TEXT NOT NULL) STRICT",
      );
      const rows = storage.sql
        .exec(
          "SELECT version,checksum,catalog_checksum FROM xeip_schema ORDER BY version",
        )
        .toArray();
      if (rows.length > 1) throw new StoreUnavailable();
      const installed = rows[0];
      let version = 0;
      if (installed) {
        if (
          (installed.version !== 1 &&
            installed.version !== 2 &&
            installed.version !== 3 &&
            installed.version !== 4 &&
            installed.version !== 5 &&
            installed.version !== 6 &&
            installed.version !== 7) ||
          installed.checksum !==
            (installed.version === 1
              ? checksum
              : installed.version === 2
                ? trustChecksum
                : installed.version === 3
                  ? authorityChecksum
                  : installed.version === 4
                    ? serviceChecksum
                    : installed.version === 5
                      ? ownerChecksum
                      : installed.version === 6
                        ? trustChunkChecksum
                        : actionRecoveryChecksum) ||
          installed.catalog_checksum !== catalog(storage)
        )
          throw new StoreUnavailable();
        version = installed.version;
      }
      if (version === 0) {
        storage.sql.exec(migration);
        storage.sql.exec(
          "INSERT INTO xeip_metadata(singleton,organization_id) VALUES (1,?)",
          organization,
        );
        storage.sql.exec(
          "INSERT INTO xeip_schema(version,checksum,catalog_checksum) VALUES (1,?,?)",
          checksum,
          catalog(storage),
        );
      }
      if (version < 2) {
        storage.sql.exec(trustMigration);
        storage.sql.exec(
          "UPDATE xeip_schema SET version=2,checksum=?,catalog_checksum=?",
          trustChecksum,
          catalog(storage),
        );
      }
      if (version < 3) {
        storage.sql.exec(authorityMigration);
        storage.sql.exec(
          "UPDATE xeip_schema SET version=3,checksum=?,catalog_checksum=?",
          authorityChecksum,
          catalog(storage),
        );
      }
      if (version < 4) {
        storage.sql.exec(serviceMigration);
        storage.sql.exec(
          "UPDATE xeip_schema SET version=4,checksum=?,catalog_checksum=?",
          serviceChecksum,
          catalog(storage),
        );
      }
      if (version < 5) {
        storage.sql.exec(ownerMigration);
        storage.sql.exec(
          "UPDATE xeip_schema SET version=5,checksum=?,catalog_checksum=?",
          ownerChecksum,
          catalog(storage),
        );
      }
      if (version < 6) {
        storage.sql.exec(trustChunkMigration);
        storage.sql.exec(
          "UPDATE xeip_schema SET version=6,checksum=?,catalog_checksum=?",
          trustChunkChecksum,
          catalog(storage),
        );
      }
      if (version < 7) {
        storage.sql.exec(actionRecoveryMigration);
        storage.sql.exec(
          "UPDATE xeip_schema SET version=7,checksum=?,catalog_checksum=?",
          actionRecoveryChecksum,
          catalog(storage),
        );
      }
      const metadata = storage.sql
        .exec(
          "SELECT organization_id,action_count FROM xeip_metadata WHERE singleton=1",
        )
        .toArray();
      if (
        metadata.length !== 1 ||
        metadata[0].organization_id !== organization ||
        metadata[0].action_count !==
          storage.sql
            .exec("SELECT COUNT(*) AS count FROM xeip_actions")
            .toArray()[0].count
      )
        throw new StoreUnavailable();
    });
  } catch {
    throw new StoreUnavailable();
  }
}
