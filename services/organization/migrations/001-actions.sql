CREATE TABLE xeip_org.actions (
  session_id text NOT NULL,
  request_id text NOT NULL,
  digest text NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
  canonical text NOT NULL CHECK (octet_length(canonical) <= 69632),
  expires_at bigint NOT NULL CHECK (expires_at >= 0),
  state text NOT NULL CHECK (state IN ('pending','approved','rejected','revoked','executing','succeeded','failed','indeterminate')),
  approver jsonb,
  approval_expires_at bigint,
  claim_id uuid UNIQUE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (session_id, request_id),
  CHECK ((state NOT IN ('approved','executing','succeeded','failed','indeterminate')) OR (approver IS NOT NULL AND approval_expires_at IS NOT NULL)),
  CHECK ((state IN ('executing','succeeded','failed','indeterminate')) = (claim_id IS NOT NULL))
);
CREATE TABLE xeip_org.audit (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  session_id text NOT NULL,
  request_id text NOT NULL,
  digest text NOT NULL,
  event text NOT NULL CHECK (event IN ('proposed','approved','rejected','revoked','claimed','succeeded','failed','indeterminate')),
  actor jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (session_id, request_id) REFERENCES xeip_org.actions(session_id, request_id)
);
CREATE INDEX audit_action ON xeip_org.audit(session_id, request_id, sequence);
CREATE FUNCTION xeip_org.protect_action() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'action deletion is not supported'; END IF;
  IF ROW(NEW.session_id,NEW.request_id,NEW.digest,NEW.canonical,NEW.expires_at,NEW.created_at)
     IS DISTINCT FROM ROW(OLD.session_id,OLD.request_id,OLD.digest,OLD.canonical,OLD.expires_at,OLD.created_at)
     THEN RAISE EXCEPTION 'immutable action content'; END IF;
  IF NOT ((OLD.state = 'pending' AND NEW.state IN ('approved','rejected','revoked'))
       OR (OLD.state = 'approved' AND NEW.state IN ('executing','revoked'))
       OR (OLD.state = 'executing' AND NEW.state IN ('succeeded','failed','indeterminate')))
     THEN RAISE EXCEPTION 'invalid action transition'; END IF;
  IF OLD.approver IS NOT NULL AND ROW(NEW.approver,NEW.approval_expires_at) IS DISTINCT FROM ROW(OLD.approver,OLD.approval_expires_at)
     THEN RAISE EXCEPTION 'immutable approval'; END IF;
  IF OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id
     THEN RAISE EXCEPTION 'immutable execution claim'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER protect_action BEFORE UPDATE OR DELETE ON xeip_org.actions FOR EACH ROW EXECUTE FUNCTION xeip_org.protect_action();
CREATE FUNCTION xeip_org.protect_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit records are append only'; END $$;
CREATE TRIGGER protect_audit BEFORE UPDATE OR DELETE ON xeip_org.audit FOR EACH ROW EXECUTE FUNCTION xeip_org.protect_audit();
