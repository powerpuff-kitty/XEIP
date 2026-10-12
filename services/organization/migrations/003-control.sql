-- Public control snapshots share the action ledger's WAL and durability boundary.
CREATE TABLE xeip_org.control_events (
  revision bigint PRIMARY KEY CHECK (revision BETWEEN 1 AND 9007199254740991),
  previous_digest text NOT NULL CHECK (previous_digest ~ '^[a-f0-9]{64}$'),
  state_canonical text NOT NULL CHECK (octet_length(convert_to(state_canonical,'UTF8')) <= 25165824),
  state_digest text NOT NULL CHECK (
    state_digest = encode(sha256(convert_to(E'XEIP organization control state v1\n' || state_canonical,'UTF8')),'hex')
  ),
  digest text NOT NULL CHECK (
    digest = encode(sha256(convert_to(E'XEIP organization control event v1\n' || revision::text || E'\n' || previous_digest || E'\n' || state_digest,'UTF8')),'hex')
  ),
  UNIQUE (revision,digest)
);
CREATE TABLE xeip_org.control_head (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  revision bigint NOT NULL,
  digest text NOT NULL,
  FOREIGN KEY (revision,digest) REFERENCES xeip_org.control_events(revision,digest)
);

CREATE FUNCTION xeip_org.protect_control_event() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE
  head xeip_org.control_head%ROWTYPE;
  previous jsonb;
  candidate jsonb;
  operation text;
  entity text;
  old_record jsonb;
  next_record jsonb;
  owner_name name;
BEGIN
  IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'control history is append only'; END IF;
  PERFORM pg_advisory_xact_lock(1480935760,2);
  SELECT * INTO head FROM xeip_org.control_head WHERE singleton FOR UPDATE;
  candidate := NEW.state_canonical::jsonb;
  operation := candidate->>'operation';
  IF candidate->>'v' IS DISTINCT FROM 'xeip.org.control/1'
     OR operation IS NULL OR operation NOT IN ('enroll','authority','trust')
     OR jsonb_typeof(candidate->'authority') IS DISTINCT FROM 'object'
     OR jsonb_typeof(candidate->'provisioning') IS DISTINCT FROM 'object'
     OR jsonb_typeof(candidate->'records') IS DISTINCT FROM 'object'
     OR jsonb_typeof(candidate->'targetRevisions') IS DISTINCT FROM 'array'
     OR jsonb_typeof(candidate->'acceptedAt') IS DISTINCT FROM 'number'
     THEN RAISE EXCEPTION 'invalid control state'; END IF;
  SELECT pg_get_userbyid(relowner) INTO owner_name FROM pg_class WHERE oid=TG_RELID;
  IF operation <> 'trust' AND current_user <> owner_name
     THEN RAISE EXCEPTION 'owner control operation required'; END IF;
  IF head.revision IS NULL THEN
    IF operation <> 'enroll' OR NEW.revision <> 1 OR NEW.previous_digest <> repeat('0',64)
       THEN RAISE EXCEPTION 'control enrollment required'; END IF;
    -- Prevent an action arriving between the emptiness check and enrollment.
    LOCK TABLE xeip_org.actions,xeip_org.audit IN SHARE ROW EXCLUSIVE MODE;
    IF EXISTS(SELECT 1 FROM xeip_org.actions) OR EXISTS(SELECT 1 FROM xeip_org.audit)
       THEN RAISE EXCEPTION 'legacy organization requires reconciliation'; END IF;
  ELSE
    IF operation = 'enroll' OR NEW.revision <> head.revision+1 OR NEW.previous_digest <> head.digest
       THEN RAISE EXCEPTION 'control head conflict'; END IF;
    SELECT state_canonical::jsonb INTO STRICT previous FROM xeip_org.control_events WHERE revision=head.revision AND digest=head.digest;
    IF candidate->'authority'->>'gateway' IS DISTINCT FROM previous->'authority'->>'gateway'
       OR (candidate->>'acceptedAt')::bigint < (previous->>'acceptedAt')::bigint
       OR NOT ((candidate->'targetRevisions') @> (previous->'targetRevisions'))
       THEN RAISE EXCEPTION 'control history rollback'; END IF;
    FOR entity,old_record IN SELECT key,value FROM jsonb_each(previous->'records') LOOP
      next_record := candidate->'records'->entity;
      IF next_record IS NULL
         OR jsonb_typeof(next_record->'generation') IS DISTINCT FROM 'number'
         OR jsonb_typeof(next_record->'serial') IS DISTINCT FROM 'number'
         OR (next_record->>'generation')::numeric <> trunc((next_record->>'generation')::numeric)
         OR (next_record->>'serial')::numeric <> trunc((next_record->>'serial')::numeric)
         OR (next_record->>'generation')::numeric NOT BETWEEN 1 AND 9007199254740991
         OR (next_record->>'serial')::numeric NOT BETWEEN 0 AND 9007199254740991
         OR next_record->>'anchor' IS DISTINCT FROM old_record->>'anchor'
         OR (next_record->>'generation')::bigint < (old_record->>'generation')::bigint
         OR (next_record->>'serial')::bigint < (old_record->>'serial')::bigint
         OR ((next_record->>'generation')::bigint = (old_record->>'generation')::bigint
             AND next_record->>'keyDigest' IS DISTINCT FROM old_record->>'keyDigest')
         OR ((next_record->>'serial')::bigint = (old_record->>'serial')::bigint
             AND next_record->>'statusDigest' IS DISTINCT FROM old_record->>'statusDigest')
         THEN RAISE EXCEPTION 'control trust rollback'; END IF;
    END LOOP;
    IF operation='trust' THEN
      IF candidate->'authority' IS DISTINCT FROM previous->'authority'
         OR candidate->>'authorityDigest' IS DISTINCT FROM previous->>'authorityDigest'
         OR candidate->'targetRevisions' IS DISTINCT FROM previous->'targetRevisions'
         THEN RAISE EXCEPTION 'owner authority operation required'; END IF;
      IF EXISTS (
        SELECT 1 FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS fresh
        WHERE NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(previous->'provisioning'->'keyDocuments') AS prior_entity
          WHERE prior_entity->'document'->>'entity'=fresh->'document'->>'entity'
        )
      ) THEN RAISE EXCEPTION 'owner entity enrollment required'; END IF;
      -- Counters alone cannot distinguish a longer, separately signed fork.
      -- Full signed documents (including signatures) define chain identity.
      -- An active chain retains its accepted prefix; removal is still allowed.
      IF EXISTS (
        SELECT 1 FROM jsonb_array_elements(previous->'provisioning'->'keyDocuments') AS prior_entry
        WHERE EXISTS (
          SELECT 1 FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS active_entry
          WHERE active_entry->'document'->>'entity'=prior_entry->'document'->>'entity'
        ) AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS retained_entry
          WHERE retained_entry->'document'=prior_entry->'document'
        )
      ) THEN RAISE EXCEPTION 'control key chain replacement'; END IF;
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER protect_control_event BEFORE INSERT OR UPDATE OR DELETE ON xeip_org.control_events
FOR EACH ROW EXECUTE FUNCTION xeip_org.protect_control_event();
CREATE TRIGGER protect_control_event_truncate BEFORE TRUNCATE ON xeip_org.control_events
FOR EACH STATEMENT EXECUTE FUNCTION xeip_org.protect_control_event();

CREATE FUNCTION xeip_org.protect_control_head() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE event xeip_org.control_events%ROWTYPE;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'control head deletion is not supported'; END IF;
  SELECT * INTO STRICT event FROM xeip_org.control_events WHERE revision=NEW.revision AND digest=NEW.digest;
  IF TG_OP='INSERT' THEN
    IF NEW.revision <> 1 THEN RAISE EXCEPTION 'invalid initial control head'; END IF;
  ELSE
    IF NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.revision <> OLD.revision+1
       OR event.previous_digest <> OLD.digest THEN RAISE EXCEPTION 'invalid control head transition'; END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER protect_control_head BEFORE INSERT OR UPDATE OR DELETE ON xeip_org.control_head
FOR EACH ROW EXECUTE FUNCTION xeip_org.protect_control_head();
CREATE TRIGGER protect_control_head_truncate BEFORE TRUNCATE ON xeip_org.control_head
FOR EACH STATEMENT EXECUTE FUNCTION xeip_org.protect_control_event();

CREATE FUNCTION xeip_org.publish_control_head() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.revision=1 THEN
    INSERT INTO xeip_org.control_head(singleton,revision,digest) VALUES(true,NEW.revision,NEW.digest);
  ELSE
    UPDATE xeip_org.control_head SET revision=NEW.revision,digest=NEW.digest WHERE singleton;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing control head'; END IF;
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER publish_control_head AFTER INSERT ON xeip_org.control_events
FOR EACH ROW EXECUTE FUNCTION xeip_org.publish_control_head();
