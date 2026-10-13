-- Bind retained/removed trust records to the signed provisioning. Migration 003
-- only checked that counters for entities already present advanced monotonically,
-- so a restricted runtime writer could drop an entity from provisioning while
-- recording forged, monotonic retained metadata (or invent an inactive identity).
-- This forward migration replaces the trigger function without rewriting 003.
-- SQL cannot validate signatures; structural binding to the accepted signed
-- documents plus the unchanged JavaScript identity worker cover all entities.
CREATE OR REPLACE FUNCTION xeip_org.protect_control_event() RETURNS trigger
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
  active_generation numeric;
  active_serial numeric;
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
    -- Every previously retained entity must survive, and its record must remain
    -- justified. Active entities advance monotonically; removed entities, which
    -- provisioning can no longer describe, may only preserve the exact record.
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
         THEN RAISE EXCEPTION 'control trust rollback'; END IF;
      SELECT max((kd->'document'->>'generation')::numeric) INTO active_generation
        FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS kd
        WHERE kd->'document'->>'entity' = entity;
      IF active_generation IS NULL THEN
        IF next_record IS DISTINCT FROM old_record
           THEN RAISE EXCEPTION 'control removed record change'; END IF;
      ELSE
        IF (next_record->>'generation')::bigint < (old_record->>'generation')::bigint
           OR (next_record->>'serial')::bigint < (old_record->>'serial')::bigint
           OR ((next_record->>'generation')::bigint = (old_record->>'generation')::bigint
               AND next_record->>'keyDigest' IS DISTINCT FROM old_record->>'keyDigest')
           OR ((next_record->>'serial')::bigint = (old_record->>'serial')::bigint
               AND next_record->>'statusDigest' IS DISTINCT FROM old_record->>'statusDigest')
           THEN RAISE EXCEPTION 'control trust rollback'; END IF;
      END IF;
    END LOOP;
    -- A record for an entity the signed provisioning no longer describes is only
    -- a retained high-water mark; it cannot be invented by a new runtime writer.
    FOR entity IN SELECT key FROM jsonb_each(candidate->'records') WHERE NOT (previous->'records' ? key) LOOP
      IF NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS kd
        WHERE kd->'document'->>'entity' = entity
      ) THEN RAISE EXCEPTION 'control record without provisioning'; END IF;
    END LOOP;
    -- Every active entity must carry a record bound to its accepted signed
    -- documents: the counter is the document's generation/serial, not the
    -- writer's claim. This rejects counter forgery even when it advances.
    FOR entity IN SELECT DISTINCT kd->'document'->>'entity' FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS kd LOOP
      next_record := candidate->'records'->entity;
      IF jsonb_typeof(next_record) IS DISTINCT FROM 'object'
         THEN RAISE EXCEPTION 'control active record required'; END IF;
      SELECT max((kd2->'document'->>'generation')::numeric) INTO active_generation
        FROM jsonb_array_elements(candidate->'provisioning'->'keyDocuments') AS kd2
        WHERE kd2->'document'->>'entity' = entity;
      SELECT (sd->'document'->>'serial')::numeric INTO active_serial
        FROM jsonb_array_elements(candidate->'provisioning'->'statusDocuments') AS sd
        WHERE sd->'document'->>'entity' = entity;
      IF jsonb_typeof(next_record->'generation') IS DISTINCT FROM 'number'
         OR (next_record->>'generation')::numeric <> active_generation
         OR active_serial IS NULL
         OR jsonb_typeof(next_record->'serial') IS DISTINCT FROM 'number'
         OR (next_record->>'serial')::numeric <> active_serial
         THEN RAISE EXCEPTION 'control active record mismatch'; END IF;
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
