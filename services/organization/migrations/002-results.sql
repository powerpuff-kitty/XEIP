-- Historical results share the action's inspection policy. Null means no trustworthy result.
ALTER TABLE xeip_org.actions ADD COLUMN result_canonical text;
ALTER TABLE xeip_org.actions ADD CONSTRAINT bounded_terminal_result CHECK (
  result_canonical IS NULL OR (
    state IN ('succeeded','failed') AND octet_length(result_canonical) <= 131072
  )
);
-- Existing protect_action permits only one transition out of executing and prevents
-- all terminal-row updates; this also makes the recorded result immutable.
