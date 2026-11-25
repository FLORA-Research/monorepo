-- A batch can contain multiple records for one node. The bridge may collect
-- the seq-0 boot banner and later sensor samples before it uploads; all rows
-- in that request get the same server-assigned timestamp. Keying only by
-- (ts, gateway_id, node_uuid) silently kept the first (often all-NULL) row and
-- discarded every subsequent sample in that batch.
--
-- Keep a surrogate primary key and make the telemetry identity sequence-aware.
-- The paired indexes preserve idempotency for retransmitted samples while
-- keeping the legacy/optional NULL sequence case idempotent too.
ALTER TABLE readings DROP CONSTRAINT readings_pkey;
ALTER TABLE readings ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY;

CREATE UNIQUE INDEX readings_idempotency_idx
    ON readings (ts, gateway_id, node_uuid, seq)
    WHERE seq IS NOT NULL;
CREATE UNIQUE INDEX readings_unknown_seq_idempotency_idx
    ON readings (ts, gateway_id, node_uuid)
    WHERE seq IS NULL;
