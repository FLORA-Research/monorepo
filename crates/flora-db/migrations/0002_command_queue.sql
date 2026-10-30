-- Command queue support.
--
-- Manual commands are queued rather than pushed, because the cloud cannot reach
-- the device: the aggregator polls for them on the schedule it already runs.
-- A queued command therefore needs an expiry, so an irrigation request that
-- arrives long after it was signed is refused rather than acted on against a
-- plot that may already be wet.

ALTER TABLE device_commands
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Existing rows predate the queue; give them a window from their own timestamp
-- rather than leaving them permanently actionable.
UPDATE device_commands
   SET expires_at = ts + INTERVAL '15 minutes'
 WHERE expires_at IS NULL;

-- Result values are constrained so the audit trail stays queryable.
UPDATE device_commands SET result = 'pending' WHERE result IS NULL;

ALTER TABLE device_commands
    ALTER COLUMN result SET NOT NULL;

ALTER TABLE device_commands
    DROP CONSTRAINT IF EXISTS device_commands_result_valid;

ALTER TABLE device_commands
    ADD CONSTRAINT device_commands_result_valid
        CHECK (result IN ('pending', 'dispatched', 'applied', 'refused', 'expired'));

-- The poll query filters on exactly this: one gateway's undelivered commands in
-- arrival order.
CREATE INDEX IF NOT EXISTS device_commands_pending_idx
    ON device_commands (gateway_id, result, ts)
    WHERE result = 'pending';
