-- FLORA cloud schema.
--
-- Two conventions worth stating, because violating either silently corrupts
-- research data rather than raising an error:
--
-- 1. Units are SI. The wire sends moisture and humidity as per mille and
--    temperature as deci-degrees; ingest converts. Storing wire values in
--    columns named `moisture` and `temperature` would make every MAE
--    calculation wrong by a factor of ten.
-- 2. Sensor metrics are nullable. The firmware reports 0xFFFF and i16::MIN for
--    "unavailable" (no calibration, a failed read, a sensor this build does not
--    carry). Those map
--    to NULL, never to a number, so analytics cannot average a sentinel.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Accounts are an Ed25519 public key. No PII is collected anywhere in this
-- schema: no email, no name, no phone.
CREATE TABLE accounts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_pubkey  BYTEA NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT accounts_owner_pubkey_len CHECK (octet_length(owner_pubkey) = 32)
);

-- Phones or app installs belonging to an account. The owner's own device is
-- just the first row here; extra rows arrive through invites.
CREATE TABLE app_devices (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    pubkey     BYTEA NOT NULL UNIQUE,
    label      TEXT,
    revoked_at TIMESTAMPTZ,
    last_seen  TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT app_devices_pubkey_len CHECK (octet_length(pubkey) = 32)
);
CREATE INDEX app_devices_account_idx ON app_devices (account_id);

-- Aggregators. `id` is the provisioner's device id: SHA-256(pubkey)[..16] hex.
CREATE TABLE gateways (
    id         TEXT PRIMARY KEY,
    account_id UUID REFERENCES accounts(id) ON DELETE SET NULL,
    pubkey     BYTEA NOT NULL,
    label      TEXT,
    status     TEXT NOT NULL DEFAULT 'unclaimed',
    fw_version TEXT,
    fw_sha256  BYTEA,
    last_seen  TIMESTAMPTZ,
    rssi       INT,
    claimed_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT gateways_status_valid CHECK (status IN ('unclaimed', 'claimed', 'retired')),
    CONSTRAINT gateways_pubkey_len CHECK (octet_length(pubkey) = 32)
);
CREATE INDEX gateways_account_idx ON gateways (account_id);

-- Field nodes, discovered by their aggregator over RS-485. Node addressing is
-- local to each aggregator, so a node is identified by (gateway_id, node_uuid)
-- and two aggregators may each have a node at address 2 without conflict.
CREATE TABLE nodes (
    id         BIGSERIAL PRIMARY KEY,
    gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    node_uuid  BYTEA NOT NULL,
    addr       SMALLINT NOT NULL,
    label      TEXT,
    fw_version TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ,
    UNIQUE (gateway_id, node_uuid),
    CONSTRAINT nodes_uuid_len CHECK (octet_length(node_uuid) = 8),
    CONSTRAINT nodes_addr_range CHECK (addr BETWEEN 1 AND 254)
);

-- Telemetry. Nullable metrics carry the "unavailable" sentinel from the wire.
CREATE TABLE readings (
    ts          TIMESTAMPTZ NOT NULL,
    gateway_id  TEXT NOT NULL,
    node_uuid   BYTEA NOT NULL,
    moisture    REAL,
    temperature REAL,
    humidity    REAL,
    valve_state SMALLINT,
    seq         BIGINT,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ts, gateway_id, node_uuid),
    CONSTRAINT readings_uuid_len CHECK (octet_length(node_uuid) = 8),
    CONSTRAINT readings_valve_valid CHECK (valve_state IS NULL OR valve_state IN (0, 1))
);
-- Time-ordered scans per node, the shape every history query uses.
CREATE INDEX readings_gateway_node_ts_idx ON readings (gateway_id, node_uuid, ts DESC);

-- One live claim token per gateway. Only the hash is stored, so a database leak
-- does not yield a usable pairing credential.
CREATE TABLE claim_tokens (
    device_id  TEXT PRIMARY KEY REFERENCES gateways(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX claim_tokens_expiry_idx ON claim_tokens (expires_at);

-- Device MQTT credentials. Hashed, like the claim token.
CREATE TABLE device_tokens (
    device_id  TEXT PRIMARY KEY REFERENCES gateways(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ
);

-- Short-lived refresh tokens issued alongside access JWTs.
CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id  UUID NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at);

-- Replay protection for /pair/claim and /auth/verify. Rows are pruned on write.
CREATE TABLE auth_nonces (
    nonce      BYTEA PRIMARY KEY,
    scope      TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT auth_nonces_scope_valid CHECK (scope IN ('pair', 'auth', 'invite'))
);
CREATE INDEX auth_nonces_expiry_idx ON auth_nonces (expires_at);

-- Invite tokens let a second phone join an existing account with no email.
CREATE TABLE invite_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,
    inviter_device_id UUID NOT NULL REFERENCES app_devices(id) ON DELETE CASCADE,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX invite_tokens_expiry_idx ON invite_tokens (expires_at);

-- Audit trail for every manual override, including the signature that
-- authorised it. The aggregator verifies independently, so this is the record
-- of what was requested rather than what was trusted.
CREATE TABLE device_commands (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
    account_id    UUID REFERENCES accounts(id) ON DELETE SET NULL,
    gateway_id    TEXT NOT NULL,
    node_addr     SMALLINT NOT NULL,
    kind          TEXT NOT NULL,
    payload       JSONB,
    app_pubkey    BYTEA,
    app_signature BYTEA,
    nonce         BIGINT,
    signed_at     TIMESTAMPTZ,
    dispatched_at TIMESTAMPTZ,
    acked_at      TIMESTAMPTZ,
    -- Set by 0002: the window after which a queued command is refused.
    expires_at    TIMESTAMPTZ,
    result        TEXT
);
CREATE INDEX device_commands_gateway_idx ON device_commands (gateway_id, ts DESC);

-- Independent reference measurements from the Chapter 3 validation procedure,
-- paired with node readings to compute MAE.
CREATE TABLE reference_measurements (
    ts             TIMESTAMPTZ NOT NULL,
    gateway_id     TEXT NOT NULL,
    node_uuid      BYTEA NOT NULL,
    moisture_ref   REAL,
    temperature_ref REAL,
    humidity_ref   REAL,
    method         TEXT,
    PRIMARY KEY (ts, gateway_id, node_uuid),
    CONSTRAINT reference_uuid_len CHECK (octet_length(node_uuid) = 8)
);
