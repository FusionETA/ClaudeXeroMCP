-- Xero MCP Auth — NeonDB table setup
--
-- Optional: server.js also creates these tables automatically on startup
-- (CREATE TABLE IF NOT EXISTS), so running this file by hand isn't required.
-- It's here for pre-provisioning a fresh DB or as a reference for the schema.

-- Multi-org support: each row is one connected Xero org, keyed by tenant_id.
CREATE TABLE IF NOT EXISTS xero_tokens (
  id            SERIAL PRIMARY KEY,
  tenant_id     TEXT    UNIQUE NOT NULL,
  tenant_name   TEXT,
  access_token  TEXT    NOT NULL,
  refresh_token TEXT    NOT NULL,
  expires_at    BIGINT  NOT NULL,
  authorised_at TEXT,
  refreshed_at  TEXT,
  is_active     BOOLEAN DEFAULT true
);

-- Tracks which org (by tenant_id) is currently active. Single row (id = 1);
-- the server upserts into it on every login and org switch.
CREATE TABLE IF NOT EXISTS xero_active_org (
  id            INTEGER PRIMARY KEY DEFAULT 1,
  tenant_id     TEXT NOT NULL REFERENCES xero_tokens(tenant_id)
);
