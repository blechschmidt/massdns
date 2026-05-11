import pg from 'pg'

const { Pool } = pg

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('sslmode=require')
    ? undefined
    : process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 10,
})

const MIGRATIONS = `
CREATE TABLE IF NOT EXISTS stations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  callsign      TEXT NOT NULL,
  frequency     TEXT NOT NULL,
  pi            TEXT NOT NULL,
  ecc           TEXT NOT NULL,
  freq5         TEXT NOT NULL,
  fqdn          TEXT NOT NULL UNIQUE,
  svc_fqdn      TEXT NOT NULL,
  stream_url    TEXT,
  website_url   TEXT,
  logo_url      TEXT,
  country       TEXT,
  service_type  TEXT NOT NULL DEFAULT 'FM',
  contact_email TEXT,
  notes         TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS service_records (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  station_id  UUID NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
  srv_type    TEXT NOT NULL,
  target      TEXT NOT NULL,
  port        INTEGER NOT NULL,
  priority    INTEGER NOT NULL DEFAULT 10,
  weight      INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS provisioning_status (
  station_id        UUID PRIMARY KEY REFERENCES stations(id) ON DELETE CASCADE,
  dns_provisioned   BOOLEAN NOT NULL DEFAULT FALSE,
  si_published      BOOLEAN NOT NULL DEFAULT FALSE,
  dns_valid         BOOLEAN,
  srv_valid         BOOLEAN,
  si_reachable      BOOLEAN,
  stream_reachable  BOOLEAN,
  last_validated    TIMESTAMPTZ,
  provision_log     JSONB NOT NULL DEFAULT '[]',
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`

export async function runMigrations() {
  const client = await pool.connect()
  try {
    await client.query(MIGRATIONS)
    console.log('[db] migrations applied')
  } finally {
    client.release()
  }
}

export async function query(sql, params) {
  const client = await pool.connect()
  try {
    return await client.query(sql, params)
  } finally {
    client.release()
  }
}
