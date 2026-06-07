-- AEGIS Lite — PostgreSQL schema (production).
-- The SQLAlchemy models mirror this; this file documents the canonical DDL and
-- is used to initialize the Postgres container in docker-compose.

CREATE TABLE IF NOT EXISTS sites (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(120) NOT NULL,
    url         VARCHAR(500) NOT NULL,
    cf_zone_id  VARCHAR(120) DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    site_id     INTEGER REFERENCES sites(id),
    ts          TIMESTAMPTZ DEFAULT now(),
    ip          VARCHAR(64),
    method      VARCHAR(10),
    path        TEXT,
    status      INTEGER,
    user_agent  TEXT,
    geo         VARCHAR(120) DEFAULT '',
    source      VARCHAR(40) DEFAULT 'log'      -- log | webhook | crowdsec | honeypot
);
CREATE INDEX IF NOT EXISTS idx_events_ip  ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_site ON events(site_id);

CREATE TABLE IF NOT EXISTS incidents (
    id            SERIAL PRIMARY KEY,
    site_id       INTEGER REFERENCES sites(id),
    source_ip     VARCHAR(64),
    threat_types  JSONB,
    severity      VARCHAR(10),                  -- low | medium | high
    status        VARCHAR(20) DEFAULT 'open',   -- open | contained | resolved
    request_count INTEGER DEFAULT 0,
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    root_cause    TEXT DEFAULT '',
    timeline      JSONB,
    report        JSONB,
    created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_ip       ON incidents(source_ip);

CREATE TABLE IF NOT EXISTS actions (
    id           SERIAL PRIMARY KEY,
    incident_id  INTEGER REFERENCES incidents(id),
    type         VARCHAR(40),                   -- block_ip | rate_limit | quarantine | revoke_session
    provider     VARCHAR(40),                   -- cloudflare | crowdsec | internal
    mode         VARCHAR(20),                   -- dry-run | approval | auto
    status       VARCHAR(30),                   -- planned | pending_approval | applied | failed | expired
    params       JSONB,
    rule_ref     VARCHAR(200) DEFAULT '',
    verified     BOOLEAN DEFAULT FALSE,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON actions(incident_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id       SERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ DEFAULT now(),
    actor    VARCHAR(40) DEFAULT 'system',      -- system | founder
    action   VARCHAR(80),
    details  JSONB
);

CREATE TABLE IF NOT EXISTS monitoring_checks (
    id              SERIAL PRIMARY KEY,
    site_id         INTEGER REFERENCES sites(id),
    ts              TIMESTAMPTZ DEFAULT now(),
    up              BOOLEAN,
    status_code     INTEGER,
    response_ms     INTEGER,
    ssl_days_left   INTEGER,
    missing_headers JSONB
);

CREATE TABLE IF NOT EXISTS allowlist (
    id     SERIAL PRIMARY KEY,
    value  VARCHAR(64) UNIQUE,                  -- IP or CIDR; never blocked
    note   VARCHAR(200) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS honeypots (
    id    SERIAL PRIMARY KEY,
    path  VARCHAR(300) UNIQUE,                  -- decoy path; any hit = malicious
    note  VARCHAR(200) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS quarantined_files (
    id               SERIAL PRIMARY KEY,
    original_name    VARCHAR(500),
    quarantine_path  VARCHAR(500),
    content_type     VARCHAR(100) DEFAULT '',
    size_bytes       INTEGER DEFAULT 0,
    reason           TEXT DEFAULT '',
    status           VARCHAR(20) DEFAULT 'quarantined', -- quarantined | released | deleted
    uploaded_by_ip   VARCHAR(64) DEFAULT '',
    created_at       TIMESTAMPTZ DEFAULT now()
);
