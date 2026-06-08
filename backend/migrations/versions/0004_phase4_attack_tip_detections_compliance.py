"""Phase 4 — ATT&CK, Threat Intel Platform, detection content + FP management,
compliance (tamper-evident audit, GDPR retention).

Revision ID: 0004_phase4
Revises: 0003_phase3
"""
from alembic import op

revision = "0004_phase4"
down_revision = "0003_phase3"
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "indicators", "threat_actors", "taxii_feeds", "sightings",
    "detection_rules", "rule_versions", "rule_tests",
    "suppression_rules", "rule_feedback", "rule_confidence",
    "retention_policies",
]


def upgrade() -> None:
    # ── ATT&CK reference data (global, not tenant-scoped) ────────────────
    op.execute("""
        CREATE TABLE attack_techniques (
            technique_id   text PRIMARY KEY,            -- T1110, T1110.004
            name           text NOT NULL,
            tactic         text NOT NULL,               -- e.g. credential-access
            url            text,
            is_subtechnique boolean NOT NULL DEFAULT false,
            parent_id      text
        );
        -- maps an AEGIS detection key -> ATT&CK technique (global defaults)
        CREATE TABLE detection_attack_map (
            detection_key text NOT NULL,                -- credential_stuffing, sqli, ...
            technique_id  text NOT NULL REFERENCES attack_techniques(technique_id),
            confidence    real NOT NULL DEFAULT 1.0,
            PRIMARY KEY (detection_key, technique_id)
        );
    """)

    # ── Threat Intelligence Platform ─────────────────────────────────────
    op.execute("""
        CREATE TABLE taxii_feeds (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name        text NOT NULL,
            api_root    text NOT NULL,
            collection  text NOT NULL,
            auth_enc    bytea,
            enabled     boolean NOT NULL DEFAULT true,
            last_poll_at timestamptz,
            created_at  timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE threat_actors (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            stix_id     text,
            name        text NOT NULL,
            aliases     text[] NOT NULL DEFAULT '{}',
            description text DEFAULT '',
            source      text DEFAULT '',
            created_at  timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE indicators (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            type        text NOT NULL,                  -- ipv4|domain|url|sha256
            value       text NOT NULL,
            confidence  integer NOT NULL DEFAULT 50,
            source      text DEFAULT '',
            actor_id    uuid REFERENCES threat_actors(id) ON DELETE SET NULL,
            labels      text[] NOT NULL DEFAULT '{}',
            valid_until timestamptz,
            created_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (org_id, type, value)
        );
        CREATE INDEX ix_indicators_lookup ON indicators(org_id, type, value);
        CREATE TABLE sightings (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            indicator_id uuid REFERENCES indicators(id) ON DELETE CASCADE,
            incident_id  integer REFERENCES incidents(id) ON DELETE CASCADE,
            observed     text NOT NULL,
            context      jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at   timestamptz NOT NULL DEFAULT now()
        );
    """)

    # ── Detection content management + false-positive management ─────────
    op.execute("""
        CREATE TABLE detection_rules (
            id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            key             text NOT NULL,
            name            text NOT NULL,
            type            text NOT NULL DEFAULT 'signature',
            enabled         boolean NOT NULL DEFAULT true,
            current_version integer NOT NULL DEFAULT 1,
            UNIQUE (org_id, key)
        );
        CREATE TABLE rule_versions (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            rule_id     uuid NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
            version     integer NOT NULL,
            definition  jsonb NOT NULL,
            author      text DEFAULT '',
            note        text DEFAULT '',
            created_at  timestamptz NOT NULL DEFAULT now(),
            UNIQUE (rule_id, version)
        );
        CREATE TABLE rule_tests (
            id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            rule_id   uuid NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
            name      text NOT NULL,
            sample    jsonb NOT NULL,
            expect_match boolean NOT NULL,
            last_result text
        );
        CREATE TABLE suppression_rules (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            match      jsonb NOT NULL,                  -- {source_ip,path,threat_type}
            reason     text DEFAULT '',
            created_by integer REFERENCES users(id) ON DELETE SET NULL,
            expires_at timestamptz,
            enabled    boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE rule_feedback (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            incident_id integer REFERENCES incidents(id) ON DELETE SET NULL,
            rule_key    text NOT NULL,
            verdict     text NOT NULL CHECK (verdict IN ('tp','fp')),
            user_id     integer REFERENCES users(id) ON DELETE SET NULL,
            created_at  timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE rule_confidence (
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            rule_key   text NOT NULL,
            tp         integer NOT NULL DEFAULT 0,
            fp         integer NOT NULL DEFAULT 0,
            confidence real NOT NULL DEFAULT 0.5,
            PRIMARY KEY (org_id, rule_key)
        );
        CREATE TABLE retention_policies (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            table_name text NOT NULL,
            ttl_days   integer NOT NULL,
            UNIQUE (org_id, table_name)
        );
    """)

    # ── Tamper-evident audit (hash chain on the existing audit_log) ──────
    op.execute("""
        ALTER TABLE audit_log
            ADD COLUMN IF NOT EXISTS prev_hash  text,
            ADD COLUMN IF NOT EXISTS entry_hash text;
    """)

    # ── RLS ──────────────────────────────────────────────────────────────
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;")
    op.execute("GRANT SELECT ON attack_techniques, detection_attack_map TO aegis_app;")
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = current_setting('app.current_org', true)::uuid)
                WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
        """)


def downgrade() -> None:
    for t in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
    op.execute("ALTER TABLE audit_log DROP COLUMN IF EXISTS prev_hash, DROP COLUMN IF EXISTS entry_hash;")
    op.execute("""
        DROP TABLE IF EXISTS retention_policies, rule_confidence, rule_feedback,
            suppression_rules, rule_tests, rule_versions, detection_rules,
            sightings, indicators, threat_actors, taxii_feeds,
            detection_attack_map, attack_techniques CASCADE;
    """)
