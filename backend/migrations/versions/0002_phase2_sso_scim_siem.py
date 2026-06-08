"""Phase 2 — SSO (OIDC/SAML) connections, SCIM tokens, SIEM connections.

All new tables are tenant-scoped (org_id) and protected by the same RLS pattern
established in migration 0001.

Revision ID: 0002_phase2
Revises: 0001_phase1
"""
from alembic import op

revision = "0002_phase2"
down_revision = "0001_phase1"
branch_labels = None
depends_on = None

NEW_TENANT_TABLES = ["idp_connections", "scim_tokens", "siem_connections"]


def upgrade() -> None:
    # ── Per-org Identity Provider connections (OIDC / SAML) ───────────────
    op.execute("""
        CREATE TABLE idp_connections (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            kind          text NOT NULL CHECK (kind IN ('oidc','saml')),
            name          text NOT NULL,
            enabled       boolean NOT NULL DEFAULT true,
            -- OIDC
            issuer        text,
            client_id     text,
            client_secret_enc bytea,
            -- SAML
            idp_metadata_xml text,
            sp_entity_id  text,
            acs_url       text,
            -- shared
            default_role  text NOT NULL DEFAULT 'read_only',
            attr_mapping  jsonb NOT NULL DEFAULT '{}'::jsonb,  -- claim/attr -> role
            email_domains text[] NOT NULL DEFAULT '{}',
            created_at    timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_idp_org ON idp_connections(org_id);
    """)

    # ── SCIM bearer tokens (one per org per IdP) ─────────────────────────
    op.execute("""
        CREATE TABLE scim_tokens (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            token_hash text NOT NULL UNIQUE,
            label      text NOT NULL DEFAULT '',
            created_at timestamptz NOT NULL DEFAULT now(),
            last_used_at timestamptz,
            revoked_at timestamptz
        );
        CREATE INDEX ix_scim_org ON scim_tokens(org_id);
    """)

    # ── SIEM forwarding connections ──────────────────────────────────────
    op.execute("""
        CREATE TABLE siem_connections (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            kind         text NOT NULL CHECK (kind IN
                         ('splunk_hec','sentinel','elastic','syslog','chronicle','webhook')),
            name         text NOT NULL,
            enabled      boolean NOT NULL DEFAULT true,
            endpoint     text NOT NULL,
            secret_enc   bytea,                       -- HEC token / shared key / etc.
            format       text NOT NULL DEFAULT 'json' CHECK (format IN ('json','cef')),
            options      jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at   timestamptz NOT NULL DEFAULT now(),
            last_ok_at   timestamptz,
            last_error   text
        );
        CREATE INDEX ix_siem_org ON siem_connections(org_id);
    """)

    # ── RLS (same fail-closed pattern as phase 1) ────────────────────────
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;")
    for t in NEW_TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = current_setting('app.current_org', true)::uuid)
                WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
        """)


def downgrade() -> None:
    for t in NEW_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
    op.execute("DROP TABLE IF EXISTS siem_connections, scim_tokens, idp_connections CASCADE;")
