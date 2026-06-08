"""Phase 1 — multi-tenancy, tenant-scoped RBAC, Postgres RLS, enterprise auth.

Expand/migrate/contract migration: it is additive and backfills a "Default
Organization" so the existing single-tenant data and users keep working while
the application is rolled over to tenant-aware code paths.

Revision ID: 0001_phase1
Revises:
"""
from alembic import op

revision = "0001_phase1"
down_revision = None
branch_labels = None
depends_on = None

# Every table that holds customer (tenant) data must be isolated by org.
TENANT_TABLES = [
    "sites", "events", "incidents", "actions", "audit_log",
    "monitoring_checks", "allowlist", "honeypots",
    "quarantined_files", "vulnerabilities", "posture_trends",
]


def upgrade() -> None:
    # gen_random_uuid() is built into Postgres core since 13; pgcrypto is only
    # needed on older servers. Try to enable it, but don't fail if unavailable.
    op.execute("DO $$ BEGIN CREATE EXTENSION IF NOT EXISTS pgcrypto; "
               "EXCEPTION WHEN OTHERS THEN NULL; END $$;")

    # ── Organizations (the tenant) ───────────────────────────────────────
    op.execute("""
        CREATE TABLE organizations (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            name        text NOT NULL,
            slug        text NOT NULL UNIQUE,
            plan        text NOT NULL DEFAULT 'free',
            status      text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','suspended','deleted')),
            settings    jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at  timestamptz NOT NULL DEFAULT now()
        );
    """)

    # ── Users become global identities; enterprise security columns ──────
    op.execute("""
        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS mfa_enabled         boolean NOT NULL DEFAULT false,
            ADD COLUMN IF NOT EXISTS password_changed_at timestamptz NOT NULL DEFAULT now(),
            ADD COLUMN IF NOT EXISTS failed_logins       integer NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS locked_until        timestamptz,
            ADD COLUMN IF NOT EXISTS is_superuser        boolean NOT NULL DEFAULT false;
    """)

    # ── Membership = tenant-scoped RBAC (a user can be in many orgs) ──────
    op.execute("""
        CREATE TABLE memberships (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id    integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            org_id     uuid    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            role       text    NOT NULL DEFAULT 'read_only'
                       CHECK (role IN ('owner','admin','analyst','read_only')),
            status     text    NOT NULL DEFAULT 'active',
            created_at timestamptz NOT NULL DEFAULT now(),
            UNIQUE (user_id, org_id)
        );
        CREATE INDEX ix_memberships_org  ON memberships(org_id);
        CREATE INDEX ix_memberships_user ON memberships(user_id);
    """)

    # ── Refresh sessions (rotation chain + revocation) ───────────────────
    op.execute("""
        CREATE TABLE refresh_sessions (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id      integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            org_id       uuid REFERENCES organizations(id) ON DELETE CASCADE,
            token_hash   text NOT NULL UNIQUE,          -- sha256 of opaque token
            parent_id    uuid REFERENCES refresh_sessions(id) ON DELETE SET NULL,
            user_agent   text DEFAULT '',
            ip           inet,
            created_at   timestamptz NOT NULL DEFAULT now(),
            last_used_at timestamptz,
            expires_at   timestamptz NOT NULL,
            revoked_at   timestamptz
        );
        CREATE INDEX ix_refresh_user ON refresh_sessions(user_id);
    """)

    # ── Asymmetric signing keys (RS256) for access tokens + JWKS ─────────
    op.execute("""
        CREATE TABLE signing_keys (
            kid             text PRIMARY KEY,
            alg             text NOT NULL DEFAULT 'RS256',
            public_pem      text NOT NULL,
            private_pem_enc bytea NOT NULL,             -- encrypted w/ KEK (envelope)
            status          text NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active','retiring','revoked')),
            created_at      timestamptz NOT NULL DEFAULT now(),
            not_after       timestamptz
        );
    """)

    # ── MFA (TOTP) + single-use backup codes ─────────────────────────────
    op.execute("""
        CREATE TABLE mfa_credentials (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id      integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type         text NOT NULL DEFAULT 'totp',
            secret_enc   bytea NOT NULL,                -- encrypted TOTP secret
            confirmed_at timestamptz,
            created_at   timestamptz NOT NULL DEFAULT now()
        );
        CREATE TABLE mfa_backup_codes (
            id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id   integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash text NOT NULL,
            used_at   timestamptz
        );
    """)

    # ── Password history (reuse prevention) ──────────────────────────────
    op.execute("""
        CREATE TABLE password_history (
            id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id         integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            hashed_password text NOT NULL,
            created_at      timestamptz NOT NULL DEFAULT now()
        );
    """)

    # ── Add nullable org_id to every tenant table (expand) ───────────────
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS org_id uuid;")

    # ── Backfill: one default org, memberships for existing users ────────
    op.execute("""
        WITH new_org AS (
            INSERT INTO organizations (name, slug, plan)
            VALUES ('Default Organization', 'default', 'enterprise')
            RETURNING id
        )
        INSERT INTO memberships (user_id, org_id, role)
        SELECT u.id, o.id, COALESCE(u.role, 'read_only')
        FROM users u CROSS JOIN new_org o;
    """)
    for t in TENANT_TABLES:
        op.execute(f"""
            UPDATE {t}
               SET org_id = (SELECT id FROM organizations WHERE slug = 'default')
             WHERE org_id IS NULL;
        """)

    # ── Contract: enforce NOT NULL + FK + index now that data is backfilled
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ALTER COLUMN org_id SET NOT NULL;")
        op.execute(
            f"ALTER TABLE {t} ADD CONSTRAINT fk_{t}_org "
            f"FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;"
        )
        op.execute(f"CREATE INDEX ix_{t}_org ON {t}(org_id);")

    # ── Least-privilege app role + Row-Level Security ────────────────────
    # The application connects as aegis_app (NOT the table owner / superuser),
    # so FORCE RLS is enforced. Every request sets app.current_org via SET LOCAL.
    # Tolerant: managed Postgres (Render/Neon) may deny CREATE ROLE / GRANT to the
    # provided owner. That's fine — when the app connects as the DB *owner* (a
    # non-superuser on managed PG), FORCE ROW LEVEL SECURITY still enforces tenant
    # isolation. On self-managed PG the dedicated aegis_app least-privilege role is used.
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
                CREATE ROLE aegis_app LOGIN;
            END IF;
            GRANT USAGE ON SCHEMA public TO aegis_app;
            GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;
            GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO aegis_app;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO aegis_app;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'aegis_app role/grants skipped (managed PG): %', SQLERRM;
        END$$;
    """)
    # RLS on tenant DATA tables only. `memberships`/`users` are identity metadata
    # read during login (before an org context exists) and are authorized in app
    # code (a token's org claim is only minted for a verified membership).
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;")
        # current_setting(..., true) -> NULL when unset, so an unscoped query
        # returns ZERO rows (fail-closed) instead of leaking cross-tenant data.
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = current_setting('app.current_org', true)::uuid)
                WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
        """)


def downgrade() -> None:
    for t in TENANT_TABLES + ["memberships"]:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
        op.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY;")
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT IF EXISTS fk_{t}_org;")
        op.execute(f"DROP INDEX IF EXISTS ix_{t}_org;")
        op.execute(f"ALTER TABLE {t} DROP COLUMN IF EXISTS org_id;")
    op.execute("""
        DROP TABLE IF EXISTS password_history, mfa_backup_codes, mfa_credentials,
            signing_keys, refresh_sessions, memberships CASCADE;
        ALTER TABLE users
            DROP COLUMN IF EXISTS mfa_enabled,
            DROP COLUMN IF EXISTS password_changed_at,
            DROP COLUMN IF EXISTS failed_logins,
            DROP COLUMN IF EXISTS locked_until,
            DROP COLUMN IF EXISTS is_superuser;
        DROP TABLE IF EXISTS organizations CASCADE;
    """)
