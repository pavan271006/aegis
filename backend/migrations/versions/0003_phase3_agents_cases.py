"""Phase 3 — Agent platform (PKI/mTLS/fleet/OTA) + Incident case management.

Tenant-scoped tables get the standard RLS policy. `agent_releases` is a global
vendor release channel (no org scope).

Revision ID: 0003_phase3
Revises: 0002_phase2
"""
from alembic import op

revision = "0003_phase3"
down_revision = "0002_phase2"
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "agent_cas", "agents", "agent_enrollment_tokens",
    "cases", "case_incidents", "case_notes", "case_events",
    "sla_policies", "escalation_rules", "playbooks", "playbook_runs",
]


def upgrade() -> None:
    # ── Agent PKI / fleet ────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE agent_cas (
            org_id      uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            ca_cert_pem text NOT NULL,
            ca_key_enc  bytea NOT NULL,
            created_at  timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE agents (
            id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name          text NOT NULL,
            hostname      text DEFAULT '',
            status        text NOT NULL DEFAULT 'enrolled'
                          CHECK (status IN ('enrolled','active','quarantined','revoked')),
            cert_serial   text UNIQUE,
            cert_fpr      text,
            version       text DEFAULT '',
            channel       text NOT NULL DEFAULT 'stable',
            labels        jsonb NOT NULL DEFAULT '{}'::jsonb,
            health        jsonb NOT NULL DEFAULT '{}'::jsonb,
            enrolled_at   timestamptz,
            last_seen_at  timestamptz,
            created_at    timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_agents_org ON agents(org_id);

        CREATE TABLE agent_enrollment_tokens (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            token_hash text NOT NULL UNIQUE,
            label      text DEFAULT '',
            max_uses   integer NOT NULL DEFAULT 1,
            uses       integer NOT NULL DEFAULT 0,
            expires_at timestamptz NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now()
        );

        -- vendor-global OTA channel (signed manifests)
        CREATE TABLE agent_releases (
            version     text PRIMARY KEY,
            channel     text NOT NULL DEFAULT 'stable',
            url         text NOT NULL,
            sha256      text NOT NULL,
            signature   text NOT NULL,           -- RS256 over sha256, AEGIS signing key
            notes       text DEFAULT '',
            created_at  timestamptz NOT NULL DEFAULT now()
        );
    """)

    # ── Incident case management ─────────────────────────────────────────
    op.execute("""
        CREATE TABLE cases (
            id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            title           text NOT NULL,
            status          text NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','investigating','contained','resolved','closed')),
            severity        text NOT NULL DEFAULT 'medium',
            priority        text NOT NULL DEFAULT 'p3',
            assignee_id     integer REFERENCES users(id) ON DELETE SET NULL,
            created_by      integer REFERENCES users(id) ON DELETE SET NULL,
            tags            jsonb NOT NULL DEFAULT '[]'::jsonb,
            opened_at       timestamptz NOT NULL DEFAULT now(),
            first_response_at timestamptz,
            resolved_at     timestamptz,
            closed_at       timestamptz,
            sla_response_due timestamptz,
            sla_resolve_due  timestamptz,
            sla_breached    boolean NOT NULL DEFAULT false
        );
        CREATE INDEX ix_cases_org ON cases(org_id);
        CREATE INDEX ix_cases_status ON cases(org_id, status);

        CREATE TABLE case_incidents (
            case_id     uuid REFERENCES cases(id) ON DELETE CASCADE,
            incident_id integer REFERENCES incidents(id) ON DELETE CASCADE,
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            PRIMARY KEY (case_id, incident_id)
        );

        CREATE TABLE case_notes (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            case_id    uuid NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            author_id  integer REFERENCES users(id) ON DELETE SET NULL,
            body       text NOT NULL,
            internal   boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE case_events (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            case_id    uuid NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            type       text NOT NULL,           -- created|status|assign|escalate|note|playbook
            actor      text DEFAULT 'system',
            data       jsonb NOT NULL DEFAULT '{}'::jsonb,
            created_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX ix_case_events_case ON case_events(case_id, created_at);

        CREATE TABLE sla_policies (
            id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            severity            text NOT NULL,
            first_response_mins integer NOT NULL,
            resolution_mins     integer NOT NULL,
            UNIQUE (org_id, severity)
        );

        CREATE TABLE escalation_rules (
            id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name        text NOT NULL,
            condition   jsonb NOT NULL DEFAULT '{}'::jsonb,  -- e.g. {sla:'response_breached'}
            after_mins  integer NOT NULL DEFAULT 0,
            action      jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {notify:[...], reassign:user}
            enabled     boolean NOT NULL DEFAULT true
        );

        CREATE TABLE playbooks (
            id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            name       text NOT NULL,
            trigger    jsonb NOT NULL DEFAULT '{}'::jsonb,
            steps      jsonb NOT NULL DEFAULT '[]'::jsonb,   -- ordered declarative actions
            enabled    boolean NOT NULL DEFAULT true,
            created_at timestamptz NOT NULL DEFAULT now()
        );

        CREATE TABLE playbook_runs (
            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            playbook_id  uuid NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
            case_id      uuid REFERENCES cases(id) ON DELETE CASCADE,
            status       text NOT NULL DEFAULT 'running',
            current_step integer NOT NULL DEFAULT 0,
            log          jsonb NOT NULL DEFAULT '[]'::jsonb,
            started_at   timestamptz NOT NULL DEFAULT now(),
            finished_at  timestamptz
        );
    """)

    # ── RLS on tenant tables ─────────────────────────────────────────────
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app;")
    op.execute("GRANT SELECT ON agent_releases TO aegis_app;")
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
    op.execute("""
        DROP TABLE IF EXISTS playbook_runs, playbooks, escalation_rules, sla_policies,
            case_events, case_notes, case_incidents, cases,
            agent_releases, agent_enrollment_tokens, agents, agent_cas CASCADE;
    """)
