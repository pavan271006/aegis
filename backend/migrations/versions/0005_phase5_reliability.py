"""Phase 5 — reliability: idempotent ingest (at-least-once dedup) + OTA canary.

Revision ID: 0005_phase5
Revises: 0004_phase4
"""
from alembic import op

revision = "0005_phase5"
down_revision = "0004_phase4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Server-side dedup so an agent that retries a batch after a network blip does
    # NOT create duplicate events/incidents (exactly-once effect over at-least-once).
    op.execute("""
        CREATE TABLE ingest_batches (
            org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            batch_id   text NOT NULL,
            agent_id   uuid REFERENCES agents(id) ON DELETE SET NULL,
            received_at timestamptz NOT NULL DEFAULT now(),
            event_count integer NOT NULL DEFAULT 0,
            PRIMARY KEY (org_id, batch_id)
        );
        ALTER TABLE ingest_batches ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ingest_batches FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON ingest_batches
            USING      (org_id = current_setting('app.current_org', true)::uuid)
            WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
        GRANT SELECT, INSERT, UPDATE, DELETE ON ingest_batches TO aegis_app;
    """)
    # OTA canary control on the fleet.
    op.execute("""
        ALTER TABLE agents
            ADD COLUMN IF NOT EXISTS canary boolean NOT NULL DEFAULT false,
            ADD COLUMN IF NOT EXISTS target_version text;
        ALTER TABLE agent_releases
            ADD COLUMN IF NOT EXISTS canary_percent integer NOT NULL DEFAULT 0;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ingest_batches CASCADE;")
    op.execute("ALTER TABLE agents DROP COLUMN IF EXISTS canary, DROP COLUMN IF EXISTS target_version;")
    op.execute("ALTER TABLE agent_releases DROP COLUMN IF EXISTS canary_percent;")
