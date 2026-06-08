"""Phase 7 — Allow RLS query bypass under system sentinel org.

Revision ID: 0007_sentinel_rls_bypass
Revises: 0006_fix_rls_policies
"""
from alembic import op

revision = "0007_sentinel_rls_bypass"
down_revision = "0006_fix_rls_policies"
branch_labels = None
depends_on = None

TABLES = ["idp_connections", "scim_tokens", "agent_enrollment_tokens", "sites"]


def upgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid OR NULLIF(current_setting('app.current_org', true), '') = '00000000-0000-0000-0000-000000000000')
                WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid OR NULLIF(current_setting('app.current_org', true), '') = '00000000-0000-0000-0000-000000000000');
        """)


def downgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
                WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid);
        """)
