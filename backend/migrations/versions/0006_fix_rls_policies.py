"""Phase 6 — fix rls policies to prevent uuid cast crashes.

Revision ID: 0006_fix_rls_policies
Revises: 0005_phase5
"""
from alembic import op

revision = "0006_fix_rls_policies"
down_revision = "0005_phase5"
branch_labels = None
depends_on = None

TABLES = [
    "sites", "events", "incidents", "actions", "audit_log",
    "monitoring_checks", "allowlist", "honeypots", "quarantined_files",
    "vulnerabilities", "posture_trends", "idp_connections", "scim_tokens",
    "siem_connections", "agent_cas", "agents", "agent_enrollment_tokens",
    "cases", "case_incidents", "case_notes", "case_events", "sla_policies",
    "escalation_rules", "playbooks", "playbook_runs", "indicators",
    "threat_actors", "taxii_feeds", "sightings", "detection_rules",
    "rule_versions", "rule_tests", "suppression_rules", "rule_feedback",
    "rule_confidence", "retention_policies", "ingest_batches",
]


def upgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid)
                WITH CHECK (org_id = NULLIF(current_setting('app.current_org', true), '')::uuid);
        """)


def downgrade() -> None:
    for t in TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {t};")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {t}
                USING      (org_id = current_setting('app.current_org', true)::uuid)
                WITH CHECK (org_id = current_setting('app.current_org', true)::uuid);
        """)
