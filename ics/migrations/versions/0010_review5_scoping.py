"""review 5 M5/M6: nodes, checks, alert channels, maintenance windows and backup policies belong to a customer (default: the MSP-internal customer),
so every list/get endpoint can scope by operator<->customer assignment; plus the one-time-secret sweeper index (L1)."""
from alembic import op

revision = "0010"
down_revision = "0009a"

DEF = "00000000-0000-0000-0000-00000000a001"
DDL = """
ALTER TABLE nodes ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id);
ALTER TABLE checks ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id);
ALTER TABLE alert_channels ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id);
ALTER TABLE maintenance_windows ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id);
ALTER TABLE backup_policies ADD COLUMN customer_id uuid NOT NULL DEFAULT '{DEF}' REFERENCES customers(id);
UPDATE checks c SET customer_id = e.customer_id FROM deployments d JOIN endpoints e ON e.id = d.endpoint_id WHERE c.deployment_id = d.id;
CREATE INDEX nodes_customer ON nodes (customer_id);
CREATE INDEX checks_customer ON checks (customer_id);
CREATE INDEX alert_channels_customer ON alert_channels (customer_id);
CREATE INDEX maintenance_customer ON maintenance_windows (customer_id);
CREATE INDEX backup_policies_customer ON backup_policies (customer_id);
CREATE INDEX guest_bootstrap_expiry ON guest_bootstrap (expires_at) WHERE secret_enc IS NOT NULL OR token_enc IS NOT NULL OR ssh_key_enc IS NOT NULL
"""


def upgrade() -> None:
    for stmt in [s for s in DDL.replace("{DEF}", DEF).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
