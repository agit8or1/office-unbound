"""infrastructure resource model (ADR-0009 §3): infra_* tables, metric_samples, endpoint credential roles + scope allowlists"""
from alembic import context, op

revision = "0006a"
down_revision = "0005"

DDL = """
ALTER TABLE endpoints
  ADD COLUMN provision_token_id text,
  ADD COLUMN provision_secret_enc bytea,
  ADD COLUMN allowed_pools text[] NOT NULL DEFAULT '{}',
  ADD COLUMN allowed_storage text[] NOT NULL DEFAULT '{}',
  ADD COLUMN allowed_networks text[] NOT NULL DEFAULT '{}',
  ADD COLUMN allow_cicustom boolean NOT NULL DEFAULT false,
  ADD COLUMN allowed_templates integer[] NOT NULL DEFAULT '{}',
  ADD COLUMN display_name text,
  ADD COLUMN enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN detached_at timestamptz,
  ADD COLUMN last_probe jsonb,
  ADD COLUMN last_probe_at timestamptz,
  ADD CONSTRAINT endpoints_provision_pair CHECK ((provision_token_id IS NULL) = (provision_secret_enc IS NULL)),
  ADD CONSTRAINT endpoints_provision_scope CHECK (provision_token_id IS NULL OR cardinality(allowed_pools) > 0);

CREATE TABLE infra_clusters (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name text NOT NULL, quorate boolean, nodes_total integer, nodes_online integer, version text,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, name)
);
CREATE TABLE infra_nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name text NOT NULL, status text NOT NULL, cpu_total integer, mem_total bigint, mem_used bigint, cpu_pct double precision,
  disk_total bigint, disk_used bigint, uptime bigint, ip text,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, name)
);
CREATE TABLE infra_storage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name text NOT NULL, node text NOT NULL DEFAULT '', type text, content text[] NOT NULL DEFAULT '{}',
  shared boolean, enabled boolean, active boolean, total bigint, used bigint,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, name, node)
);
CREATE TABLE infra_networks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  name text NOT NULL, node text NOT NULL DEFAULT '', kind text NOT NULL CHECK (kind IN ('bridge','sdn_zone','sdn_vnet')),
  vlan_aware boolean, ports text, cidr text, zone text, tag integer,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, kind, name, node)
);
CREATE TABLE infra_guests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  vmid integer NOT NULL, kind text NOT NULL CHECK (kind IN ('vm','lxc')), node text NOT NULL, name text, status text NOT NULL,
  tags text[] NOT NULL DEFAULT '{}', pool text, ou_managed boolean NOT NULL DEFAULT false, ou_deployment_id text,
  cpus integer, mem_max bigint, disk_max bigint, uptime bigint, cpu_pct double precision, mem_used bigint,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, vmid)
);
CREATE INDEX infra_guests_dep ON infra_guests (ou_deployment_id) WHERE ou_deployment_id IS NOT NULL;
CREATE TABLE infra_templates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  vmid integer NOT NULL, kind text NOT NULL CHECK (kind IN ('vm','lxc')), node text NOT NULL, name text, pool text,
  tags text[] NOT NULL DEFAULT '{}', disk_max bigint,
  observed_at timestamptz NOT NULL, source text NOT NULL DEFAULT 'proxmox',
  UNIQUE (endpoint_id, vmid)
);
CREATE TABLE infra_collect_state (
  endpoint_id uuid PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
  last_discovery_at timestamptz, last_discovery_ok boolean, last_error text, warnings jsonb NOT NULL DEFAULT '[]',
  counts jsonb NOT NULL DEFAULT '{}', last_metrics_at timestamptz, last_metrics_error text
);
CREATE TABLE metric_samples (
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  scope_type text NOT NULL CHECK (scope_type IN ('node','guest','storage')),
  scope_id text NOT NULL,
  metric text NOT NULL,
  resolution text NOT NULL CHECK (resolution IN ('1m','5m','1h')),
  ts timestamptz NOT NULL,
  value double precision NOT NULL,
  vmax double precision NOT NULL,
  PRIMARY KEY (endpoint_id, scope_type, scope_id, metric, resolution, ts)
);
CREATE INDEX metric_samples_ts ON metric_samples (resolution, ts);
GRANT SELECT, INSERT, UPDATE, DELETE ON infra_clusters, infra_nodes, infra_storage, infra_networks, infra_guests, infra_templates,
      infra_collect_state, metric_samples TO {APP}
"""


def upgrade() -> None:
    app = context.config.attributes.get("app_role", "ics_app")
    for stmt in [s for s in DDL.replace("{APP}", app).split(";\n") if s.strip()]:
        op.execute(stmt)


def downgrade() -> None:
    raise RuntimeError("irreversible by design")
