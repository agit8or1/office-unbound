# Deployment catalog (ADR-0009 section 4)

Versioned, validated by pydantic in `ics/ics/deploy/catalog.py` (`load_catalog()`; unknown keys are rejected, a bad file fails loudly with the file and field).
`OU_CATALOG_DIR` overrides the directory. The catalog digest (sha256 of all files) is embedded in every plan.

- `catalog.yaml` - `catalog_version`, `os_images[]` (id, approved Proxmox `template`, `sha256` pin or empty = plan warns), `default_os_image`, `vm_overhead`
  (added to every VM), `placement` (`cpu_overcommit`, `memory_reserve_pct`, `storage_reserve_pct` = safety margin on PHYSICAL free space, `thin_max_ratio_pct`).
- `components/<name>.yaml`
  - `artifacts[]` (min 1): `kind: oci` -> `image`, `digest` (REQUIRED: `sha256:<64 hex>`, or the bare placeholder `sha256:` = not built/pinned yet; plans refuse to
    execute while a placeholder remains), `version`; `kind: package` -> `package`, exact `version` (no latest/ranges), `repo` (`ob-apt-*`, `ubuntu-noble`, `debian-bookworm`).
  - `resources.{cores,memory_mb,disk_gb}` and `volumes[].size_gb`: `Formula{base, per_user, source}`; value = `ceil(base + per_user*users)` (exact decimal math).
    `source` is mandatory: cite the lab measurement or say "assumption" (plans list every assumption as a warning).
  - `ports[]` (`exposure`: `local` loopback only, `internal` VMs that depend on this component, `edge` reverse-proxy VMs, `public` anywhere, `ics` the control plane),
    `depends_on` (hard, must be in the layout), `after` (order only), `dns[]` (`target`: `vm`, `edge`, or literal), `health_checks[]` (`http|tcp_tls|smtp_banner`, port must be declared),
    `backup{method,quiesce,rpo_hours,evidence}`, `upgrade.downtime_seconds`, `placement: every_vm` (node agent).
  - `sizing` (sizing engine, docs/status/sizing-api.md): `services[]` (wizard service ids), `core`, `minimum`/`recommended` floors
    `{cores,memory_mb,disk_gb}`, `cores|memory_mb|disk_gb: {base, base_evidence: measured|estimate, source, factors[{per: total_user|
    concurrent_user|office_editor|meeting_participant|concurrent_call|mailbox_gb|file_gb, value, evidence, source}]}`, `volumes[]` (same model +
    `volume`, must cover exactly the component's volumes), `safety_margin_pct` (applied to estimate parts), `consolidation{group, isolation:
    none|preferred|required, never_with[], reason}`, `ha{min_replicas, strategies[{id, status: implemented|designed|not_supported, note}], note}`
    (application HA only with an implemented replication strategy; `vm_restart_shared_storage` is recovery, not HA), `limitations[]`,
    `validated{total_users, concurrent, concurrent_metric, reference}` (what a lab actually exercised).
- `profiles/<name>.yaml`: `max_users`, `min_nodes`, `ha`, `tenancy` (`single|multi`), `dedicated_nodes`, `custom`, `maturity` (`lab-validated|experimental`),
  `vms[]` (`name`, `components`, `replicas`, `anti_affinity`, `per_tenant`), `optional_components`/`default_optional`, `backup{schedule,retention_days,snapshot_before_change,offsite}`,
  `sizing_preset{deployment_type, architecture}`. Titles carry no VM counts; the API derives `vm_counts` from the layout.

Cross-file checks: unknown/duplicate components, dependency cycles, components on more than one VM entry, listing `every_vm` components, HA profiles must have `replicas>=2` + anti-affinity,
dependencies missing from a layout.
Plan-time checks (not catalog-time): VM port conflicts, capacity, thin-pool overcommit, unpinned artifacts.
