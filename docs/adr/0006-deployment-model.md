# ADR-0006 Deployment and isolation model
Status: Accepted (2026-11-15)
One isolated stack per customer (unique deployment_id/customer_id, own VMs, own secrets, own backup boundary). Proxmox VMs provisioned from pinned cloud images via cloud-init; components installed with pinned package/container versions from versioned blueprints in `blueprints/`. ICS executes blueprints through typed actions; no Kubernetes. Lightweight single-customer layout first (est. 4 VMs: identity, groupware, files, office).
