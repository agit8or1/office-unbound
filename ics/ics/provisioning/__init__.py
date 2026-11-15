"""Provider-agnostic provisioning framework: policy model, plan/diff, package-generator interface, permission drift.

Providers (today: Proxmox, ics/providers/proxmox/provisioning.py) compute a ProvisioningPlan from a Policy and the provider's
discovered state; the SAME plan feeds Mode A (applied by the ICS with temporary credentials) and Mode B (rendered into a package
the customer's administrator runs). Both modes end in the same restricted integration.
"""
