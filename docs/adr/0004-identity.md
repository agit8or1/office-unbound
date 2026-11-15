# ADR-0004 Identity architecture
Status: Proposed — pending spike (2026-11-15)
Per customer stack: one LDAP directory as user/group source of truth (candidate lldap; OpenLDAP/389DS if OpenCloud/gromox schema needs require), federated into one Keycloak instance/realm for OIDC SSO + MFA. Gromox binds LDAP directly (ldap_adaptor cannot use Keycloak). OpenCloud uses Keycloak OIDC; user provisioning path (autoprovision vs. shared LDAP) decided by spike.
Provisioning is done by ICS/MSP API into LDAP, then reconciled downstream. Deprovisioning must revoke Keycloak sessions + offline tokens, gromox access, app passwords, ActiveSync devices; max delay to be measured (target ≤ 5 min).
