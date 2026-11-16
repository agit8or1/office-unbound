"""Portal settings: everything comes from the environment (EnvironmentFile=/etc/ou-portal/portal.env). No secrets in code."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        raise RuntimeError(f"missing required setting {name}")
    return v


def _secret(name: str) -> str:
    """Secret from NAME (env) or NAME_FILE (path, preferred: keeps it out of the process environment)."""
    f = os.environ.get(name + "_FILE")
    if f:
        return Path(f).read_text().strip()
    return _env(name)


@dataclass(frozen=True)
class Settings:
    base_url: str                     # https://portal.<domain>
    issuer: str                       # Keycloak realm URL
    client_id: str
    client_secret: str
    files_url: str                    # OpenCloud root URL
    mail_web_url: str                 # grommunio-web URL (…/web/)
    mail_domain: str                  # e-mail domain of the users
    org_name: str
    imap_host: str
    imap_port: int
    smtp_host: str
    smtp_port: int
    dav_host: str
    dav_base: str                     # path prefix of CalDAV/CardDAV, e.g. /dav
    autodiscover_host: str
    editor_app: str = "external-collaboraonline"   # OpenCloud web route of the editor app
    doc_ext: dict = field(default_factory=lambda: {"document": "docx", "spreadsheet": "xlsx", "presentation": "pptx"})
    session_ttl: int = 8 * 3600       # absolute lifetime of a portal session
    http_timeout: float = 8.0
    ca_bundle: str | None = None      # None = system store (lab CA is installed there)
    ics_url: str | None = None        # ICS base URL for the Admin area (tenant API). None = the Admin area is not offered at all.
    ics_key: str = ""                 # per-customer service credential (file), identifies the customer to the ICS; never a user secret
    ics_ca_bundle: str | None = None  # CA for the ICS TLS certificate
    admin_role: str = "org-admin"     # Keycloak realm role that opens the Admin area (the ICS verifies it again from the signed token)

    @property
    def host(self) -> str:
        return self.base_url.split("://", 1)[1].split("/", 1)[0]

    @property
    def issuer_origin(self) -> str:
        scheme, rest = self.issuer.split("://", 1)
        return f"{scheme}://{rest.split('/', 1)[0]}"

    @property
    def account_url(self) -> str:
        return self.issuer + "/account"

    def mail_view_url(self, view: str) -> str:
        """Deep link into grommunio-web (patch blueprints/build/grommunio-web/patches/0001-context-deep-link.patch). With Keycloak SSO on the
        mail node the user is not asked for a password again. `view` comes from a fixed set (the templates), never from user input."""
        if view not in ("mail", "calendar", "contacts"):
            raise ValueError("unknown view")
        return self.mail_web_url if view == "mail" else f"{self.mail_web_url}?action=context&view={view}"


def load() -> Settings:
    base = _env("PORTAL_BASE_URL").rstrip("/")
    host = base.split("://", 1)[1]
    mail_domain = _env("PORTAL_MAIL_DOMAIN")
    mail_host = _env("PORTAL_MAIL_HOST")
    return Settings(
        base_url=base,
        issuer=_env("PORTAL_OIDC_ISSUER").rstrip("/"),
        client_id=_env("PORTAL_OIDC_CLIENT_ID", "ou-portal"),
        client_secret=_secret("PORTAL_OIDC_CLIENT_SECRET"),
        files_url=_env("PORTAL_FILES_URL").rstrip("/"),
        mail_web_url=_env("PORTAL_MAIL_WEB_URL"),
        mail_domain=mail_domain,
        org_name=_env("PORTAL_ORG_NAME", "Office Unbound"),
        imap_host=mail_host,
        imap_port=int(_env("PORTAL_IMAP_PORT", "993")),
        smtp_host=_env("PORTAL_SMTP_HOST", mail_host),
        smtp_port=int(_env("PORTAL_SMTP_PORT", "587")),
        dav_host=_env("PORTAL_DAV_HOST", mail_host),
        dav_base=_env("PORTAL_DAV_BASE", "/dav").rstrip("/"),
        autodiscover_host=_env("PORTAL_AUTODISCOVER_HOST", f"autodiscover.{mail_domain}"),
        editor_app=_env("PORTAL_EDITOR_APP", "external-collaboraonline"),
        ca_bundle=os.environ.get("PORTAL_CA_BUNDLE") or None,
        ics_url=(os.environ.get("PORTAL_ICS_URL") or "").rstrip("/") or None,
        ics_key=_secret("PORTAL_ICS_KEY") if (os.environ.get("PORTAL_ICS_URL") or "") else "",
        ics_ca_bundle=os.environ.get("PORTAL_ICS_CA_BUNDLE") or None,
        admin_role=_env("PORTAL_ADMIN_ROLE", "org-admin"),
    )
