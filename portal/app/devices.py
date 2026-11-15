"""Device onboarding: generated configuration files + per-platform instructions.

Rules (hard): no password, token or secret is ever written into a generated file; every file is derived from the
signed-in user's e-mail address and the server settings only. Unsigned profiles are lab-acceptable; production must sign
(see docs/status/portal-results.md, "Profile signing").
"""
from __future__ import annotations

import plistlib
import uuid
from xml.sax.saxutils import escape

from .config import Settings

# Pinned desktop client release (verified against the vendor's published digests, 2026-11-15). Update with the release.
DESKTOP_RELEASE = "v4.0.0"
_BASE = "https://github.com/opencloud-eu/desktop/releases/download/" + DESKTOP_RELEASE + "/"
DESKTOP_DOWNLOADS = [
    {"platform": "Linux (AppImage, x86-64)", "file": "OpenCloud_Desktop-v4.0.0-linux-gcc-x86_64.AppImage",
     "sha256": "22c5fac4453ce2bfb033f4a4f288aea33bbdc1178518026973f76b1c5c4e1d2c", "size_mb": 71.4},
    {"platform": "macOS (Apple silicon)", "file": "OpenCloud_Desktop-v4.0.0-macos-clang-arm64.pkg",
     "sha256": "6db479f17b3cbad27826e9599caff2177363945c7dca192f1e9e08d875c66d27", "size_mb": 61.4},
    {"platform": "macOS (Intel)", "file": "OpenCloud_Desktop-v4.0.0-macos-clang-x86_64.pkg",
     "sha256": "b5172a8b47f21da7947307ccb3db057aa1b5b8ce826c430721d8d550d5e866f5", "size_mb": 66.2},
]
for _d in DESKTOP_DOWNLOADS:
    _d["url"] = _BASE + _d["file"]
DESKTOP_RELEASES_PAGE = "https://github.com/opencloud-eu/desktop/releases"
MOBILE_APPS = {
    "ios": "https://apps.apple.com/app/id6743121005",
    "android_play": "https://play.google.com/store/apps/details?id=eu.opencloud.android",
    "android_fdroid": "https://f-droid.org/packages/eu.opencloud.android/",
    "davx5_fdroid": "https://f-droid.org/packages/at.bitfire.davdroid/",
}


def local_part(email: str) -> str:
    return email.split("@", 1)[0]


def autoconfig_xml(cfg: Settings, email: str | None = None) -> str:
    """Mozilla autoconfig (Thunderbird, also K-9/FairEmail and others). %EMAILADDRESS% is substituted by the client."""
    dom = escape(cfg.mail_domain)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{dom}">
    <domain>{dom}</domain>
    <displayName>{escape(cfg.org_name)} mail</displayName>
    <displayShortName>{escape(cfg.org_name)}</displayShortName>
    <incomingServer type="imap">
      <hostname>{escape(cfg.imap_host)}</hostname>
      <port>{cfg.imap_port}</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{escape(cfg.smtp_host)}</hostname>
      <port>{cfg.smtp_port}</port>
      <socketType>{"SSL" if cfg.smtp_port == 465 else "STARTTLS"}</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
    <documentation url="{escape(cfg.base_url)}/devices">
      <descr lang="en">Set up your devices</descr>
    </documentation>
  </emailProvider>
</clientConfig>
"""


def mobileconfig(cfg: Settings, email: str, display_name: str) -> bytes:
    """Apple configuration profile (IMAP/SMTP + CalDAV + CardDAV). NO passwords: iOS/macOS prompts for it on install.
    UNSIGNED. Identifiers/UUIDs are deterministic per (portal host, user) so re-installing replaces instead of duplicating."""
    ns = uuid.uuid5(uuid.NAMESPACE_DNS, cfg.host)

    def u(kind: str) -> str:
        return str(uuid.uuid5(ns, f"{email.lower()}/{kind}")).upper()

    ident = "eu.officeunbound.portal." + cfg.host.replace(":", "-")
    principal = cfg.dav_base + "/"
    payloads = [
        {
            "PayloadType": "com.apple.mail.managed", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.mail.{u('mail')}",
            "PayloadUUID": u("mail"), "PayloadDisplayName": f"{cfg.org_name} mail", "PayloadOrganization": cfg.org_name,
            "EmailAccountDescription": f"{cfg.org_name} mail", "EmailAccountName": display_name, "EmailAccountType": "EmailTypeIMAP",
            "EmailAddress": email,
            "IncomingMailServerAuthentication": "EmailAuthPassword", "IncomingMailServerHostName": cfg.imap_host,
            "IncomingMailServerPortNumber": cfg.imap_port, "IncomingMailServerUseSSL": True, "IncomingMailServerUsername": email,
            "OutgoingMailServerAuthentication": "EmailAuthPassword", "OutgoingMailServerHostName": cfg.smtp_host,
            "OutgoingMailServerPortNumber": cfg.smtp_port, "OutgoingMailServerUseSSL": True, "OutgoingMailServerUsername": email,
            "OutgoingPasswordSameAsIncomingPassword": True, "PreventMove": False, "SMIMEEnabled": False,
        },
        {
            "PayloadType": "com.apple.caldav.account", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.caldav.{u('caldav')}",
            "PayloadUUID": u("caldav"), "PayloadDisplayName": f"{cfg.org_name} calendar", "PayloadOrganization": cfg.org_name,
            "CalDAVAccountDescription": f"{cfg.org_name} calendar", "CalDAVHostName": cfg.dav_host, "CalDAVPort": 443,
            "CalDAVUseSSL": True, "CalDAVUsername": email, "CalDAVPrincipalURL": principal,
        },
        {
            "PayloadType": "com.apple.carddav.account", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.carddav.{u('carddav')}",
            "PayloadUUID": u("carddav"), "PayloadDisplayName": f"{cfg.org_name} contacts", "PayloadOrganization": cfg.org_name,
            "CardDAVAccountDescription": f"{cfg.org_name} contacts", "CardDAVHostName": cfg.dav_host, "CardDAVPort": 443,
            "CardDAVUseSSL": True, "CardDAVUsername": email, "CardDAVPrincipalURL": principal,
        },
    ]
    profile = {
        "PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.{u('profile')}", "PayloadUUID": u("profile"),
        "PayloadDisplayName": f"{cfg.org_name}: mail, calendar, contacts", "PayloadOrganization": cfg.org_name,
        "PayloadDescription": "Sets up mail, calendar and contacts. You will be asked for your password; it is not stored in this profile.",
        "PayloadRemovalDisallowed": False, "PayloadContent": payloads,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def platform_hint(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    if "iphone" in ua or "ipad" in ua:
        return "ios"
    if "android" in ua:
        return "android"
    if "windows" in ua:
        return "windows"
    if "macintosh" in ua or "mac os" in ua:
        return "mac"
    if "linux" in ua or "x11" in ua:
        return "linux"
    return ""
