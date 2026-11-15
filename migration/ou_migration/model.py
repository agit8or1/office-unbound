"""Assessment data model.

Every reported number/fact is a ``Field`` carrying a provenance tag:

* ``verified``   - read directly from the source API / public DNS in this run.
* ``estimated``  - derived by a stated formula from verified inputs (basis says how).
* ``assumption`` - an operator input or a default we chose (basis says which).

Only metadata and counts are ever stored. No message bodies, file names, file content,
event/contact content. (Display names / UPNs of directory objects ARE stored: they are
needed for identity mapping; see docs/status/migration-assessment.md "Data handling".)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

VERIFIED, ESTIMATED, ASSUMPTION = "verified", "estimated", "assumption"
TAGS = (VERIFIED, ESTIMATED, ASSUMPTION)


@dataclass(frozen=True)
class Field:
    value: Any
    tag: str
    basis: str = ""

    def __post_init__(self):
        if self.tag not in TAGS:
            raise ValueError(f"bad tag {self.tag!r}")

    def to_json(self) -> dict:
        d = {"value": self.value, "tag": self.tag}
        if self.basis:
            d["basis"] = self.basis
        return d


def verified(value, basis=""):
    return Field(value, VERIFIED, basis)


def estimated(value, basis):
    return Field(value, ESTIMATED, basis)


def assumption(value, basis):
    return Field(value, ASSUMPTION, basis)


# Size buckets for file/mailbox distributions (bytes upper bounds).
SIZE_BUCKETS = [("<1 GiB", 1 << 30), ("1-5 GiB", 5 << 30), ("5-25 GiB", 25 << 30),
                ("25-50 GiB", 50 << 30), (">=50 GiB", None)]


def bucketize(sizes: list[int]) -> dict[str, int]:
    out = {name: 0 for name, _ in SIZE_BUCKETS}
    for s in sizes:
        for name, hi in SIZE_BUCKETS:
            if hi is None or s < hi:
                out[name] += 1
                break
    return out


@dataclass
class Domain:
    name: str
    verified: bool
    is_default: bool = False
    services: list[str] = field(default_factory=list)
    dns: dict | None = None  # filled by dns_check


@dataclass
class User:
    source_id: str
    login: str                      # UPN (M365) / primaryEmail (Google)
    display_name: str = ""
    mail: str = ""
    aliases: list[str] = field(default_factory=list)
    enabled: bool = True
    user_type: str = "member"       # member | guest | service
    licensed: bool | None = None
    is_admin: bool | None = None
    suspended: bool = False
    # usage (None = not obtainable / not collected)
    mailbox_bytes: int | None = None
    mailbox_items: int | None = None
    has_archive: bool | None = None
    file_bytes: int | None = None
    file_count: int | None = None
    last_activity: str | None = None
    login_concealed: bool = False   # report names hashed by tenant privacy setting
    shared_mailbox_guess: bool = False


@dataclass
class Group:
    source_id: str
    name: str
    mail: str = ""
    kind: str = "security"  # distribution | security | mail-security | m365-group | team | google-group
    members: int | None = None
    dynamic: bool = False
    has_team: bool = False


@dataclass
class Site:
    source_id: str
    url: str
    template: str = ""
    bytes: int | None = None
    files: int | None = None
    page_views: int | None = None
    is_deleted: bool = False


@dataclass
class Inventory:
    provider: str                   # m365 | google
    tenant_id: str = ""
    tenant_name: str = ""
    collected_at: str = ""
    domains: list[Domain] = field(default_factory=list)
    users: list[User] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)
    sites: list[Site] = field(default_factory=list)
    # counts obtained without content (key -> int); absent = not collected
    counts: dict[str, int] = field(default_factory=dict)
    # feature signals detected in the source (key -> bool|int), for unsupported-feature mapping
    signals: dict[str, Any] = field(default_factory=dict)
    # drive file-size distribution (bucket -> count of files) when a metadata scan was permitted
    file_size_buckets: dict[str, int] | None = None
    sharing: dict[str, int] = field(default_factory=dict)  # e.g. {"anyone_link_files": n, "external_shares": n}
    warnings: list[str] = field(default_factory=list)  # partial failures, concealed names, missing permissions
    coverage: dict[str, str] = field(default_factory=dict)  # collector -> ok | partial | skipped | failed: reason
