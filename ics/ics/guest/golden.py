"""Verification of a golden-image release before `image.import` (ADR-0008 step 8, docs/status/bootstrap-v2.md).

A release directory holds `ou-golden-<os>-<date>.qcow2`, its CycloneDX SBOM, `SHA256SUMS` and `SHA256SUMS.sig` (base64 DER ECDSA P-256 / SHA-256 over
SHA256SUMS, made on the offline release host). The ICS holds only the PUBLIC key (a file whose SHA-256-of-SPKI pin the operator confirmed, the same
convention as the container image signing key). Nothing is imported unless the manifest signature verifies, the image and SBOM hashes match it, and the
file names are the closed form the provider verb accepts."""
import base64
import hashlib
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

IMAGE_RE = re.compile(r"^ou-golden-(debian-12|ubuntu-24\.04)-\d{8}\.qcow2$")
LINE_RE = re.compile(r"^([0-9a-f]{64})  (\S+)$")


class ReleaseError(Exception):
    """Operator-readable, secret-free."""


@dataclass(frozen=True)
class Release:
    path: str
    name: str
    os: str
    sha256: str
    sbom_path: str

    @property
    def date(self) -> str:
        return self.name.rsplit("-", 1)[1].split(".")[0]


REL_TAG = re.compile(r"(?:^|[;, ])ou-rel-(debian-12|ubuntu-24\.04)-(\d{8})(?:$|[;, ])")


def newest_imported(tag_strings, os_id: str) -> str | None:
    """Review 5 M7 (rollback protection): the newest release date already imported for this OS, read from the template tags the verb itself sets."""
    best = None
    for t in tag_strings:
        for m in REL_TAG.finditer(";" + str(t) + ";"):
            if m.group(1) == os_id and (best is None or m.group(2) > best):
                best = m.group(2)
    return best


# ---- review 7 M-4: the trust root and the downgrade floor are SERVER state, never part of a plan or of the caller's spec -------------------------------
_TRUST: dict = {"pem": None, "pin": None}


def configure(pubkey_pem: str | None, pin_sha256: str | None) -> None:
    """called by Runtime from Settings (ICS_GUEST_RELEASE_PUBKEY_FILE + ICS_GUEST_RELEASE_PIN_SHA256, the operator-confirmed pin of the offline release key)"""
    _TRUST.update(pem=pubkey_pem, pin=pin_sha256)


def trust_root() -> tuple[str, str]:
    if not _TRUST["pem"] or not _TRUST["pin"]:
        raise ReleaseError("this ICS has no golden-image release key configured (ICS_GUEST_RELEASE_PUBKEY_FILE / ICS_GUEST_RELEASE_PIN_SHA256): nothing is imported")
    return _TRUST["pem"], _TRUST["pin"]


class FloorStore:
    """the downgrade floor per OS; the real store is the `image_floor` table (monotonic by trigger)"""

    def get(self, os_id: str) -> str | None:
        raise NotImplementedError

    def raise_to(self, os_id: str, date: str) -> None:
        raise NotImplementedError


class MemoryFloor(FloorStore):
    def __init__(self):
        self.d: dict[str, str] = {}

    def get(self, os_id):
        return self.d.get(os_id)

    def raise_to(self, os_id, date):
        if date > self.d.get(os_id, ""):
            self.d[os_id] = date


class DbFloor(FloorStore):
    def __init__(self, rt):
        self.rt = rt

    def get(self, os_id):
        from sqlalchemy import text
        with self.rt.session() as db:
            return db.execute(text("SELECT release_date FROM image_floor WHERE os = :o"), {"o": os_id}).scalar()

    def raise_to(self, os_id, date):
        from sqlalchemy import text
        with self.rt.session() as db:
            db.execute(text("INSERT INTO image_floor (os, release_date) VALUES (:o, :d) ON CONFLICT (os) DO UPDATE SET release_date = GREATEST(image_floor.release_date, EXCLUDED.release_date)"),
                       {"o": os_id, "d": date})
            db.commit()


_FLOOR: FloorStore | None = None


def set_floor_store(store: FloorStore | None) -> None:
    global _FLOOR
    _FLOOR = store


def floor_store() -> FloorStore:
    if _FLOOR is None:
        raise ReleaseError("no downgrade-floor store configured: nothing is imported")
    return _FLOOR


def key_pin(pem: str) -> str:
    k = serialization.load_pem_public_key(pem.encode())
    return hashlib.sha256(k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_release(directory: str, pubkey_pem: str, pin_sha256: str) -> Release:
    try:
        pub = serialization.load_pem_public_key(pubkey_pem.encode())
    except ValueError:
        raise ReleaseError("the release public key is not a valid PEM public key") from None
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise ReleaseError("the release key must be an ECDSA P-256 public key")
    if key_pin(pubkey_pem) != pin_sha256.lower():
        raise ReleaseError("the release public key does not match the operator-confirmed pin")
    try:
        with open(os.path.join(directory, "SHA256SUMS"), "rb") as f:
            manifest = f.read(65536)
        sig = base64.b64decode(open(os.path.join(directory, "SHA256SUMS.sig"), "rb").read(4096), validate=True)
    except (OSError, ValueError):
        raise ReleaseError("SHA256SUMS or SHA256SUMS.sig is missing or malformed") from None
    try:
        pub.verify(sig, manifest, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ReleaseError("the manifest signature does not verify against the release key") from None
    entries = {}
    for line in manifest.decode("ascii", "strict").splitlines():
        m = LINE_RE.match(line)
        if not m or "/" in m.group(2) or m.group(2) in entries:
            raise ReleaseError("malformed manifest line")
        entries[m.group(2)] = m.group(1)
    images = [n for n in entries if IMAGE_RE.match(n)]
    if len(images) != 1 or f"{images[0]}.sbom.cdx.json" not in entries or len(entries) != 2:
        raise ReleaseError("the manifest must list exactly one ou-golden-<os>-<date>.qcow2 and its SBOM")
    name = images[0]
    for n in (name, name + ".sbom.cdx.json"):
        p = os.path.join(directory, n)
        if not os.path.isfile(p) or os.path.islink(p) or _sha256_file(p) != entries[n]:
            raise ReleaseError(f"{n} does not match the signed manifest")
    return Release(os.path.join(directory, name), name, IMAGE_RE.match(name).group(1), entries[name], os.path.join(directory, name + ".sbom.cdx.json"))
