"""Verification of a golden-image release before `image.import` (ADR-0008 step 8, docs/status/golden-image-prod-results.md s4).

A release directory holds, for one image `ou-golden-<os>-<YYYYMMDD>.qcow2`:
  manifest.json      canonical JSON (schema `ou-golden-manifest-v2`, written by blueprints/build/guest-image/manifest.py), signed by the release signer
  manifest.json.sig  base64 DER ECDSA P-256 / SHA-256 over the EXACT bytes of manifest.json
  <image>, <image>.sbom.cdx.json, <image>.packages.lock, <image>.provenance.json   the files the manifest binds by SHA-256
The ICS holds only the PUBLIC release key (operator-confirmed SPKI pin) and the PUBLIC key of the independent test runner (ou-test-attest); both come from
Settings, never from a request. Nothing is imported unless: the signature verifies; the manifest is canonical and closed-schema; every bound file matches
its hash (image, SBOM, package list, provenance); the package list, provenance and manifest agree with each other; the boot-test attestation was made by
the test runner (Ed25519, review 7 H-3: the runner ran the test itself) for THIS image hash, kind image-first-boot, result pass, and is not stale; and the
version is not below the rollback floor kept in the ICS database (review 7 M-4: the floor is monotonic and lives here, not in Proxmox tags)."""
import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "ou-golden-manifest-v2"
MANIFEST, MANIFEST_SIG = "manifest.json", "manifest.json.sig"
IMAGE_RE = re.compile(r"^ou-golden-(debian-12|ubuntu-24\.04)-(\d{8})\.qcow2$")
ATT_PREFIX = b"ou-test-attestation-v1\n"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_MANIFEST = 256 * 1024
MAX_ATTESTATION_AGE = 90 * 86400
TOP_KEYS = {"schema", "name", "os", "version", "created_at", "image", "packages", "sbom", "provenance", "boot_test"}
ATT_KEYS = {"v", "kind", "name", "sha256", "result", "log_sha256", "at", "run_id"}


class ReleaseError(Exception):
    """Operator-readable, secret-free."""


@dataclass(frozen=True)
class Floor:
    version: int
    image_sha256: str


@dataclass(frozen=True)
class Trust:
    """Everything the verifier trusts, built ONLY from Settings by `trust_from_settings` (no field is ever taken from a request or a plan)."""
    release_pubkey_pem: str
    release_pin_sha256: str
    attestor_pubkey_b64: str


@dataclass(frozen=True)
class Release:
    path: str
    name: str
    os: str
    sha256: str
    sbom_path: str
    version: int = 0
    packages_path: str = ""
    provenance_path: str = ""
    manifest_sha256: str = ""
    attestation_run_id: str = ""
    created_at: int = 0

    @property
    def date(self) -> str:
        return self.name.rsplit("-", 1)[1].split(".")[0]


def canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


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

    def record(self, rel) -> None:
        """after a successful import: raise both floors for rel.os (release date and manifest version); never lowers either"""
        raise NotImplementedError


class MemoryFloor(FloorStore):
    def __init__(self):
        self.d: dict[str, str] = {}

    def get(self, os_id):
        return self.d.get(os_id)

    def raise_to(self, os_id, date):
        if date > self.d.get(os_id, ""):
            self.d[os_id] = date

    def record(self, rel):
        self.raise_to(rel.os, rel.date)
        v = getattr(self, "v", {})
        if rel.version > v.get(rel.os, 0):
            v[rel.os] = rel.version
        self.v = v


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

    def record(self, rel):
        advance_floor(self.rt, rel)       # one upsert: date = GREATEST(old, new); version only ever rises (trigger enforced, migration 0015g)


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


def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _bound_file(directory: str, spec, expect_name: str, label: str) -> str:
    if not isinstance(spec, dict) or spec.get("file") != expect_name or not HEX64.match(str(spec.get("sha256", ""))):
        raise ReleaseError(f"manifest entry for {label} is malformed")
    p = os.path.join(directory, expect_name)
    if not os.path.isfile(p) or os.path.islink(p) or _sha256_file(p) != spec["sha256"]:
        raise ReleaseError(f"{expect_name} does not match the signed manifest")
    return p


def verify_release(directory: str, pubkey_pem: str, pin_sha256: str, *, attestor_pubkey_b64: str, floor: Floor | None = None, allow_downgrade: bool = False,
                   now: float | None = None) -> Release:
    now = time.time() if now is None else now
    try:
        pub = serialization.load_pem_public_key(pubkey_pem.encode())
    except ValueError:
        raise ReleaseError("the release public key is not a valid PEM public key") from None
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp256r1":
        raise ReleaseError("the release key must be an ECDSA P-256 public key")
    if key_pin(pubkey_pem) != pin_sha256.lower():
        raise ReleaseError("the release public key does not match the operator-confirmed pin")
    try:
        att_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(attestor_pubkey_b64, validate=True))
    except (ValueError, TypeError):
        raise ReleaseError("the test-runner attestation key is missing or invalid (ICS_GUEST_GOLDEN_ATTESTOR_PUBKEY)") from None
    try:
        with open(os.path.join(directory, MANIFEST), "rb") as f:
            raw = f.read(MAX_MANIFEST + 1)
        sig = base64.b64decode(open(os.path.join(directory, MANIFEST_SIG), "rb").read(4096), validate=True)
    except (OSError, ValueError):
        raise ReleaseError("manifest.json or manifest.json.sig is missing or malformed") from None
    if len(raw) > MAX_MANIFEST:
        raise ReleaseError("manifest.json is too large")
    try:
        pub.verify(sig, raw, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ReleaseError("the manifest signature does not verify against the release key") from None
    try:
        m = json.loads(raw.decode("ascii"), object_pairs_hook=_no_dups)
    except (ValueError, UnicodeDecodeError):
        raise ReleaseError("manifest.json is not valid JSON") from None
    if not isinstance(m, dict) or canon(m) + b"\n" != raw:
        raise ReleaseError("manifest.json is not in canonical form")
    if set(m) != TOP_KEYS or m["schema"] != SCHEMA:
        raise ReleaseError("manifest schema is not ou-golden-manifest-v2 or has unexpected fields")
    name = m["name"]
    nm = IMAGE_RE.match(name) if isinstance(name, str) else None
    if not nm or m["os"] != nm.group(1):
        raise ReleaseError("manifest name/os are inconsistent or not a golden image name")
    if type(m["version"]) is not int or m["version"] < 1 or type(m["created_at"]) is not int or m["created_at"] < 1_000_000_000:
        raise ReleaseError("manifest version/created_at are not valid integers")
    if m["created_at"] > now + 86400:
        raise ReleaseError("manifest is dated in the future")
    img = _bound_file(directory, m["image"], name, "image")
    if m["image"].get("size") != os.path.getsize(img) or set(m["image"]) != {"file", "sha256", "size"}:
        raise ReleaseError("image size does not match the manifest")
    sbom = _bound_file(directory, m["sbom"], name + ".sbom.cdx.json", "SBOM")
    pk = _bound_file(directory, m["packages"], name + ".packages.lock", "package list")
    prov_spec = m["provenance"]
    prov = _bound_file(directory, prov_spec, name + ".provenance.json", "provenance")
    try:
        bom = json.load(open(sbom, "rb"))
        if bom["bomFormat"] != "CycloneDX" or not isinstance(bom.get("components"), list) or len(bom["components"]) < 50:
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise ReleaseError("the SBOM is not a CycloneDX document with a component inventory") from None
    lines = [l for l in open(pk, encoding="ascii", errors="strict").read().splitlines() if l.strip()]
    if not lines or any(not re.fullmatch(r"[a-z0-9][a-z0-9+.\-]*=[A-Za-z0-9.+:~\-]+", l) for l in lines) or lines != sorted(set(lines)) or m["packages"].get("count") != len(lines):
        raise ReleaseError("the package list is malformed, unsorted or its count does not match the manifest")
    try:
        pv = json.load(open(prov, "rb"))
        if (pv["os"] != m["os"] or pv["source_date_epoch"] != m["created_at"] or prov_spec.get("source_date_epoch") != m["created_at"]
                or pv["package_lock_sha256"] != m["packages"]["sha256"] or prov_spec.get("package_lock_sha256") != pv["package_lock_sha256"]
                or pv["recipe_sha256"] != prov_spec.get("recipe_sha256") or not HEX64.match(str(pv["recipe_sha256"])) or not pv.get("archive_inrelease_sha256")):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise ReleaseError("the build provenance is missing or disagrees with the manifest (epoch, os, package list, recipe hash)") from None
    bt = m["boot_test"]
    if not isinstance(bt, dict) or set(bt) != {"attestation", "sig", "attestation_sha256"} or not isinstance(bt["attestation"], dict) or set(bt["attestation"]) != ATT_KEYS:
        raise ReleaseError("the boot-test attestation is missing or has unexpected fields")
    att = bt["attestation"]
    try:
        att_pub.verify(base64.b64decode(bt["sig"], validate=True), ATT_PREFIX + canon(att))
    except (InvalidSignature, ValueError, TypeError):
        raise ReleaseError("the boot-test attestation was not made by the configured test runner") from None
    if hashlib.sha256(canon(att)).hexdigest() != bt["attestation_sha256"]:
        raise ReleaseError("attestation hash does not match")
    if (att["v"] != 2 or att["kind"] != "image-first-boot" or att["name"] != "first-boot" or att["sha256"] != m["image"]["sha256"] or att["result"] != "pass"
            or not HEX64.match(str(att["log_sha256"])) or not re.fullmatch(r"[0-9a-f]{32}", str(att["run_id"])) or type(att["at"]) is not int):
        raise ReleaseError("the boot-test attestation is not a passing image-first-boot attestation of this image")
    if att["at"] < m["created_at"] or att["at"] > now + 300 or now - att["at"] > MAX_ATTESTATION_AGE:
        raise ReleaseError("the boot-test attestation is older than the build, in the future, or stale (> 90 days)")
    if floor is not None and not allow_downgrade:
        if m["version"] < floor.version:
            raise ReleaseError(f"release version {m['version']} is below the rollback floor {floor.version} for {m['os']}; a downgrade needs a separately approved plan")
        if m["version"] == floor.version and floor.image_sha256 != m["image"]["sha256"]:
            raise ReleaseError("a different image carries the version already accepted for this OS")
    return Release(img, name, m["os"], m["image"]["sha256"], sbom, m["version"], pk, prov, hashlib.sha256(raw).hexdigest(), att["run_id"], m["created_at"])


# ---- Settings + database floor -------------------------------------------------------------------------------------------------------------------

def trust_from_settings(settings) -> Trust:
    """The ONLY source of release trust: operator settings. Refuses when any of the three is missing."""
    f, pin, att = settings.guest_golden_release_pubkey_file, settings.guest_golden_release_pin_sha256, settings.guest_golden_attestor_pubkey
    if not (f and pin and att):
        raise ReleaseError("golden image import is not configured (ICS_GUEST_GOLDEN_RELEASE_PUBKEY_FILE, ..._PIN_SHA256, ICS_GUEST_GOLDEN_ATTESTOR_PUBKEY)")
    try:
        pem = open(f, encoding="ascii").read()
    except OSError:
        raise ReleaseError("the release public key file cannot be read") from None
    return Trust(pem, pin, att)


def get_floor(rt, os_id: str) -> Floor | None:
    from sqlalchemy import text
    with rt.session() as db:
        r = db.execute(text("SELECT version, image_sha256 FROM image_floor WHERE os = :o"), {"o": os_id}).first()
    return Floor(int(r[0]), r[1]) if r and r[0] is not None else None


def advance_floor(rt, rel: Release) -> bool:
    """Record an accepted release. Only ever raises the floor (the table's trigger refuses anything else). True when the floor moved."""
    from sqlalchemy import text
    with rt.session() as db:
        r = db.execute(text(
            "INSERT INTO image_floor (os, release_date, version, image_sha256, image_name) VALUES (:o, :d, :v, :s, :n) "
            "ON CONFLICT (os) DO UPDATE SET version = EXCLUDED.version, image_sha256 = EXCLUDED.image_sha256, image_name = EXCLUDED.image_name, "
            "release_date = GREATEST(image_floor.release_date, EXCLUDED.release_date) "
            "WHERE image_floor.version IS NULL OR image_floor.version < EXCLUDED.version RETURNING version"),
            {"o": rel.os, "d": rel.date, "v": rel.version, "s": rel.sha256, "n": rel.name}).first()
        db.commit()
    return r is not None


def verify_for_import(rt, release_dir: str, *, allow_downgrade: bool = False) -> Release:
    """Verification with trust from Settings and the floor from the database. The os is read from the (signed) manifest first, then the floor for that os
    is applied. This is what an import plan step calls; the result is what ImageImportSpec carries."""
    trust = trust_from_settings(rt.settings)
    first = verify_release(release_dir, trust.release_pubkey_pem, trust.release_pin_sha256, attestor_pubkey_b64=trust.attestor_pubkey_b64, floor=None)
    floor = get_floor(rt, first.os)
    return verify_release(release_dir, trust.release_pubkey_pem, trust.release_pin_sha256, attestor_pubkey_b64=trust.attestor_pubkey_b64, floor=floor,
                          allow_downgrade=allow_downgrade)
