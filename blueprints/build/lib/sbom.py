#!/usr/bin/env python3
"""ADR-0008 step 5: SPDX 2.3 SBOM per binary .deb of a component.
  sbom.py <component> <state-dir> <build-dir>
Primary generator (documented equivalent, deterministic): dpkg metadata + recipe (pinned upstream commit, licences) +
runtime Depends resolved to the exact versions in the builder manifest + bundled npm/composer packages from lock files.
Secondary: syft (pinned, checksum-verified) over the extracted package payload -> <pkg>.syft.spdx.json (cross-check,
catches bundled content we did not model). Output: <state>/out/<component>/sbom/."""
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import urllib.request
import uuid

import yaml

comp, state, bdir = sys.argv[1:4]
out = os.path.join(state, "out", comp)
art = os.path.join(out, "artifacts")
sb = os.path.join(out, "sbom")
os.makedirs(sb, exist_ok=True)
recipe = yaml.safe_load(open(os.path.join(bdir, comp, "recipe.yaml")))
info = dict(l.strip().split("=", 1) for l in open(os.path.join(out, "source.info")) if "=" in l)
env = {}
for l in open(os.path.join(bdir, "tools.env")):
    if "=" in l and not l.startswith("#"):
        k, v = l.strip().split("=", 1)
        env[k] = v
sde = int(info["source_date_epoch"])
created = subprocess.check_output(["date", "-u", "-d", f"@{sde}", "+%Y-%m-%dT%H:%M:%SZ"]).decode().strip()


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def ensure_tool(name, url, sha, dest_tar=False):
    tdir = os.path.join(state, "tools")
    os.makedirs(tdir, exist_ok=True)
    fn = os.path.join(tdir, os.path.basename(url))
    if not os.path.exists(fn):
        urllib.request.urlretrieve(url, fn)
    if sha256(fn) != sha:
        sys.exit(f"CHECKSUM MISMATCH for {name}: refusing to use it")
    if dest_tar:
        d = os.path.join(tdir, name)
        if not os.path.exists(os.path.join(d, name)):
            os.makedirs(d, exist_ok=True)
            tarfile.open(fn).extractall(d, filter="data")
        return os.path.join(d, name)
    os.chmod(fn, 0o755)
    return fn


builder_ver = {}
for l in open(os.path.join(out, "artifacts", "build-env.txt")):
    n, v = l.split(None, 1)
    builder_ver[n] = v.strip()
purl_q = "arch=amd64&distro=debian-12"


def lock_pkgs(srcdir):
    res = []
    for dp, dn, fn in os.walk(srcdir):
        dn[:] = [d for d in dn if d not in (".git", "node_modules")]
        for f in fn:
            p = os.path.join(dp, f)
            if f == "package-lock.json":
                for k, v in (json.load(open(p)).get("packages") or {}).items():
                    if k and v.get("version") and not v.get("dev") and not v.get("devOptional"):
                        n = v.get("name") or k.split("node_modules/")[-1]
                        lic = v.get("license")
                        res.append(("npm", n, v["version"], lic if isinstance(lic, str) else None))
            elif f == "yarn.lock":      # no licence data in yarn.lock: NOASSERTION
                txt = open(p, encoding="utf8").read()
                for n, v in sorted(set(re.findall(r'^"?(@?[^@\s"]+)@[^\n]*:\n  version "([^"]+)"', txt, re.M))):
                    res.append(("npm", n, v, None))
            elif f == "composer.lock":
                for v in json.load(open(p)).get("packages", []):
                    res.append(("composer", v["name"], v["version"].lstrip("v"), " AND ".join(v.get("license") or []) or None))
    return res


srcdir = os.path.join(state, "src", recipe["src_name"])
bundled = lock_pkgs(srcdir)
pyl = os.path.join(bdir, comp, "debian", "requirements.lock")
if os.path.exists(pyl):   # hash-locked PyPI packages shipped in the package (admin-api)
    for l in open(pyl):
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", l)
        if m:
            bundled.append(("pypi", m.group(1).lower(), m.group(2), None))
debs = sorted(f for f in os.listdir(art) if f.endswith(".deb") and "-dbgsym_" not in f)
syft = None
index = []
for deb in debs:
    path = os.path.join(art, deb)
    ctl = {}
    for l in subprocess.check_output(["dpkg-deb", "-f", path]).decode().split("\n"):
        if re.match(r"^[A-Za-z-]+:", l):
            k, v = l.split(":", 1)
            ctl[k] = v.strip()
    name, ver = ctl["Package"], ctl["Version"]
    ns = uuid.uuid5(uuid.NAMESPACE_URL, f"https://officeunbound.com/sbom/{name}/{ver}/{sha256(path)}")
    pk = []
    spdx_id = "SPDXRef-Package"
    pk.append({
        "SPDXID": spdx_id, "name": name, "versionInfo": ver,
        "supplier": "Organization: Office Unbound", "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False, "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(path)}],
        "licenseDeclared": "NOASSERTION",
        "licenseComments": "declared source licences (SPDX ids / exception texts): " + ", ".join(recipe["licenses"]),
        "copyrightText": "NOASSERTION",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                          "referenceLocator": f"pkg:deb/officeunbound/{name}@{ver}?arch=amd64&distro=debian-12"}]})
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": spdx_id}]
    # upstream source
    repo = recipe["source"]["repo"].replace("https://github.com/", "")
    pk.append({"SPDXID": "SPDXRef-Source", "name": recipe["src_name"] + "-upstream", "versionInfo": recipe["source"]["tag"],
               "downloadLocation": f"git+{recipe['source']['repo']}@{recipe['source']['commit']}", "filesAnalyzed": False,
               "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
               "checksums": [{"algorithm": "SHA256", "checksumValue": info["orig_sha256"]}],
               "comment": "checksum is of the deterministic git-archive orig tarball; commit pinned in recipe",
               "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                 "referenceLocator": f"pkg:github/{repo}@{recipe['source']['commit']}"}]})
    rels.append({"spdxElementId": spdx_id, "relationshipType": "GENERATED_FROM", "relatedSpdxElement": "SPDXRef-Source"})
    # patches
    pdir = os.path.join(bdir, comp, "patches")
    for p in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
        if p.endswith(".patch"):
            i = "SPDXRef-Patch-" + re.sub(r"[^A-Za-z0-9.-]", "-", p)
            pk.append({"SPDXID": i, "name": p, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                       "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
                       "checksums": [{"algorithm": "SHA256", "checksumValue": sha256(os.path.join(pdir, p))}]})
            rels.append({"spdxElementId": i, "relationshipType": "PATCH_APPLIED", "relatedSpdxElement": "SPDXRef-Source"})
    # runtime dependencies (from Depends), resolved to exact installed versions in the builder (= what linked against)
    deps = set()
    for part in ctl.get("Depends", "").split(","):
        for alt in part.split("|")[:1]:
            m = re.match(r"\s*([a-z0-9][a-z0-9+.-]+)", alt)
            if m:
                deps.add(m.group(1))
    n = 0
    for d in sorted(deps):
        n += 1
        i = f"SPDXRef-Dep-{n}"
        v = builder_ver.get(d)
        if d.startswith("ou-"):
            purl = None
        else:
            purl = f"pkg:deb/debian/{d}@{v}?{purl_q}" if v else None
        e = {"SPDXID": i, "name": d, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
             "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
             "comment": "runtime Depends; version = what the builder had installed" if v else "runtime Depends (virtual/our package or not in builder)"}
        if v:
            e["versionInfo"] = v
        if purl:
            e["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]
        pk.append(e)
        rels.append({"spdxElementId": spdx_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": i})
    # bundled language packages (only for packages that ship them: arch-all web/sync/dav/admin payloads)
    if bundled and name != "ou-gromox-php-mapi" and (recipe.get("bundles_lock_packages", False)):
        for n2, (eco, bn, bv, bl) in enumerate(bundled):
            i = f"SPDXRef-Bundled-{n2}"
            pk.append({"SPDXID": i, "name": bn, "versionInfo": bv, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                       "licenseDeclared": bl or "NOASSERTION", "copyrightText": "NOASSERTION",
                       "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                         "referenceLocator": f"pkg:{eco}/{bn}@{bv}"}]})
            rels.append({"spdxElementId": spdx_id, "relationshipType": "CONTAINS", "relatedSpdxElement": i})
    doc = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": f"{name}-{ver}",
           "documentNamespace": f"https://officeunbound.com/spdx/{ns}",
           "creationInfo": {"created": created, "creators": ["Organization: Office Unbound", "Tool: ou-sbom-1 (blueprints/build/lib/sbom.py)"]},
           "packages": pk, "relationships": rels}
    fn = os.path.join(sb, f"{name}_{ver}.spdx.json")
    json.dump(doc, open(fn, "w"), indent=1, sort_keys=True)
    # secondary: syft over the extracted payload
    syft = syft or ensure_tool("syft", env["SYFT_URL"], env["SYFT_SHA256"], dest_tar=True)
    tmp = os.path.join(state, "tmp-extract", name)
    subprocess.run(["rm", "-rf", tmp], check=True)
    os.makedirs(tmp)
    subprocess.run(["dpkg-deb", "-x", path, tmp], check=True)
    sfn = os.path.join(sb, f"{name}_{ver}.syft.spdx.json")
    r = subprocess.run([syft, "scan", f"dir:{tmp}", "-o", f"spdx-json={sfn}", "-q"], capture_output=True, text=True,
                       env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"})
    sd = json.load(open(sfn)) if os.path.exists(sfn) else {"packages": []}
    subprocess.run(["rm", "-rf", tmp], check=True)
    index.append({"package": name, "version": ver, "sbom": os.path.basename(fn), "packages_in_sbom": len(pk),
                  "syft_packages": len(sd.get("packages", [])), "deb_sha256": sha256(path)})
    print(f"sbom {name} {ver}: {len(pk)} packages (ou-sbom), {len(sd.get('packages', []))} (syft)")
json.dump(index, open(os.path.join(sb, "index.json"), "w"), indent=1)
