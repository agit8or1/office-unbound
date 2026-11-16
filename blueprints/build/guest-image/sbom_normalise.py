#!/usr/bin/env python3
"""Make the syft CycloneDX output reproducible: the only two run-dependent fields are the random `serialNumber` and the wall-clock `metadata.timestamp`.
Usage: sbom_normalise.py <sbom.json> <packages.lock> <SOURCE_DATE_EPOCH>   (rewrites the SBOM in place, sorted keys)"""
import datetime
import hashlib
import json
import sys
import uuid

p, lock, sde = sys.argv[1], sys.argv[2], int(sys.argv[3])
b = json.load(open(p))
b["serialNumber"] = "urn:uuid:" + str(uuid.UUID(hashlib.sha256(open(lock, "rb").read()).hexdigest()[:32]))
b.setdefault("metadata", {})["timestamp"] = datetime.datetime.fromtimestamp(sde, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
open(p, "w").write(json.dumps(b, sort_keys=True, indent=1) + "\n")
