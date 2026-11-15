#!/usr/bin/env python3
"""Key rotation test helper (inside ou-id1): add / remove a higher-priority RS256 key provider in the realm.
  kc-rotate-key.py add     new active key (priority above all existing) -> Keycloak signs new tokens with it at once
  kc-rotate-key.py remove  delete that provider -> the previous key is the active signing key again (rollback)
"""
import sys

sys.path.insert(0, "/root")
from kc_lib import REALM, admin_token, call  # noqa: E402

NAME = "ou-rotation-test"
A = f"/admin/realms/{REALM}"
T = admin_token()
realm_id = call("GET", A, T)[1]["id"]
comps = call("GET", f"{A}/components?type=org.keycloak.keys.KeyProvider", T)[1]
mine = [c for c in comps if c["name"] == NAME]
if sys.argv[1] == "add":
    if mine:
        print("already present")
    else:
        prio = max([int((c.get("config", {}).get("priority") or ["0"])[0]) for c in comps] + [100]) + 100
        call("POST", f"{A}/components", T, {"name": NAME, "providerId": "rsa-generated", "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm_id,
                                            "config": {"priority": [str(prio)], "enabled": ["true"], "active": ["true"], "keySize": ["2048"], "algorithm": ["RS256"]}})
        print("added key provider priority", prio)
else:
    for c in mine:
        call("DELETE", f"{A}/components/{c['id']}", T)
    print("removed", len(mine))
