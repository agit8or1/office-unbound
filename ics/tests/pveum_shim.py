#!/usr/bin/env python3
"""TEST DOUBLE: a fake `pveum` / `pvesh` that forwards the subset of commands the generated provisioning script uses to the Proxmox SIMULATOR
(tests/pve_sim.py) as root@pam. Used only by tests to run the Mode B script against the simulator. Never contacts anything but SIM_URL.

env: SIM_URL (https://127.0.0.1:port), SIM_USER, SIM_PASS. Invoked as `pveum_shim.py pveum ARGS...` or `pveum_shim.py pvesh ARGS...`."""
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

URL = os.environ["SIM_URL"]
assert URL.startswith("https://127.0.0.1:"), "shim only talks to the local simulator"
CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname, CTX.verify_mode = False, ssl.CERT_NONE


def call(method, path, form=None, auth=None):
    data = urllib.parse.urlencode(form or {}).encode() if method != "GET" or form else None
    req = urllib.request.Request(URL + "/api2/json" + path, data=data, method=method)
    if auth:
        req.add_header("Cookie", "PVEAuthCookie=" + urllib.parse.quote(auth["ticket"]))
        req.add_header("CSRFPreventionToken", auth["CSRFPreventionToken"])
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return json.load(r)["data"]
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"{e.code} {e.reason}\n")
        sys.exit(255)


def login():
    return call("POST", "/access/ticket", {"username": os.environ["SIM_USER"], "password": os.environ["SIM_PASS"]})


def opts(args):
    pos, kv, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            kv[a[2:]] = args[i + 1]
            i += 2
        else:
            pos.append(a)
            i += 1
    return pos, kv


def main():
    tool, args = sys.argv[1], sys.argv[2:]
    auth = login()
    pos, kv = opts(args)
    if tool == "pvesh":
        assert pos[0] == "get", pos
        print(json.dumps(call("GET", pos[1], auth=auth), indent=2))
        return
    a, b = pos[0], pos[1]
    if (a, b) == ("user", "add"):
        call("POST", "/access/users", {"userid": pos[2], "comment": kv.get("comment", ""), "enable": kv.get("enable", "1")}, auth)
    elif (a, b) == ("user", "delete"):
        call("DELETE", f"/access/users/{pos[2]}", {}, auth)
    elif (a, b, pos[2]) == ("user", "token", "add"):
        out = call("POST", f"/access/users/{pos[3]}/token/{pos[4]}", {"privsep": kv.get("privsep", "1"), "comment": kv.get("comment", "")}, auth)
        print(json.dumps(out))
    elif (a, b, pos[2]) == ("user", "token", "remove"):
        call("DELETE", f"/access/users/{pos[3]}/token/{pos[4]}", {}, auth)
    elif (a, b) == ("role", "add"):
        call("POST", "/access/roles", {"roleid": pos[2], "privs": kv["privs"]}, auth)
    elif (a, b) == ("role", "modify"):
        call("PUT", f"/access/roles/{pos[2]}", {"privs": kv["privs"]}, auth)
    elif (a, b) == ("role", "delete"):
        call("DELETE", f"/access/roles/{pos[2]}", {}, auth)
    elif (a, b) in (("acl", "modify"), ("acl", "delete")):
        f = {"path": pos[2], "roles": kv["roles"], "propagate": kv.get("propagate", "1")}
        if "users" in kv:
            f["users"] = kv["users"]
        if "tokens" in kv:
            f["tokens"] = kv["tokens"]
        if b == "delete":
            f["delete"] = "1"
        call("PUT", "/access/acl", f, auth)
    elif (a, b) == ("pool", "add"):
        call("POST", "/pools", {"poolid": pos[2], "comment": kv.get("comment", "")}, auth)
    elif (a, b) == ("pool", "delete"):
        call("DELETE", f"/pools/{pos[2]}", {}, auth)
    else:
        sys.stderr.write(f"shim: unsupported command {args}\n")
        sys.exit(2)


main()
