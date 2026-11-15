#!/usr/bin/python3
"""Render the polkit rule from the root-owned agent.json: user ou-agent may `restart` exactly the allowlisted units; every other
systemd1 action is denied for that user. usage: render_polkit.py /etc/ou-agent/agent.json > /etc/polkit-1/rules.d/50-ou-agent.rules"""
import json
import re
import sys

USER_UNITS = {"gromox.sync_user": "ou-rb-gromox-sync", "gromox.kick_user": "ou-rb-gromox-quarantine",
              "gromox.user_state": "ou-rb-gromox-state", "gromox.kill_sessions": "ou-rb-gromox-kill",
              "gromox.wipe_devices": "ou-rb-gromox-wipe", "gromox.devices": "ou-rb-gromox-devices", "opencloud.check_user": "ou-rb-opencloud-check", "opencloud.revoke_app_tokens": "ou-rb-opencloud-revoke",
              "podman.pull_verified": "ou-rb-podman", "podman.deploy_unit": "ou-rb-podman", "podman.remove_unit": "ou-rb-podman",
              "podman.status": "ou-rb-podman", "guest.facts": "ou-rb-podman", "pkg.install_pinned": "ou-rb-pkg"}

cfg = json.load(open(sys.argv[1]))
units = sorted({u + ".service" for u in cfg["runbooks"].get("service.restart", {}).get("units", [])})
assert all(re.fullmatch(r"[a-z0-9][a-z0-9_.@-]{0,62}\.service", u) for u in units), "bad unit name"
print("// generated from /etc/ou-agent/agent.json by render_polkit.py - do not edit")
print("polkit.addRule(function(action, subject) {")
print('  if (subject.user != "ou-agent" || action.id.indexOf("org.freedesktop.systemd1.") != 0) return polkit.Result.NOT_HANDLED;')
templates = sorted({USER_UNITS[k] for k in cfg["runbooks"] if k in USER_UNITS})
assert all(re.fullmatch(r"ou-rb-[a-z-]+", t) for t in templates)
print("  var allowed = %s;" % json.dumps(units))
print("  var tmpl = %s;" % json.dumps(templates))
print('  if (action.id == "org.freedesktop.systemd1.manage-units" && action.lookup("verb") == "restart" &&')
print("      allowed.indexOf(action.lookup(\"unit\")) >= 0) return polkit.Result.YES;")
print("  // identity runbooks: START exactly the fixed template units with a lowercase-uid instance; nothing else")
print('  if (action.id == "org.freedesktop.systemd1.manage-units" && action.lookup("verb") == "start") {')
print('    var m = /^(ou-rb-[a-z-]+)@[a-z][a-z0-9._-]{1,31}\\.service$/.exec(action.lookup("unit") || "");')
print("    if (m && tmpl.indexOf(m[1]) >= 0) return polkit.Result.YES;")
print("  }")
print("  return polkit.Result.NO;")
print("});")
