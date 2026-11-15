#!/usr/bin/python3
"""Render the polkit rule from the root-owned agent.json: user ou-agent may `restart` exactly the allowlisted units; every other
systemd1 action is denied for that user. usage: render_polkit.py /etc/ou-agent/agent.json > /etc/polkit-1/rules.d/50-ou-agent.rules"""
import json
import re
import sys

cfg = json.load(open(sys.argv[1]))
units = sorted({u + ".service" for u in cfg["runbooks"].get("service.restart", {}).get("units", [])})
assert all(re.fullmatch(r"[a-z0-9][a-z0-9_.@-]{0,62}\.service", u) for u in units), "bad unit name"
print("// generated from /etc/ou-agent/agent.json by render_polkit.py - do not edit")
print("polkit.addRule(function(action, subject) {")
print('  if (subject.user != "ou-agent" || action.id.indexOf("org.freedesktop.systemd1.") != 0) return polkit.Result.NOT_HANDLED;')
print("  var allowed = %s;" % json.dumps(units))
print('  if (action.id == "org.freedesktop.systemd1.manage-units" && action.lookup("verb") == "restart" &&')
print("      allowed.indexOf(action.lookup(\"unit\")) >= 0) return polkit.Result.YES;")
print("  return polkit.Result.NO;")
print("});")
