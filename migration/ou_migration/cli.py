"""CLI: ``python -m ou_migration assess --provider m365|google --out DIR [--resume CKPT] ...``

Credentials come from the environment / secret files only:
  m365:   OU_M365_TENANT_ID, OU_M365_CLIENT_ID, OU_M365_CLIENT_SECRET | OU_M365_CLIENT_SECRET_FILE
  google: OU_GOOGLE_SA_KEY_FILE (service-account JSON, mode 0600), OU_GOOGLE_ADMIN_SUBJECT (a super-admin to impersonate)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from . import assess, dns_check, report
from .auth import GoogleAuth, GraphAuth
from .checkpoint import Checkpoint
from .estimate import Assumptions
from .http import HttpClient
from .secrets import SecretError
from .sources.google import GoogleCollector
from .sources.m365 import M365Collector


def run(provider, out_dir, *, environ=None, checkpoint=None, resolver=None, bandwidth_mbps=100.0, deep=False,
        deep_max_users=None, http=None, collector_kwargs=None, auth_kwargs=None, assumptions=None):
    environ = os.environ if environ is None else environ
    http = http or HttpClient()
    if provider == "m365":
        auth = GraphAuth.from_env(http, environ, **(auth_kwargs or {}))
        ck = Checkpoint(checkpoint, "m365", environ["OU_M365_TENANT_ID"])
        kw = dict(collector_kwargs or {})
        kw.setdefault("deep_counts", deep)
        if deep_max_users:
            kw["deep_max_users"] = deep_max_users
        inv = M365Collector(http, auth, ck, **kw).collect()
    elif provider == "google":
        auth = GoogleAuth.from_env(http, environ, **(auth_kwargs or {}))
        ck = Checkpoint(checkpoint, "google", auth.sa_email + "|" + auth.admin_subject.split("@")[-1])
        kw = dict(collector_kwargs or {})
        kw.setdefault("deep", deep)
        if deep_max_users:
            kw["deep_max_users"] = deep_max_users
        inv = GoogleCollector(http, auth, ck, **kw).collect()
    else:
        raise SystemExit(f"unknown provider {provider}")
    a = assumptions or Assumptions(bandwidth_mbps=bandwidth_mbps)
    rep = assess.build(inv, resolver=resolver, assumptions=a,
                       stats={"http_retries": http.retries, "throttle_events": http.throttle_events})
    return report.write(rep, out_dir)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ou_migration", description="Read-only pre-migration assessment")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("assess")
    a.add_argument("--provider", required=True, choices=["m365", "google"])
    a.add_argument("--out", required=True)
    a.add_argument("--checkpoint", help="checkpoint file; an existing file is resumed")
    a.add_argument("--bandwidth-mbps", type=float, default=100.0)
    a.add_argument("--deep", action="store_true", help="opt-in sampled per-user counts (needs extra permissions)")
    a.add_argument("--deep-max-users", type=int)
    a.add_argument("--dns-resolver", action="append", help="DNS server IP (repeatable); default: system resolvers")
    a.add_argument("--no-dns", action="store_true")
    from .engine import cli as engine_cli
    engine_cli.add_parsers(sub)
    ns = ap.parse_args(argv)
    if ns.cmd in ("mail-migrate", "mail-verify"):
        return engine_cli.run(ns)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    try:
        res = None if ns.no_dns else dns_check.UdpResolver(ns.dns_resolver)
        jp, hp = run(ns.provider, ns.out, checkpoint=ns.checkpoint, resolver=res, bandwidth_mbps=ns.bandwidth_mbps,
                     deep=ns.deep, deep_max_users=ns.deep_max_users)
    except SecretError as e:
        print(f"credential error: {e}", file=sys.stderr)
        return 2
    print(jp)
    print(hp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
