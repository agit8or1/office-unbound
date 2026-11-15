"""python -m ics.cli {create-admin,verify-chain,run-worker-once}"""
import argparse
import getpass
import sys

from . import audit, auth
from .runtime import Runtime


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ics.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ca = sub.add_parser("create-admin", help="bootstrap an account (default role admin); prints the TOTP URI once")
    ca.add_argument("--username", required=True)
    ca.add_argument("--role", default="admin", choices=auth.ROLES)
    ca.add_argument("--password-env", help="read password from this env var instead of prompting")
    sub.add_parser("verify-chain", help="verify the audit hash chain; exit 1 if broken")
    args = ap.parse_args(argv)
    rt = Runtime()
    if args.cmd == "create-admin":
        import os
        pw = os.environ[args.password_env] if args.password_env else getpass.getpass("Password (min 12 chars): ")
        with rt.session() as db:
            uri = auth.create_user(db, rt, args.username, pw, args.role)
        print("Created", args.username, "with role", args.role)
        print("TOTP provisioning URI (shown once, add it to your authenticator now):")
        print(uri)
        return 0
    with rt.session() as db:
        res = audit.verify_chain(db)
    print(res)
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
