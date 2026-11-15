"""python -m ics.cli {create-admin,issue-enrollment,unlock,verify-chain}

Run on the host as the service user (`sudo -u ics .venv/bin/python -m ics.cli ...`). This is the break-glass path:
it talks to the database directly, is never rate limited, and never prints a password. Tokens are printed once here
and are never returned by the HTTP API.
"""
import argparse
import sys

from sqlalchemy import text

from . import audit, auth
from .runtime import Runtime


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ics.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ca = sub.add_parser("create-admin", help="bootstrap an account (default role admin) and print a one-time enrollment token")
    ca.add_argument("--username", required=True)
    ca.add_argument("--role", default="admin", choices=auth.ROLES)
    ie = sub.add_parser("issue-enrollment", help="(re)issue a one-time enrollment token for an existing/invited user; resets their password+TOTP")
    ie.add_argument("--username", required=True)
    ul = sub.add_parser("unlock", help="clear login throttling for a user")
    ul.add_argument("--username", required=True)
    sub.add_parser("verify-chain", help="verify the audit hash chain; exit 1 if broken")
    args = ap.parse_args(argv)
    rt = Runtime()
    with rt.session() as db:
        if args.cmd == "create-admin":
            token = auth.create_account_cli(db, rt, args.username, args.role)
            print("Created", args.username, "with role", args.role)
            _show(args.username, token)
            return 0
        if args.cmd == "issue-enrollment":
            try:
                token = auth.issue_enrollment_token(db, rt, args.username)
            except ValueError as e:
                print(e, file=sys.stderr)
                return 1
            _show(args.username, token)
            return 0
        if args.cmd == "unlock":
            n = db.execute(text("DELETE FROM login_attempts WHERE username = :u"), {"u": args.username}).rowcount
            audit.append(db, "auth.unlocked", actor_name="cli", resource="user", details={"username": args.username})
            db.commit()
            print("cleared", n, "login attempt rows")
            return 0
        res = audit.verify_chain(db)
    print(res)
    return 0 if res["ok"] else 1


def _show(username: str, token: str) -> None:
    print(f"One-time enrollment token for {username} (shown once; valid 24h; hand it over out of band):")
    print(token)
    print("The user then calls POST /api/v1/auth/enroll {username, token, password} and /auth/enroll/confirm {username, token, totp_code}.")


if __name__ == "__main__":
    sys.exit(main())
