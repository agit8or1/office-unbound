"""python -m ics.cli {create-admin,issue-enrollment,unlock,verify-chain}

Run on the host as the service user (`sudo -u ics .venv/bin/python -m ics.cli ...`). This is the break-glass path:
it talks to the database directly, is never rate limited, and never prints a password. Tokens are printed once here
and are never returned by the HTTP API.
"""
import argparse
import json
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
    du = sub.add_parser("disable-user", help="BREAK-GLASS (host root): disable an operator account and end its sessions; audited")
    du.add_argument("--username", required=True)
    du.add_argument("--reason", required=True, help="why the normal approval workflow could not be used (recorded in the audit log)")
    ns = sub.add_parser("backup-node-secret", help="BREAK-GLASS (host root): print the policy's restic repository password as JSON for `ou-backup --direct provision <tier>`; audited, never logged")
    ns.add_argument("--policy", required=True)
    ra = sub.add_parser("backup-recovery-ack", help="record that the offline recovery key was exported (fingerprint only, never the key); audited")
    ra.add_argument("--policy", required=True)
    ra.add_argument("--fingerprint", required=True, help="16 hex characters printed by `ou-backup --direct recovery-key`")
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
        if args.cmd == "disable-user":
            if len(args.reason.strip()) < 10:
                print("--reason must explain the break-glass use (>= 10 characters)", file=sys.stderr)
                return 2
            row = db.execute(text("SELECT id, role, disabled FROM users WHERE username = :u FOR UPDATE"), {"u": args.username}).first()
            if row is None:
                print("no such user", file=sys.stderr)
                return 1
            if row.disabled:
                print(args.username, "is already disabled")
                return 0
            if row.role == "admin":
                others = db.execute(text("SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled AND id <> :i"), {"i": row.id}).scalar()
                if not others:
                    print("refusing: this is the last active admin", file=sys.stderr)
                    return 1
            db.execute(text("UPDATE users SET disabled = true WHERE id = :i"), {"i": row.id})
            n = db.execute(text("DELETE FROM sessions WHERE user_id = :i"), {"i": row.id}).rowcount
            audit.append(db, "user.disabled.break_glass", actor_name="cli", resource="user", resource_id=str(row.id),
                         details={"username": args.username, "role": row.role, "sessions_revoked": n, "reason": args.reason.strip()[:500]})
            db.commit()
            print(f"disabled {args.username} (role {row.role}); revoked {n} session(s); recorded in audit log")
            return 0
        if args.cmd in ("backup-node-secret", "backup-recovery-ack"):
            from .backups import ops as backup_ops
            try:
                if args.cmd == "backup-node-secret":
                    print(json.dumps(backup_ops.node_secret(rt, db, args.policy)))
                else:
                    backup_ops.recovery_ack(db, args.policy, args.fingerprint)
                    print("recorded; the key itself is not stored anywhere in ICS")
            except (KeyError, backup_ops.BackupError) as e:
                print(e.args[0] if e.args else e, file=sys.stderr)
                return 1
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
