"""python -m ics.cli {create-admin,issue-enrollment,unlock,verify-chain,promote,controller-status,...}

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
    rw = sub.add_parser("rewrap-master", help="re-wrap every vault-encrypted secret under a NEW master key file (see docs/status/credential-vault.md)")
    rw.add_argument("--new-key-file", required=True)
    sub.add_parser("migrate-credentials", help="move legacy per-endpoint secrets into the credential vault (idempotent)")
    sub.add_parser("verify-chain", help="verify the audit hash chain; exit 1 if broken")
    du = sub.add_parser("disable-user", help="BREAK-GLASS (host root): disable an operator account and end its sessions; audited")
    du.add_argument("--username", required=True)
    du.add_argument("--reason", required=True, help="why the normal approval workflow could not be used (recorded in the audit log)")
    ns = sub.add_parser("backup-node-secret", help="BREAK-GLASS (host root): print the policy's restic repository password as JSON for `ou-backup --direct provision <tier>`; audited, never logged")
    ns.add_argument("--policy", required=True)
    up = sub.add_parser("upgrade-preflight", help="read-only checks before upgrading the ou-ics package: disk space, backup freshness, running jobs, standby state, schema")
    up.add_argument("--backup-dir", default="/var/backups/office-unbound/ics")
    up.add_argument("--max-backup-age-hours", type=float, default=24)
    up.add_argument("--json", action="store_true")
    ra = sub.add_parser("backup-recovery-ack", help="record that the offline recovery key was exported (fingerprint only, never the key); audited")
    ra.add_argument("--policy", required=True)
    ra.add_argument("--fingerprint", required=True, help="16 hex characters printed by `ou-backup --direct recovery-key`")
    pr = sub.add_parser("promote", help="ROOT, on the STANDBY: fenced promotion to primary (docs/runbooks/ics-recovery.md, ADR-0012)")
    pr.add_argument("--confirm", help='non-interactive confirmation: exactly "promote <hostname>"')
    pr.add_argument("--fence-old-dsn-file", help="file with a postgresql+psycopg:// URL of the (still reachable) old primary: mark it fenced first")
    pr.add_argument("--no-restart", action="store_true")
    pr.add_argument("--no-announce", action="store_true", help="do not send the new epoch to agents now (they learn it on the first monitor pass)")
    sn = sub.add_parser("standby-note", help="record a standby lifecycle event in the audit log (called by the standby scripts on the primary)")
    sn.add_argument("event", choices=["keys-exported", "standby-prepared"])
    sn.add_argument("--standby-ip", required=True)
    sub.add_parser("controller-status", help="print role, controller epoch and replication position")
    args = ap.parse_args(argv)
    if args.cmd == "promote":
        from . import promote
        return promote.promote(args)
    rt = Runtime()
    with rt.session() as db:
        if args.cmd == "upgrade-preflight":
            from . import upgrade
            facts = upgrade.gather(db, rt.settings, backup_dir=args.backup_dir)
            checks = upgrade.evaluate(facts, int(args.max_backup_age_hours * 3600))
            if args.json:
                print(json.dumps({"ready": upgrade.verdict(checks) == 0, "checks": [c.__dict__ for c in checks]}, indent=1))
            else:
                print(upgrade.render(checks))
            return upgrade.verdict(checks)
        if args.cmd == "rewrap-master":
            from .credentials import rewrap
            from .vault import Vault
            new = Vault.from_file(args.new_key_file)
            if new.key == rt.vault.key:
                print("the new key file is identical to the current key", file=sys.stderr)
                return 1
            try:
                counts = rewrap.rewrap_all(db, rt.vault, new)
                db.commit()
            except Exception as e:  # noqa: BLE001  (nothing is committed on failure)
                db.rollback()
                print(f"re-wrap failed, nothing was changed: {type(e).__name__}", file=sys.stderr)
                return 1
            print("re-wrapped:", counts)
            print("Now replace the key file ICS_VAULT_KEY_FILE points to with the new key and restart ics. Keep the old key until verified.")
            return 0
        if args.cmd == "migrate-credentials":
            from .credentials import service
            print("credentials created:", service.adopt_all(rt))
            return 0
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
        if args.cmd == "controller-status":
            from . import epoch as epochmod
            print({"configured_role": rt.settings.role, **epochmod.get_state(db),
                   "in_recovery": db.execute(text("SELECT pg_is_in_recovery()")).scalar()})
            return 0
        if args.cmd == "standby-note":
            audit.append(db, "standby." + args.event.replace("-", "_"), actor_name="cli", resource="controller",
                         details={"standby_ip": args.standby_ip, "operator": __import__("os").environ.get("SUDO_USER", "root")})
            db.commit()
            print("recorded", args.event)
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
