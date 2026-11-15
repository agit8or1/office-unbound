"""Credential expiry: status transitions, purge of retired credentials, and alerts through the existing notification pipeline
(alert_channels -> notifications -> monitor.dispatch_notifications). Alerts carry no secret; each (credential, kind) fires once."""
from sqlalchemy import text

from .. import audit
from ..runtime import Runtime
from . import service


def _alert(db, c, kind: str, detail: str) -> int:
    fresh = db.execute(text("INSERT INTO credential_alerts (credential_id, kind) VALUES (:c, :k) ON CONFLICT DO NOTHING RETURNING 1"),
                       {"c": str(c.id), "k": kind}).first()
    if not fresh:
        return 0
    chans = db.execute(text("SELECT id FROM alert_channels WHERE enabled")).all()
    for ch in chans:
        db.execute(text("INSERT INTO notifications (incident_id, channel_id, event, status, detail) VALUES (NULL, :ch, :e, 'pending', :d)"),
                   {"ch": str(ch.id), "e": f"credential.{kind}", "d": detail})
    audit.append(db, f"credential.{kind}", actor_name="monitor", resource="credential", resource_id=str(c.id),
                 details={"provider": c.provider, "customer_id": str(c.customer_id), "label": c.label,
                          "expires_at": c.expires_at.isoformat() if c.expires_at else None, "notified_channels": len(chans)})
    return len(chans)


def tick(rt: Runtime) -> dict:
    out = {"expiring": 0, "expired": 0, "purged": 0}
    with rt.session() as db:
        for c in db.execute(text("SELECT * FROM credentials WHERE status IN ('active','expiring') AND expires_at IS NOT NULL "
                                 "AND expires_at <= now() FOR UPDATE")).all():
            db.execute(text("UPDATE credentials SET status = 'expired' WHERE id = :i"), {"i": str(c.id)})
            service._event(db, c.id, "expired", "system")
            _alert(db, c, "expired", f"Credential '{c.label}' ({c.provider}) expired at {c.expires_at.isoformat()}. "
                                      f"Provider access is lost until the customer issues a replacement.")
            out["expired"] += 1
        for c in db.execute(text("SELECT * FROM credentials WHERE status = 'active' AND expires_at IS NOT NULL "
                                 "AND expires_at <= now() + make_interval(days => :d) FOR UPDATE"), {"d": service.EXPIRY_WARN_DAYS}).all():
            db.execute(text("UPDATE credentials SET status = 'expiring' WHERE id = :i"), {"i": str(c.id)})
            service._event(db, c.id, "expiring", "system")
            _alert(db, c, "expiring", f"Credential '{c.label}' ({c.provider}) expires at {c.expires_at.isoformat()}. Rotate it before then.")
            out["expiring"] += 1
        out["purged"] = service.purge_retired(db)
        db.commit()
    return out
