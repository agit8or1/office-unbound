"""Operator <-> customer scoping. ICS operators are independent of any tenant identity: scope lives only in ICS tables.

`user.customer_ids` is None for the MSP "all customers" scope, otherwise a frozenset of customer id strings (possibly empty =
sees nothing). Out-of-scope objects answer 404 (not 403) so their existence is not disclosed."""
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

DEFAULT_CUSTOMER = "00000000-0000-0000-0000-00000000a001"


def load(db: Session, user_id, all_customers: bool):
    if all_customers:
        return None
    rows = db.execute(text("SELECT customer_id FROM operator_customers WHERE user_id = :u"), {"u": str(user_id)}).all()
    return frozenset(str(r.customer_id) for r in rows)


def attach(db: Session, user, row) -> None:
    """Called by auth.current_user: sets user.customer_ids and exposes it to query helpers via db.info."""
    user.customer_ids = load(db, row.id, getattr(row, "all_customers", True))
    db.info["customer_ids"] = user.customer_ids


def allowed(user, customer_id) -> bool:
    ids = getattr(user, "customer_ids", None)
    return ids is None or str(customer_id) in ids


def assert_customer(user, customer_id, what: str = "resource") -> None:
    if not allowed(user, customer_id):
        raise HTTPException(404, f"{what} not found")


def clause(db_or_user, column: str) -> str:
    """SQL fragment limiting `column` (a customer_id expression) to the caller's scope; '' + TRUE for all-customers.
    Ids are validated UUIDs, inlined as literals (no user text reaches the SQL)."""
    ids = db_or_user.info.get("customer_ids") if hasattr(db_or_user, "info") else getattr(db_or_user, "customer_ids", None)
    if ids is None:
        return "TRUE"
    lits = ",".join(f"'{UUID(i)}'" for i in sorted(ids))
    return f"{column} IN ({lits})" if lits else "FALSE"


def endpoint_clause(db_or_user, column: str = "endpoint_id") -> str:
    c = clause(db_or_user, "customer_id")
    return "TRUE" if c == "TRUE" else f"{column} IN (SELECT id FROM endpoints WHERE {c})"


def endpoint_customer(db: Session, endpoint_id) -> str | None:
    r = db.execute(text("SELECT customer_id FROM endpoints WHERE id = :i"), {"i": str(endpoint_id)}).first()
    return str(r.customer_id) if r else None


def assert_endpoint(db: Session, user, endpoint_id) -> None:
    cid = endpoint_customer(db, endpoint_id)
    if cid is None or not allowed(user, cid):
        raise HTTPException(404, "endpoint not found")


def customer_of_params(db: Session, params: dict) -> str | None:
    """The customer a plan's params touch (endpoint, credential, approval or explicit customer_id)."""
    if params.get("customer_id"):
        return str(params["customer_id"])
    if params.get("endpoint_id"):
        return endpoint_customer(db, params["endpoint_id"])
    if params.get("stack"):   # identity actions name the customer stack; its owning customer is in the stack config
        r = db.execute(text("SELECT config->>'customer_id' AS c FROM idm_stacks WHERE name = :n"), {"n": str(params["stack"])}).first()
        return r.c if r and r.c else None
    if params.get("credential_id"):
        r = db.execute(text("SELECT customer_id FROM credentials WHERE id = :i"), {"i": str(params["credential_id"])}).first()
        return str(r.customer_id) if r else None
    return None
