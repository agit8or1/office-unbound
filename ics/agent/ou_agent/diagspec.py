"""`guest.journal`: READ-ONLY diagnostics (agent >= 0.8.1). Pure functions, stdlib only: the closed parameter schema and the redaction.

Used twice: by the agent before spooling and again by the root helper (diaghelper.py, template unit ou-rb-diag@), which never trusts the spool.
Nothing here names a path, a unit or a pattern that the request supplies. The request names a KEY of a fixed table (UNITS, FILES, GREPS); the
helper maps that key to a fixed journal match or a fixed absolute path. No free regex, no glob, no path component, no option reaches a program.

Every line that leaves the VM is redacted first (redact_line): bearer tokens, JWTs, Authorization/Cookie headers, key=value secrets (password=,
secret=, token=, ...), JSON secret fields and long token-shaped strings become ***; non-printable characters become ?; the total is capped."""
import re

from .guestspec import _exact, _int
from .proto import Reject

DIAG_RUNBOOK = "guest.journal"
FAMILY = "diag"
SERVICE_USER = "ou-svc"

# key -> ("system", unit) | ("user", unit of the rootless service user ou-svc). Keep the keys short: they are what the console offers.
UNITS = {
    # web edge and PHP
    "nginx": ("system", "nginx.service"),
    "php8.3-fpm": ("system", "php8.3-fpm.service"),
    # groupware (gromox)
    "gromox-http": ("system", "gromox-http.service"),
    "gromox-zcore": ("system", "gromox-zcore.service"),
    "gromox-midb": ("system", "gromox-midb.service"),
    "gromox-imap": ("system", "gromox-imap.service"),
    "gromox-pop3": ("system", "gromox-pop3.service"),
    "gromox-delivery": ("system", "gromox-delivery.service"),
    "gromox-delivery-queue": ("system", "gromox-delivery-queue.service"),
    "gromox-event": ("system", "gromox-event.service"),
    "gromox-timer": ("system", "gromox-timer.service"),
    "postfix": ("system", "postfix@-.service"),        # Ubuntu runs the instance unit; postfix.service is an empty wrapper
    "saslauthd": ("system", "saslauthd.service"),
    "redis-server": ("system", "redis-server.service"),
    "mariadb": ("system", "mariadb.service"),
    # identity
    "slapd": ("system", "slapd.service"),
    "postgresql": ("system", "postgresql@16-main.service"),
    # portal, certificates, the agent itself, first boot
    "ou-portal": ("system", "ou-portal.service"),
    "certbot": ("system", "certbot.service"),
    "certbot-timer": ("system", "certbot.timer"),
    "ou-agent": ("system", "ou-agent.service"),
    "ou-bootstrap": ("system", "ou-bootstrap.service"),
    # containers of the service user (podman.deploy_unit: ou-<component>-<name>)
    "keycloak": ("user", "ou-identity-keycloak.service"),
    "opencloud": ("user", "ou-files-opencloud.service"),
    "opencloud-collaboration": ("user", "ou-files-opencloud-collaboration.service"),
    "collabora": ("user", "ou-office-collabora.service"),
}

# key -> absolute path. Only these files, only the last lines, opened without following a symlink, regular files only.
FILES = {
    "nginx-error": "/var/log/nginx/error.log",
    "nginx-access": "/var/log/nginx/access.log",
    "php8.3-fpm": "/var/log/php8.3-fpm.log",                     # the pools set catch_workers_output: grommunio-web's PHP errors land here
    "gromox-php-fpm": "/var/log/gromox/php-fpm.log",             # upstream gromox pool (php_admin_value[error_log])
    "grommunio-sync": "/var/log/grommunio-sync/grommunio-sync.log",
    "grommunio-sync-error": "/var/log/grommunio-sync/grommunio-sync-error.log",
    "grommunio-dav": "/var/log/grommunio-dav/dav.log",
    "letsencrypt": "/var/log/letsencrypt/letsencrypt.log",
}

# key -> fixed, case-insensitive pattern applied by the helper (never a pattern from the request)
GREPS = {
    "error": r"error|fatal|crit|emerg|alert|exception|panic|segfault",
    "warning": r"warn",
    "php": r"PHP (Fatal|Parse|Warning|Notice|Deprecated)|Uncaught|Stack trace",
    "http-5xx": r"\" 5[0-9][0-9] | 5[0-9][0-9] [0-9]+ \"|HTTP/[0-9.]+\" 5[0-9][0-9]|upstream|status[= ]5[0-9][0-9]",
    "denied": r"denied|forbidden|permission|unauthori[sz]ed|refused",
    "timeout": r"timeout|timed out",
    "start-stop": r"start|stop|exit|killed|failed|restart",
}

MAX_LINES = 300
MAX_SINCE_MINUTES = 1440
MAX_LINE_CHARS = 2000
MAX_TOTAL_BYTES = 32 * 1024     # all lines together, after redaction: the signed agent response stays below the ICS cap (64 KiB) after JSON escaping
SCAN_LINES = 5000               # with `grep`: how far back the helper looks to find `lines` matching lines


def check(p, cfg=None):
    """{unit|file, lines, since_minutes?, grep?} -> normalised params, or Reject. Exactly one of unit / file."""
    _exact(p, ("unit", "file", "lines", "since_minutes", "grep"), ("lines",))
    if ("unit" in p) == ("file" in p):
        raise Reject("bad_params", "give exactly one of unit or file")
    out = {"lines": _int(p["lines"], 1, MAX_LINES, "lines (1..%d)" % MAX_LINES)}
    if "unit" in p:
        if not isinstance(p["unit"], str) or p["unit"] not in UNITS:
            raise Reject("not_allowed", "unit is not on the diagnostics allowlist")
        out["unit"] = p["unit"]
    else:
        if not isinstance(p["file"], str) or p["file"] not in FILES:
            raise Reject("not_allowed", "file is not on the diagnostics allowlist")
        out["file"] = p["file"]
    if p.get("since_minutes") is not None:
        if "file" in out:
            raise Reject("bad_params", "since_minutes applies to a unit's journal only")
        out["since_minutes"] = _int(p["since_minutes"], 1, MAX_SINCE_MINUTES, "since_minutes (1..%d)" % MAX_SINCE_MINUTES)
    if p.get("grep") is not None:
        if not isinstance(p["grep"], str) or p["grep"] not in GREPS:
            raise Reject("bad_params", "grep must be one of " + ", ".join(GREPS))
        out["grep"] = p["grep"]
    return out


def validate_runbook_config(name, c):
    if c != {"enabled": True}:
        raise ValueError(f"{name} takes exactly {{\"enabled\": true}}")


# ---------------------------------------------------------------- redaction
# a key that ENDS in one of these is a secret (client_secret, access_token, PHPSESSID, db_password, api_key); signal=, ActiveState= are not
_SECRET_WORDS = r"(?:password|passwd|passphrase|pwd|pass|secret|token|apikey|[_-]key|auth|session|sessid|sessionid|sid|cookie|credentials?|" \
                r"ticket|signature|nonce)"
_RULES = [
    # Authorization / Cookie / Set-Cookie / X-*-Token header values (to the end of the line or the closing quote)
    (re.compile(r"(?i)\b((?:proxy-)?authorization|cookie|set-cookie|x-[a-z-]*(?:token|key|secret|auth)[a-z-]*)(\s*[:=]\s*)[^\"\r\n]*"), r"\1\2***"),
    # Bearer / Basic / Negotiate credentials anywhere
    (re.compile(r"(?i)\b(bearer|basic|negotiate|digest)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 ***"),
    # JWT / JWS / JWE (base64url JSON header "eyJ")
    (re.compile(r"eyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*){1,4}"), "***"),
    # key=value / key: value secrets (query strings, form bodies, log key-values); the key is kept, the value goes
    (re.compile(r"(?i)\b([A-Za-z0-9_.-]*" + _SECRET_WORDS + r")(=)[^&\s\"',;]+"), r"\1\2***"),
    # "password: hunter2" style (colon-separated, unquoted)
    (re.compile(r"(?i)\b((?:password|passwd|passphrase|secret|client_secret|token|access_token|refresh_token|api_key)\s*:\s*)[^\s\"',;]+"), r"\1***"),
    # OAuth authorization codes in redirects (`code` alone is too common in log lines to treat everywhere: "code=exited")
    (re.compile(r"([?&](?:code|session_state)=)[^&\s\"',;]+"), r"\1***"),
    # JSON / PHP array fields: "password":"...", 'secret' => '...'
    (re.compile(r"(?i)([\"'][A-Za-z0-9_.-]*" + _SECRET_WORDS + r"[\"']\]?\s*(?::|=>|=)\s*)(\"[^\"]*\"|'[^']*')"), r'\1"***"'),
    # PEM blocks that ended up on one line
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)"), "[private key]"),
]
_TOKENISH = re.compile(r"[A-Za-z0-9_+=-]{20,}")


def _tokenish(m):
    """Long runs that look generated (mixed letters and at least 3 digits, or long hex) are replaced; plain words, paths and package names stay."""
    s = m.group(0)
    digits = sum(ch.isdigit() for ch in s)
    if digits >= 3 and any(ch.isalpha() for ch in s) and (any(ch.isupper() for ch in s) or len(s) >= 32 or re.fullmatch(r"[0-9a-f-]{20,}", s)):
        return "***"
    return s


def redact_line(line, scrub=None):
    """One log line, safe to leave the VM: printable ASCII, secrets replaced, capped. `scrub` is an extra callable (the cfg helper's
    Ctx.scrub style: known secret values -> ***) applied first when the caller has one."""
    t = str(line or "")
    if scrub is not None:
        t = scrub(t)
    t = "".join(ch if 32 <= ord(ch) < 127 or ch == "\t" else "?" for ch in t)
    for rx, rep in _RULES:
        t = rx.sub(rep, t)
    t = _TOKENISH.sub(_tokenish, t)
    return t[:MAX_LINE_CHARS]


def cap(lines):
    """Keep the LAST lines whose total size fits MAX_TOTAL_BYTES. Returns (lines, truncated)."""
    out, size = [], 0
    for ln in reversed(lines):
        size += len(ln) + 1
        if size > MAX_TOTAL_BYTES:
            return list(reversed(out)), True
        out.append(ln)
    return list(reversed(out)), False
