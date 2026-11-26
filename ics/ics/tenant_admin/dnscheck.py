"""Read-only DNS health for a customer's mail domain. Tiny stdlib resolver (TXT/MX/CNAME/A/SRV over UDP with TCP fallback) so the ICS needs no new
dependency. Only names derived from the customer's configured mail domain are ever queried (never a caller-supplied name)."""
import os
import random
import re
import socket
import struct

TYPES = {"A": 1, "CNAME": 5, "MX": 15, "TXT": 16, "SRV": 33}


class DnsError(Exception):
    pass


def _servers() -> list[str]:
    try:
        return [m.group(1) for m in re.finditer(r"^nameserver\s+(\S+)", open("/etc/resolv.conf").read(), re.M) if ":" not in m.group(1)] or ["127.0.0.53"]
    except OSError:
        return ["127.0.0.53"]


def _name(buf: bytes, off: int) -> tuple[str, int]:
    parts, jumped, end = [], False, off
    for _ in range(128):
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        parts.append(buf[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    else:
        raise DnsError("bad name")
    return ".".join(parts), (end if jumped else off)


def _parse(buf: bytes, qtype: int) -> tuple[int, list[str], bool]:
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    off = 12
    for _ in range(qd):
        _, off = _name(buf, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _name(buf, off)
        t, _, _, ln = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rd = buf[off:off + ln]
        if t == qtype:
            if t == 16:
                s, i = b"", 0
                while i < len(rd):
                    s += rd[i + 1:i + 1 + rd[i]]
                    i += 1 + rd[i]
                out.append(s.decode("utf-8", "replace"))
            elif t == 15:
                out.append(_name(buf, off + 2)[0].lower().rstrip("."))
            elif t == 5:
                out.append(_name(buf, off)[0].lower().rstrip("."))
            elif t == 1:
                out.append(socket.inet_ntoa(rd))
            elif t == 33:
                out.append(_name(buf, off + 6)[0].lower().rstrip(".") + ":" + str(struct.unpack(">H", rd[4:6])[0]))
        elif t == 5 and qtype != 5:
            pass  # a CNAME in the chain; the resolver already followed it
        off += ln
    return flags & 0xF, out, bool(flags & 0x200)


def query(name: str, rtype: str, servers: list[str] | None = None, timeout: float = 3.0) -> list[str]:
    """-> list of record texts (empty for NXDOMAIN/no data). Raises DnsError if no resolver answered."""
    if not re.fullmatch(r"[A-Za-z0-9_]([A-Za-z0-9_.-]{0,250}[A-Za-z0-9])?", name):
        raise DnsError("invalid name")
    qt = TYPES[rtype]
    qid = random.SystemRandom().randrange(65536)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + struct.pack(">HH", qt, 1)
    last = None
    for srv in servers or _servers():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(q, (srv, 53))
            buf, _ = s.recvfrom(4096)
            s.close()
            if struct.unpack(">H", buf[:2])[0] != qid:
                continue
            rc, out, tc = _parse(buf, qt)
            if tc:
                t = socket.create_connection((srv, 53), timeout=timeout)
                t.sendall(struct.pack(">H", len(q)) + q)
                n = struct.unpack(">H", t.recv(2))[0]
                data = b""
                while len(data) < n:
                    c = t.recv(n - len(data))
                    if not c:
                        break
                    data += c
                t.close()
                rc, out, _ = _parse(data, qt)
            if rc in (0, 3):
                return out
            last = f"rcode {rc}"
        except (OSError, struct.error, IndexError) as e:
            last = type(e).__name__
    raise DnsError(f"no resolver answered ({last})")


def dkim_p(v: str) -> str:
    """The p= (public key) tag of a DKIM record, whitespace removed (a long record is split into several strings by DNS tools)."""
    m = re.search(r"(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=\s]*)", v)
    return re.sub(r"\s+", "", m.group(1)) if m else ""


def check_domain(domain: str, mail_host: str | None, dkim_selector: str, resolver=query, *, dkim_available: bool = True,
                 dkim_value: str | None = None) -> list[dict]:
    """Records the customer's DNS must carry. status: ok | missing | differs | unknown (resolver failed) | not_available.

    dkim_available=False: the mail server does not sign outgoing mail (no DKIM key exists), so DKIM is not queried and the row says so."""
    mail_host = (mail_host or "").lower().rstrip(".")
    spf_want = "v=spf1 mx -all"
    rows = []

    def row(key, title, name, rtype, want, how, test, optional=False):
        base = {"key": key, "title": title, "name": name, "type": rtype, "expected": want, "how": how, "optional": optional}
        try:
            found = resolver(name, rtype)
        except DnsError:
            rows.append({**base, "found": [], "status": "unknown"})
            return
        st = "missing" if not found else ("ok" if test(found) else "differs")
        rows.append({**base, "found": found, "status": st})

    row("mx", "Incoming mail (MX)", domain, "MX", f"10 {mail_host}" if mail_host else "your mail server", "Add an MX record so mail for your domain is delivered to your mail server.",
        lambda f: (not mail_host) or mail_host in f)
    row("spf", "Sender policy (SPF)", domain, "TXT", spf_want, "Add one TXT record on the domain. If you already have an SPF record, merge into it; a domain may have only one.",
        lambda f: any(x.lower().startswith("v=spf1") for x in f) and sum(x.lower().startswith("v=spf1") for x in f) == 1)
    if dkim_value:
        want = dkim_p(dkim_value)
        row("dkim", "Message signing (DKIM)", f"{dkim_selector}._domainkey.{domain}", "TXT", dkim_value,
            "Publish this TXT record exactly as shown: your mail server signs outgoing mail with the matching private key. Some DNS "
            "providers split a long value into several quoted strings; that is fine.",
            lambda f: any(dkim_p(x) == want for x in f))
    elif dkim_available:
        row("dkim", "Message signing (DKIM)", f"{dkim_selector}._domainkey.{domain}", "TXT", "v=DKIM1; k=rsa; p=<public key from your mail server>",
            "Publish the DKIM public key generated for your mail server as a TXT record at this name. Ask your service provider for the key value.",
            lambda f: any("v=dkim1" in x.lower() and "p=" in x.lower() for x in f))
    else:
        rows.append({"key": "dkim", "title": "Message signing (DKIM)", "name": f"{dkim_selector}._domainkey.{domain}", "type": "TXT", "expected": "-",
                     "how": "This mail server does not sign outgoing mail yet, so there is no DKIM record to publish now. "
                            "Signing is planned together with internet mail.",
                     "optional": True, "found": [], "status": "not_available"})
    row("dmarc", "Spoofing protection (DMARC)", f"_dmarc.{domain}", "TXT", f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}",
        "Add a TXT record. Start with p=none to observe, then move to quarantine or reject once reports look clean.",
        lambda f: any(x.lower().startswith("v=dmarc1") for x in f))
    row("autodiscover", "Automatic mail setup (autodiscover)", f"autodiscover.{domain}", "CNAME", mail_host or "your mail server",
        "Add a CNAME so Outlook and phones can find the right server by themselves.", lambda f: (not mail_host) or mail_host in f)
    for key, title, svc, port, what in SRV_RECORDS:
        row(key, title, f"{svc}.{domain}", "SRV", f"0 1 {port} {mail_host or 'your mail server'}",
            f"Optional. Lets {what} find the server from just an e-mail address. Priority 0, weight 1, port {port}.",
            lambda f, port=port: any(x.rsplit(":", 1)[-1] == str(port) and ((not mail_host) or x.rsplit(":", 1)[0] == mail_host) for x in f),
            optional=True)
    return rows


# client-setup SRV records (RFC 6186 mail, RFC 6764 calendar/contacts, Microsoft's autodiscover SRV); recommended, never required
SRV_RECORDS = (("srv_autodiscover", "Outlook setup (autodiscover SRV)", "_autodiscover._tcp", 443, "Outlook"),
               ("srv_imaps", "Incoming mail setup (IMAP SRV)", "_imaps._tcp", 993, "mail apps"),
               ("srv_submission", "Outgoing mail setup (SMTP SRV)", "_submission._tcp", 587, "mail apps"),
               ("srv_caldavs", "Calendar setup (CalDAV SRV)", "_caldavs._tcp", 443, "calendar apps"),
               ("srv_carddavs", "Contacts setup (CardDAV SRV)", "_carddavs._tcp", 443, "contacts apps"))
