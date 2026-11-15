"""Public-DNS posture of the tenant's domains (MX / SPF / DKIM / DMARC). Stdlib-only DNS client
(RFC 1035 wire format over UDP, TCP fallback on truncation). Everything returned is ``verified``
as of the moment of the query (DNS is the source of truth for mail routing).
"""
from __future__ import annotations

import random
import socket
import struct

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}


class DnsError(Exception):
    pass


def system_resolvers() -> list[str]:
    out = []
    try:
        for line in open("/etc/resolv.conf"):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
                out.append(parts[1])
    except OSError:
        pass
    return out


def build_query(name: str, rtype: str, qid: int) -> bytes:
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".")) + b"\0"
    return hdr + q + struct.pack(">HH", TYPES[rtype], 1)


def _name(buf: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(buf):
            raise DnsError("truncated name")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            hops += 1
            if hops > 20:
                raise DnsError("compression loop")
            continue
        labels.append(buf[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def parse_response(buf: bytes, qid: int) -> tuple[int, bool, list[tuple[str, str]]]:
    """-> (rcode, truncated, [(rtype, text)])"""
    if len(buf) < 12:
        raise DnsError("short response")
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise DnsError("id mismatch")
    off = 12
    for _ in range(qd):
        _, off = _name(buf, off)
        off += 4
    out = []
    inv = {v: k for k, v in TYPES.items()}
    for _ in range(an):
        _, off = _name(buf, off)
        t, _c, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rd = off
        if t == TYPES["MX"]:
            pref = struct.unpack(">H", buf[rd:rd + 2])[0]
            host, _ = _name(buf, rd + 2)
            out.append(("MX", f"{pref} {host}"))
        elif t == TYPES["CNAME"]:
            out.append(("CNAME", _name(buf, rd)[0]))
        elif t == TYPES["TXT"]:
            parts, p = [], rd
            while p < rd + rdlen:
                ln = buf[p]
                parts.append(buf[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                p += 1 + ln
            out.append(("TXT", "".join(parts)))
        elif t in inv:
            out.append((inv[t], ""))
        off = rd + rdlen
    return flags & 0xF, bool(flags & 0x200), out


class UdpResolver:
    def __init__(self, servers: list[str] | None = None, port=53, timeout=3.0):
        self.servers = servers or system_resolvers()
        self.port, self.timeout = port, timeout
        if not self.servers:
            raise DnsError("no DNS resolver configured")

    def query(self, name: str, rtype: str) -> list[str]:
        last = None
        for srv in self.servers:
            qid = random.randrange(65536)
            pkt = build_query(name, rtype, qid)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(pkt, (srv, self.port))
                    data, _ = s.recvfrom(4096)
                rcode, tc, recs = parse_response(data, qid)
                if tc:
                    with socket.create_connection((srv, self.port), timeout=self.timeout) as s:
                        s.sendall(struct.pack(">H", len(pkt)) + pkt)
                        ln = struct.unpack(">H", _recv(s, 2))[0]
                        rcode, _, recs = parse_response(_recv(s, ln), qid)
                if rcode == 3:
                    return []  # NXDOMAIN
                if rcode != 0:
                    raise DnsError(f"rcode {rcode}")
                return [t for ty, t in recs if ty == rtype]
            except (OSError, DnsError) as e:
                last = e
        raise DnsError(f"DNS query failed for {name} {rtype}: {last}")


def _recv(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise DnsError("tcp closed")
        b += c
    return b


def check_domain(resolver, domain: str, provider: str) -> dict:
    """Return the DNS posture. ``resolver.query(name, rtype) -> list[str]``. Errors become 'unknown' entries."""
    res: dict = {"domain": domain}

    def q(name, rtype):
        try:
            return resolver.query(name, rtype)
        except DnsError as e:
            res.setdefault("errors", []).append(str(e)[:120])
            return None

    mx = q(domain, "MX")
    res["mx"] = mx
    if mx is None:
        res["mx_state"] = "unknown"
    elif not mx:
        res["mx_state"] = "none"
    else:
        hosts = " ".join(m.split()[-1].lower() for m in mx)
        res["mx_state"] = ("microsoft" if "mail.protection.outlook.com" in hosts else
                           "google" if ("aspmx" in hosts or "googlemail.com" in hosts or "google.com" in hosts) else
                           "third-party-filter-or-other")
    txt = q(domain, "TXT")
    spf = [t for t in (txt or []) if t.lower().startswith("v=spf1")]
    res["spf"] = spf
    res["spf_state"] = ("unknown" if txt is None else "missing" if not spf else
                        "multiple-records(invalid)" if len(spf) > 1 else
                        "hard-fail" if spf[0].rstrip().endswith("-all") else
                        "soft-fail" if spf[0].rstrip().endswith("~all") else "permissive/other")
    dm = q("_dmarc." + domain, "TXT")
    pol = next((t for t in (dm or []) if t.lower().startswith("v=dmarc1")), None)
    res["dmarc_state"] = "unknown" if dm is None else "missing" if pol is None else \
        ("p=" + next((x.split("=", 1)[1].strip() for x in pol.split(";") if x.strip().lower().startswith("p=")), "?"))
    if provider == "m365":
        sel = [q(f"selector{i}._domainkey.{domain}", "CNAME") for i in (1, 2)]
        res["dkim_state"] = "unknown" if any(s is None for s in sel) else "enabled" if all(sel) else "not-configured"
    else:
        g = q(f"google._domainkey.{domain}", "TXT")
        res["dkim_state"] = "unknown" if g is None else "enabled" if g else "not-configured-or-custom-selector"
    return res
