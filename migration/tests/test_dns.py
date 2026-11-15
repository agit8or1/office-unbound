import socket
import struct
import threading

import pytest

from ou_migration import dns_check as d


def _n(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def make_answer(qid, qname, rtype, rdatas, rcode=0, tc=False):
    flags = 0x8180 | rcode | (0x200 if tc else 0)
    pkt = struct.pack(">HHHHHH", qid, flags, 1, len(rdatas), 0, 0) + _n(qname) + struct.pack(">HH", d.TYPES[rtype], 1)
    for rd in rdatas:
        pkt += b"\xc0\x0c" + struct.pack(">HHIH", d.TYPES[rtype], 1, 60, len(rd)) + rd   # compressed owner name
    return pkt


def test_parse_mx_txt_cname_with_compression():
    mx = struct.pack(">H", 0) + _n("contoso-example.mail.protection.outlook.com")
    rc, tc, recs = d.parse_response(make_answer(7, "contoso.example", "MX", [mx]), 7)
    assert recs == [("MX", "0 contoso-example.mail.protection.outlook.com")] and rc == 0 and not tc
    txt = b"".join(bytes([len(p)]) + p for p in (b"v=spf1 include:spf.protection", b".outlook.com -all"))
    assert d.parse_response(make_answer(8, "x.example", "TXT", [txt]), 8)[2] == [("TXT", "v=spf1 include:spf.protection.outlook.com -all")]


def test_id_mismatch_and_loop_rejected():
    with pytest.raises(d.DnsError):
        d.parse_response(make_answer(1, "a.example", "MX", []), 2)
    evil = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c" + b"\0\0\0\0"
    with pytest.raises(d.DnsError):
        d.parse_response(evil, 1)


class FakeDnsServer:
    def __init__(self, zone):
        self.zone, self.sock = zone, socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            qid = struct.unpack(">H", data[:2])[0]
            off, labels = 12, []
            while data[off]:
                labels.append(data[off + 1:off + 1 + data[off]].decode())
                off += 1 + data[off]
            qname, qt = ".".join(labels), struct.unpack(">H", data[off + 1:off + 3])[0]
            rtype = {v: k for k, v in d.TYPES.items()}[qt]
            rd = self.zone.get((qname, rtype))
            self.sock.sendto(make_answer(qid, qname, rtype, rd or [], rcode=0 if rd else 3), addr)


def test_udp_resolver_against_loopback_fake_dns_and_check_domain():
    mx = struct.pack(">H", 0) + _n("contoso-example.mail.protection.outlook.com")
    t = lambda s: bytes([len(s)]) + s.encode()
    zone = {("contoso.example", "MX"): [mx], ("contoso.example", "TXT"): [t("v=spf1 include:spf.protection.outlook.com -all")],
            ("_dmarc.contoso.example", "TXT"): [t("v=DMARC1; p=quarantine; rua=mailto:d@contoso.example")],
            ("selector1._domainkey.contoso.example", "CNAME"): [_n("selector1-contoso-example._domainkey.contoso.onmicrosoft.com")],
            ("selector2._domainkey.contoso.example", "CNAME"): [_n("selector2-contoso-example._domainkey.contoso.onmicrosoft.com")]}
    srv = FakeDnsServer(zone)
    r = d.UdpResolver(["127.0.0.1"], port=srv.port, timeout=2)
    res = d.check_domain(r, "contoso.example", "m365")
    assert res["mx_state"] == "microsoft" and res["spf_state"] == "hard-fail" and res["dmarc_state"] == "p=quarantine" and res["dkim_state"] == "enabled"
    bare = d.check_domain(r, "nothing.example", "google")
    assert bare["mx_state"] == "none" and bare["spf_state"] == "missing" and bare["dmarc_state"] == "missing"


def test_resolver_failure_becomes_unknown_not_exception():
    class Broken:
        def query(self, n, t):
            raise d.DnsError("boom")
    res = d.check_domain(Broken(), "x.example", "google")
    assert res["mx_state"] == "unknown" and res["spf_state"] == "unknown" and res["errors"]


def test_mx_classification():
    class R:
        def __init__(self, mx):
            self.mx = mx

        def query(self, n, t):
            return self.mx if t == "MX" and not n.startswith("_") else []
    assert d.check_domain(R(["1 aspmx.l.google.com"]), "a.example", "google")["mx_state"] == "google"
    assert d.check_domain(R(["10 mx.mimecast.example"]), "a.example", "m365")["mx_state"] == "third-party-filter-or-other"
