"""Minimal SIP-over-TLS REGISTER probe with digest auth (stdlib only). Returns the final status code (200, 401, 403, 404...)."""
import hashlib
import re
import secrets
import socket
import ssl


def _recv(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf.decode(errors="replace")


def register(user, password, cafile, host="pbx.ou-lab.internal", ip="192.168.186.247", port=5061, expires=60, domain="pbx.ou-lab.internal"):
    ctx = ssl.create_default_context(cafile=cafile)
    raw = socket.create_connection((ip, port), timeout=8)
    s = ctx.wrap_socket(raw, server_hostname=host)
    lport = s.getsockname()[1]
    callid = secrets.token_hex(8)
    tag = secrets.token_hex(4)

    def msg(cseq, auth=""):
        return ("REGISTER sip:%s SIP/2.0\r\nVia: SIP/2.0/TLS 192.168.186.1:%d;branch=z9hG4bK%s;rport\r\nMax-Forwards: 70\r\n"
                "From: <sip:%s@%s>;tag=%s\r\nTo: <sip:%s@%s>\r\nCall-ID: %s\r\nCSeq: %d REGISTER\r\n"
                "Contact: <sip:%s@192.168.186.1:%d;transport=tls>\r\nExpires: %d\r\n%sContent-Length: 0\r\n\r\n"
                % (domain, lport, secrets.token_hex(4), user, domain, tag, user, domain, callid, cseq, user, lport, expires, auth))
    try:
        s.sendall(msg(1).encode())
        r = _recv(s)
        code = int(r.split()[1])
        if code != 401:
            return code
        ch = re.search(r"WWW-Authenticate:\s*Digest\s+(.*)", r, re.I).group(1)
        p = dict((k.lower(), v.strip('"')) for k, v in re.findall(r'(\w+)=("[^"]*"|[^,\s]+)', ch))
        uri = "sip:" + domain
        ha1 = hashlib.md5(("%s:%s:%s" % (user, p["realm"], password)).encode()).hexdigest()
        ha2 = hashlib.md5(("REGISTER:" + uri).encode()).hexdigest()
        if "auth" in p.get("qop", ""):
            cn, nc = secrets.token_hex(4), "00000001"
            resp = hashlib.md5(("%s:%s:%s:%s:auth:%s" % (ha1, p["nonce"], nc, cn, ha2)).encode()).hexdigest()
            extra = ',qop=auth,cnonce="%s",nc=%s' % (cn, nc)
        else:
            resp = hashlib.md5(("%s:%s:%s" % (ha1, p["nonce"], ha2)).encode()).hexdigest()
            extra = ""
        auth = 'Authorization: Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=MD5%s%s\r\n' % (
            user, p["realm"], p["nonce"], uri, resp, extra, (',opaque="%s"' % p["opaque"]) if "opaque" in p else "")
        s.sendall(msg(2, auth).encode())
        return int(_recv(s).split()[1])
    finally:
        s.close()
