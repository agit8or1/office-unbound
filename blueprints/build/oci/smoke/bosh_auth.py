#!/usr/bin/env python3
"""Open a BOSH session on a Jitsi prosody with `?room=<r>&token=<jwt>` and try SASL ANONYMOUS (how jitsi-meet authenticates a token user).
usage: bosh_auth.py <prosody-bosh-url> <domain> <room> <jwt>   -> prints SUCCESS / FAILURE:<why>, exit 0 for SUCCESS, 1 otherwise"""
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

url, domain, room, token = sys.argv[1:5]
full = url + "?" + urllib.parse.urlencode({"room": room, "token": token})
NS = "http://jabber.org/protocol/httpbind"


def post(body):
    req = urllib.request.Request(full, data=body.encode(), headers={"Content-Type": "text/xml; charset=utf-8", "Host": domain})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


rid = 1000
st, b = post(f"<body rid='{rid}' xmlns='{NS}' to='{domain}' xml:lang='en' wait='10' hold='1' content='text/xml; charset=utf-8' ver='1.6' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>")
m = re.search(r"sid='([^']+)'", b)
if st != 200 or not m:
    print("FAILURE:no-session HTTP %s %s" % (st, b[:160]))
    sys.exit(1)
sid = m.group(1)
if "ANONYMOUS" not in b:
    print("FAILURE:no ANONYMOUS mechanism offered: " + re.sub(r"xmlns[:a-z]*=.[^ >]*", "", b)[:700])
    sys.exit(1)
rid += 1
st, b = post(f"<body rid='{rid}' sid='{sid}' xmlns='{NS}'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/></body>")
if "<success" in b:
    print("SUCCESS: SASL ANONYMOUS accepted for room %s" % room)
    sys.exit(0)
print("FAILURE:" + re.sub(r"\s+", " ", b)[:200])
sys.exit(1)
