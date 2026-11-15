#!/usr/bin/env python3
"""T12 CardDAV contact create/read against grommunio-dav.

Same discovery pattern as T11 with addressbook-home-set. PUT a vCard with a
unique FN, GET it back, DELETE.
PROVES: CardDAV endpoint, addressbook discovery, contact write/read.
DOES NOT PROVE: GAL search, photo/large contact handling, sync behaviour in
Apple/DAVx5/Thunderbird, MAPI contact folder visibility.
"""
import os
import sys
import urllib.parse
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ou_lab as L

rep = L.Report("T12 CardDAV")
if not L.need_requests(rep):
    rep.finish()
import requests
pw = L.password_for("alice")
if not (L.CA_FILE and pw):
    rep.skipped("config", "need OU_CA_FILE, OU_PASSWORD_ALICE"); rep.finish()
V = L.verify()
auth = ("alice@" + L.MAIL_DOMAIN, pw)
base = "https://%s" % L.HOST_MAIL
NS = {"d": "DAV:", "c": "urn:ietf:params:xml:ns:carddav"}

def propfind(url, body, depth="0"):
    return requests.request("PROPFIND", url, data=body, auth=auth, verify=V, timeout=30,
                            headers={"Depth": depth, "Content-Type": "application/xml"})

r = requests.request("PROPFIND", base + "/.well-known/carddav", auth=auth, verify=V, timeout=30, allow_redirects=True, headers={"Depth": "0"})
start = r.url if r.status_code in (200, 207) else base + "/dav/"
rep.check("well-known/carddav reachable", r.status_code in (200, 207), "resolved to %s" % r.url,
          "HTTP %s; falling back to %s" % (r.status_code, start))
cup = propfind(start, '<d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>')
if not rep.check("principal discovery", cup.status_code == 207, "HTTP 207", "HTTP %s" % cup.status_code):
    rep.finish()
href = ET.fromstring(cup.content).find(".//d:current-user-principal/d:href", NS)
principal = urllib.parse.urljoin(start, href.text) if href is not None else start
hs = propfind(principal, '<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:prop><c:addressbook-home-set/></d:prop></d:propfind>')
h = ET.fromstring(hs.content).find(".//c:addressbook-home-set/d:href", NS) if hs.status_code == 207 else None
home = urllib.parse.urljoin(principal, h.text) if h is not None else None
if not rep.check("addressbook-home-set", home is not None, home, "none (HTTP %s)" % hs.status_code):
    rep.finish()
ab = propfind(home, '<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>', "1")
target = None
for resp in ET.fromstring(ab.content).findall("d:response", NS):
    if resp.find(".//c:addressbook", NS) is not None:
        target = urllib.parse.urljoin(home, resp.find("d:href", NS).text); break
if not rep.check("addressbook collection", bool(target), target, "no addressbook under %s" % home):
    rep.finish()
uid = "ou-lab-%s" % L.RUN_ID
fn = "Lab Contact %s" % L.RUN_ID
vcf = ("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nFN:%s\r\nN:%s;Lab;;;\r\nEMAIL;TYPE=INTERNET:%s@%s\r\nEND:VCARD\r\n"
       % (uid, fn, L.RUN_ID, uid, L.MAIL_DOMAIN))
url = target.rstrip("/") + "/" + uid + ".vcf"
p = requests.put(url, data=vcf.encode(), auth=auth, verify=V, timeout=30, headers={"Content-Type": "text/vcard", "If-None-Match": "*"})
rep.check("PUT contact", p.status_code in (201, 204), "HTTP %s" % p.status_code, "HTTP %s %s" % (p.status_code, p.text[:120]))
g = requests.get(url, auth=auth, verify=V, timeout=30)
rep.check("GET contact", g.status_code == 200 and fn in g.text, "FN round-trips", "HTTP %s, FN missing" % g.status_code)
d = requests.delete(url, auth=auth, verify=V, timeout=30)
rep.check("DELETE contact", d.status_code in (200, 204), "HTTP %s" % d.status_code, "HTTP %s" % d.status_code)
rep.finish()
