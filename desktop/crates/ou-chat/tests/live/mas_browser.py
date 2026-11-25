#!/usr/bin/env python3
"""Stand-in for the system browser in the live chat test: follows a MAS authorization URL through MAS -> Keycloak sign-in ->
MAS consent until the redirect reaches the 127.0.0.1 loopback listener of the Rust test.

Usage: mas_browser.py <authorization-url>   (env OU_TEST_USER, OU_TEST_PASSWORD_FILE)
Prints only step hosts/paths and status codes; never page bodies, query strings, cookies or the password.
TLS is verified with the system trust store (requests default). Only https hosts under OU_TEST_DOMAIN and the loopback are visited.
"""
import html.parser
import os
import sys
import urllib.parse

import requests


class Forms(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.links, self._cur = [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": [], "buttons": []}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            t = (a.get("type") or "text").lower()
            if t == "submit":
                self._cur["buttons"].append((a.get("name"), a.get("value", "")))
            else:
                self._cur["inputs"].append((a.get("name"), t, a.get("value", "")))
        elif tag == "button" and self._cur is not None:
            self._cur["buttons"].append((a.get("name"), a.get("value", "")))
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def allowed(url, domain):
    u = urllib.parse.urlsplit(url)
    if u.hostname == "127.0.0.1" and u.scheme == "http":
        return True
    return u.scheme == "https" and (u.hostname == domain or (u.hostname or "").endswith("." + domain))


def main():
    url = sys.argv[1]
    domain = os.environ["OU_TEST_DOMAIN"]
    user = os.environ["OU_TEST_USER"]
    with open(os.environ["OU_TEST_PASSWORD_FILE"]) as f:
        password = f.read().strip()
    s = requests.Session()
    s.headers["User-Agent"] = "OfficeUnboundDesktop-livetest"
    method, data = "get", None
    for step in range(20):
        if not allowed(url, domain):
            print(f"refusing to visit {urllib.parse.urlsplit(url).hostname}", file=sys.stderr)
            return 2
        r = s.request(method, url, data=data, allow_redirects=False, timeout=30)
        p = urllib.parse.urlsplit(url)
        print(f"step {step}: {method.upper()} {p.hostname}{p.path} -> {r.status_code}", file=sys.stderr)
        if p.hostname == "127.0.0.1":
            return 0 if r.status_code == 200 else 1
        if r.status_code in (301, 302, 303, 307, 308):
            url, method, data = urllib.parse.urljoin(url, r.headers["Location"]), "get", None
            continue
        if r.status_code != 200:
            return 1
        parser = Forms()
        parser.feed(r.text)
        pw_form = next((f for f in parser.forms if any(t == "password" for _, t, _ in f["inputs"])), None)
        if pw_form:
            fields = {n: v for n, t, v in pw_form["inputs"] if n}
            fields.update({"username": user, "password": password})
            url, method, data = urllib.parse.urljoin(url, pw_form["action"]), "post", fields
            continue
        post = next((f for f in parser.forms if f["method"] == "post"), None)
        if post:
            fields = {n: v for n, t, v in post["inputs"] if n}
            btn = next((b for b in post["buttons"] if (b[1] or "").lower() not in ("cancel", "deny", "reject")), None)
            if btn and btn[0]:
                fields[btn[0]] = btn[1]
            url, method, data = urllib.parse.urljoin(url, post["action"] or url), "post", fields
            continue
        up = next((h for h in parser.links if "/upstream/authorize/" in h), None)
        if up:
            url, method, data = urllib.parse.urljoin(url, up), "get", None
            continue
        print("no form or upstream link on the page", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
