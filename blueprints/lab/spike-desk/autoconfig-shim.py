#!/usr/bin/env python3
"""Lab-only stand-in for the customer's "autoconfig.<domain> -> portal" DNS/proxy step (see docs/status/portal-results.md).
The portal's lab certificate is for portal.<lab domain> only, so a client asking for http://autoconfig.<domain>/mail/config-v1.1.xml
is answered by this tiny forwarder running INSIDE the desktop machine (127.0.0.1:80), which fetches the real document from the
portal over verified TLS (lab CA in the system store) and logs every request it receives."""
import http.server, ssl, sys, urllib.request, time
UP = "https://portal.ou-lab.internal"
LOG = "/root/cc/shim.log"

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        up = path.split("?")[0]
        if up.startswith("/mail/config-v1.1.xml"):
            up = "/.well-known/autoconfig/mail/config-v1.1.xml"
        with open(LOG, "a") as f:
            f.write("%s Host=%s GET %s UA=%s -> %s\n" % (time.strftime("%H:%M:%S"), self.headers.get("Host"), path, self.headers.get("User-Agent"), up))
        try:
            r = urllib.request.urlopen(UP + up, timeout=15, context=ssl.create_default_context())
            body = r.read(); self.send_response(r.status); self.send_header("Content-Type", r.headers.get("Content-Type", "text/xml"))
        except Exception as e:
            body = str(e).encode(); self.send_response(502)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass

http.server.ThreadingHTTPServer(("127.0.0.1", 80), H).serve_forever()
