"""Minimal webhook receiver: verifies X-MSP-Signature over the RAW body, de-duplicates on the event id (delivery is at-least-once) and
acknowledges with 2xx only after the event is durably handled.

    OU_WEBHOOK_SECRET=whsec_... python examples/webhook_receiver.py 8099
Run it behind HTTPS (ICS refuses plain-http webhook urls).
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ou_msp import EventDeduper, verify_signature  # noqa: E402

SECRET = os.environ["OU_WEBHOOK_SECRET"]
dedupe = EventDeduper()


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not verify_signature(SECRET, raw, self.headers.get("X-MSP-Signature", "")):
            self.send_response(401)
            self.end_headers()
            return
        event = json.loads(raw)
        if dedupe.first_time(event):  # a retry of an already handled event is acknowledged but not processed again
            print(event["type"], event["id"], event["customer_id"], json.dumps(event["data"])[:200])
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 8099), Hook).serve_forever()
