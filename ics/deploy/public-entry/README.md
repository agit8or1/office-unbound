# Public entry on the ICS host (single public IP, router forwards 80/443 here)

Installed on the ICS host on 2026-11-20 at the owner's request ("route by subdomain ... maybe use a proxy"); see docs/status/host-changes.md.

* `ou-public-sni.conf` -> `/etc/nginx/ou-public-sni.conf` (included from nginx.conf, main context; needs `libnginx-mod-stream`):
  443 routed by TLS server name **without decrypting**: deployment names pass through to their gateway/mail VM; any other name (or none)
  reaches the ICS console only from LAN/VPN (`geo`, the router's own address counts as outside); every other connection is closed.
  The real client address travels with the PROXY protocol, so the console's allow-list in `ics.conf` still applies.
* `ou-public-http.conf` -> `/etc/nginx/sites-available/` (enabled): port 80 for deployment names only (HTTPS redirect, ACME HTTP-01).
* `ics-admin-fw.nft` -> `/etc/office-unbound/ics-admin-fw.nft`: 80/443 accepted; nginx decides.
* `ics.conf` (console): listens on `127.0.0.1:4443 ssl http2 proxy_protocol` with `set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`.

The name -> VM map is written by hand for the test domain today; ADR-0018 G1 makes the ICS generate it from the deployments' plans
(same file, validated with `nginx -t`, previous revision kept).
