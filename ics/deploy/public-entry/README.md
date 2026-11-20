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

## Management access: who may reach the console under its public name (0.7.1)

`ou-console-public.conf` (console under its public name) takes its access rule from `include /etc/nginx/ou-console-access.conf;`. Settings ->
Network & domains -> "Management access (this console)" sets it with the typed action `settings.management.update` (needs approval, audited):

| Mode | File written |
|---|---|
| Public | `allow all;` |
| LAN/VPN only | `allow 192.168.22.0/24;` `allow 10.0.0.0/8;` (or the listed ranges) then `deny all;` |
| Allow list | `allow <range>;` per listed range (max 32; `0.0.0.0/0` and `::/0` refused) then `deny all;` |

The bare-IP console (`ics.conf`, LAN/VPN only) is not touched. Client addresses arrive through the PROXY protocol, so `allow`/`deny` see the real
address. The LAN address of the console keeps working from the LAN whatever is chosen here, which is the way back in after a lock-out.

The console service never runs anything as root (its sandbox: `NoNewPrivileges=true`, no capabilities). It hands the rendered file to
**`ou-console-access.socket`** (`/run/ou-console-access.sock`, owned by root, group `ics`, mode 0660, one connection at a time); systemd starts
`ou-console-access@.service` as root for each connection with the socket as stdin/stdout, and the helper (`python3 -I`, fixed paths, run from the
root-owned install `/opt/office-unbound/ics/deploy/public-entry/ou-console-access`; logic in `ics/ics/console_access_core.py`) answers one line,
`OK ...` or `ERROR ...`. The setting is stored only after `OK`. The helper:

* reads at most 8 KiB; every line must be a comment, `allow <IPv4/IPv6 range>;`, `allow all;` or `deny all;` (anything else, or no allow/deny line,
  is refused before any file is touched);
* keeps the current file as `ou-console-access.conf.prev`, writes `.new`, renames it into place, runs `/usr/sbin/nginx -t -q`;
* if nginx refuses it, puts the previous file back (nginx is not reloaded); otherwise runs `systemctl reload nginx.service`.

`install.sh` installs and enables the socket. By hand, with the same checks:
`printf 'allow 192.168.22.0/24;\nallow 10.0.0.0/8;\ndeny all;\n' | sudo python3 -I /opt/office-unbound/ics/deploy/public-entry/ou-console-access apply`
(the setting shown in the console then does not reflect the file).
