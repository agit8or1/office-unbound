# Lab desktop-client machine `ou-desk2` (client compatibility, Thunderbird + Evolution)

Purpose: run REAL open-source desktop mail/calendar/contacts clients against the lab groupware (`gw1.ou-lab.internal`, Gromox 3.13 +
grommunio-dav 1.9 + the portal's autoconfig document) and record what actually works. Results: `docs/status/client-compat-results.md`.

| Piece | File |
|---|---|
| Machine (clone of `ou-base-noble`, zone `oulab`, `PrivateUsers=pick`, `MemoryMax=2G`, Xvfb) | `install-desk2.sh` (run inside) |
| Thunderbird ESR 153.7.0 (Mozilla tarball, checksum + signature verified), driven over Marionette (chrome JS) | `marionette.py`, `../tests/cc_tb_mail.py`, `../tests/cc_tb_dav.py` |
| Stand-in for the customer's `autoconfig.<domain>` -> portal DNS/proxy step (desk2 only) | `autoconfig-shim.py` |
| Evolution 3.52 + evolution-ews 3.52, driven over the EDS client API + Camel | `evo-session.sh`, `evo-servers.sh`, `../tests/cc_evo_worker.py`, `../tests/cc_evo.py` |
| shared helpers (IMAP/CalDAV/CardDAV/EWS server-side verification) | `../tests/cc_lib.py` |

## Prerequisites in the lab (done through the documented paths only)
* Test users (never printed): `ldap-user.sh add cctb1|cctb2|ccev1|ccev2 -` on `ou-id1`, then `gw-ldap-sync.py --user <uid>@ou-lab.internal` on `ou-gw1`.
  Passwords: copy `OU_PASSWORD_<UID>` lines from `ou-id1:/root/ou-lab-secrets/test-users.env` into `/root/cc/users.env` (0600) in the desk machine and
  one line each into `/home/evo1/pw.env` (CCEV1) and `/home/evo2/pw.env` (CCEV2) (0600, owner evo1/evo2).
* desk2 `/etc/hosts` only: `gw1`/`autodiscover.gw1` -> 192.168.186.218, `auth`/`ldap` -> .241, `portal` -> .244, `autoconfig.ou-lab.internal` -> 127.0.0.1 (shim).
  Lab CA + `OU Lab CA gw1` public certs in the system store (and imported into Thunderbird's own NSS store by the test).

## Run
```
# Thunderbird (Xvfb :99, profile /home/tester/tb)
systemd-run --unit=xvfb Xvfb :99 -screen 0 1280x900x24 -nolisten tcp
systemd-run --unit=acshim python3 /root/cc/autoconfig-shim.py
systemd-run --unit=tb -p User=tester -E DISPLAY=:99 -E HOME=/home/tester /opt/thunderbird/thunderbird -no-remote -profile /home/tester/tb -marionette -remote-allow-system-access
python3 /root/cc/cc_tb_mail.py ; python3 /root/cc/cc_tb_dav.py        # use a fresh profile per run (see notes)
# Evolution
/root/cc/evo-servers.sh start ; python3 /root/cc/cc_evo.py
```
Each test prints PASS/FAIL/PARTIAL/NOT SUPPORTED lines with the exact protocol/API used and writes `/root/cc/result-*.json`.

## Honest scope
* "Driven through the client" = real Thunderbird / Evolution Data Server + Camel processes executing the client's own code paths
  (account-hub autoconfig lookup, SMTP/IMAP/CalDAV/CardDAV/EWS stacks) via Marionette / EDS APIs. The **GUI is not clicked**.
* Server-side facts are verified with independent protocol clients (imaplib, raw CalDAV/CardDAV, raw EWS).
* Marionette runs with `-remote-allow-system-access`; the profile is a throw-away lab profile. Passwords live only in the lab
  secrets file and the client's own login store inside the machine.

## Notes from the second run (agent BJ, docs/status/gw-client-fixes-results.md)
* The harness hard-codes the user names `cctb1/2`, `ccev1/2`. If Gromox still holds old accounts with those names but different directory entry UUIDs
  (`gw-ldap-sync.py` reports `conflict ... externid differs`), create fresh directory users and rename them in the copies inside the machine
  (`sed -i 's/cctb/bjtb/g; s/ccev/bjev/g' /root/cc/*.py /root/cc/*.sh`).
* After a restart of the machine `/run/user/<uid of evo1,evo2>` does not exist: `install -d -o evoN -g evoN -m 0700 /run/user/$(id -u evoN)` before
  `evo-servers.sh start`, otherwise gnome-keyring cannot start and the EWS backend never connects.
* A fresh Evolution Data Server profile lists only "Global Address List" after the first `setup`; stop (`evo-servers.sh stop`) and start the servers again, then
  run `setup` again (`/root/cc/evosetup.py`-style call, or just let `cc_evo.py` do it): Calendar/Contacts/Notes/Tasks appear.
* `EWS_DEBUG=2 evo-servers.sh start` logs the SOAP request/response bodies of evolution-ews to the journal of `evoNsrv` (level 1: headers only).
* `tb_folders_probe.py <address>` prints the folders a Thunderbird account knows (with flags) and where Fcc goes; the duplicate Sent/Trash investigation used it.
* Thunderbird: after account creation the harness now calls `MailServices.imap.discoverAllFolders` (what the first start does) and the test uses the autoconfig
  document unchanged (587 STARTTLS + AUTH), no manual port override any more.
