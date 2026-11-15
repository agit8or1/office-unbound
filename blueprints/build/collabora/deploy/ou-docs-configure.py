#!/usr/bin/env python3
"""Apply the Office Unbound Docs deployment settings to the patched-default /etc/coolwsd/coolwsd.xml.
Text-level edits (keeps the shipped comments); every edit must match exactly once or the script aborts.
Usage: ou-docs-configure.py <wopi-host-url> <ca-file> [coolwsd.xml]
Example: ou-docs-configure.py https://cloud.ou-lab.internal:443 /etc/ou-lab/tls/ca.crt
TLS: terminated by the reverse proxy (nginx, lab cert), coolwsd listens on loopback only.
"""
import re, sys
host, ca = sys.argv[1], sys.argv[2]
path = sys.argv[3] if len(sys.argv) > 3 else "/etc/coolwsd/coolwsd.xml"
t = open(path).read()

def sub(pat, repl, flags=re.S, count=0):
    global t
    new, n = re.subn(pat, repl, t, count=count, flags=flags)
    if n != 1:
        sys.exit("pattern matched %d times (want 1): %s" % (n, pat))
    t = new

# no outbound update-version fetch, no update popup (already false by patch 0002)
sub(r'(<fetch_update_check [^>]*>)\d+(</fetch_update_check>)', r'\g<1>0\2')
sub(r'(<allow_update_popup [^>]*>)\w+(</allow_update_popup>)', r'\1false\2')
# no jail mount (nspawn has no CAP_SYS_ADMIN); capabilities=false -> landlock/none. Real VMs: leave defaults.
sub(r'(<mount_jail_tree [^>]*>)\w+(</mount_jail_tree>)', r'\1false\2')
sub(r'(<capabilities [^>]*>)\w+(</capabilities>)', r'\1false\2')
# listen on loopback only, behind the TLS proxy
sub(r'(<listen [^>]*>)\w+(</listen>)', r'\1loopback\2')
sub(r'(<ssl desc="SSL settings">.*?<enable [^>]*>)\w+(</enable>)', r'\1false\2', count=1)
sub(r'(<termination [^>]*>)\w+(</termination>)', r'\1true\2')
# (top-level <ssl> is the first such block; storage.wopi.ssl inherits from it, so only the first match is edited: count=1)
# trust the lab CA for coolwsd -> WOPI host connections, strict verification
sub(r'(<ssl desc="SSL settings">.*?<ca_file_path [^>]*>)[^<]*(</ca_file_path>)', r'\g<1>%s\2' % ca, count=1)
sub(r'(<ssl desc="SSL settings">.*?<ssl_verification [^>]*>)\w+(</ssl_verification>)', r'\1true\2', count=1)
# WOPI host allowlist: exactly one host
sub(r'(<alias_groups [^>]*?)mode="first"', r'\1mode="groups"')
sub(r'(<alias_groups [^>]*>)', r'\1\n<group><host allow="true">%s</host></group>' % host)
# admin console off
sub(r'(<admin_console [^>]*>\s*<enable [^>]*>)\w+(</enable>)', r'\1false\2')
open(path, "w").write(t)
print("configured", path)
