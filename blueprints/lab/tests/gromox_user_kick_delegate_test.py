#!/usr/bin/python3
"""M2 test on a BUILD machine (never ou-gw1): USER-KICK must end the sessions whose AUTHENTICATED user is the kicked user (own + delegated)
and must not end other users' delegate sessions on the kicked user's mailbox. Four IMAP sessions: A bob, B bob!carol, C carol, D carol!bob."""
import imaplib, os, socket, subprocess, sys, time, base64

D = "ou-lab.internal"
PW = "Kick-Test-" + os.urandom(6).hex()
bob, carol = f"bob@{D}", f"carol@{D}"


def sh(c, **k):
    return subprocess.run(c, shell=True, capture_output=True, text=True, **k)


def sql(q):
    r = sh(f'mysql -N -e "{q}"')
    assert r.returncode == 0, r.stderr
    return r.stdout


# prepare (lab clone only)
h = sh(f"openssl passwd -6 '{PW}'").stdout.strip()
orig = sql(f"select username,password from email.users where username in ('{bob}','{carol}')")
sql(f"update email.users set password='{h.replace(chr(36), chr(92)+chr(36))}' where username in ('{bob}','{carol}')")
for owner, actor in ((bob, carol), (carol, bob)):   # actor may log in to owner's store as delegate (store owner right on IPM_SUBTREE)
    db = f"/var/lib/gromox/user/{owner}/exmdb/exchange.sqlite3"
    sh(f"sqlite3 {db} \"delete from permissions where folder_id=9 and username='{actor}'; insert into permissions(folder_id,username,permission) values (9,'{actor}',{0x2000 | 0x100});\"")
sh("cp -a /etc/gromox/gromox.cfg /root/gromox.cfg.kicktest; sed -i '/^auth_backend_selection/d' /etc/gromox/gromox.cfg; echo auth_backend_selection=allow_all >> /etc/gromox/gromox.cfg")
sh("systemctl restart gromox-event gromox-http gromox-midb gromox-imap")
time.sleep(6)


def login(user):
    c = imaplib.IMAP4("127.0.0.1", 143, timeout=10)
    t, d = c.login(user, PW)
    assert t == "OK", (user, d)
    return c


def alive(c):
    try:
        c.noop()
        return True
    except Exception:
        return False


def kick(user):
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/gromox/event.sock")
    f = s.makefile("rwb", buffering=0)
    f.readline()
    f.write(b"ID kicktest\r\n"); f.readline()
    f.write(f"USER-KICK {user} *\r\n".encode()); print("event answer:", f.readline().strip())
    s.close()


try:
    S = {"A bob": login(bob), "B bob!carol": login(f"{bob}!{carol}"), "C carol": login(carol), "D carol!bob": login(f"{carol}!{bob}")}
    for n, c in S.items():
        c.select("INBOX")
    print("all four sessions up:", {n: alive(c) for n, c in S.items()})
    kick(bob)
    t0 = time.time()
    time.sleep(3)
    res = {n: alive(c) for n, c in S.items()}
    print("after USER-KICK bob:", res)
    ok = (not res["A bob"]) and (not res["B bob!carol"]) and res["C carol"] and res["D carol!bob"]
    # a fresh login of bob after the kick works (no ban list)
    fresh = alive(login(bob))
    print("fresh bob login after kick:", fresh)
    print("RESULT", "PASS" if ok and fresh else "FAIL")
    sys.exit(0 if ok and fresh else 1)
finally:
    sh("cp -a /root/gromox.cfg.kicktest /etc/gromox/gromox.cfg")
    for line in orig.strip().splitlines():
        u, p = line.split("\t")
        sql(f"update email.users set password='{p}' where username='{u}'")
