"""Review 5 M2: the ICS-host neighbour table (ARP) as the witness of which hardware address answers for an IPv4 address.
Read-only (/proc/net/arp); no scanning. The only packet that can be caused is one TCP connect to the address the guest itself reported (the
very host the ICS is about to enroll), to make the kernel resolve it if the entry has aged out."""
import re
import socket

ARP = "/proc/net/arp"
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _lookup(addr: str, path: str = ARP) -> str | None:
    try:
        lines = open(path).read().splitlines()[1:]
    except OSError:
        return None
    for ln in lines:
        p = ln.split()
        if len(p) >= 4 and p[0] == addr and p[2] != "0x0" and MAC.match(p[3].lower()) and p[3] != "00:00:00:00:00:00":
            return p[3].lower()
    return None


def readable(path: str = ARP) -> bool:
    """False when this process cannot see the neighbour table at all (e.g. a systemd sandbox with ProcSubset=pid hides /proc/net): then a
    missing entry says nothing about the guest, and the caller must report the real cause instead of blaming the network."""
    try:
        with open(path) as f:
            f.readline()
        return True
    except OSError:
        return False


def mac_of(addr: str, port: int = 8443, path: str = ARP) -> str | None:
    """MAC the kernel has for `addr` on a directly attached segment, or None (routed / unknown)."""
    m = _lookup(addr, path)
    if m is None:
        try:
            socket.create_connection((addr, port), timeout=3).close()   # same peer the enrollment contacts next; resolves the neighbour entry
        except OSError:
            pass
        m = _lookup(addr, path)
    return m
