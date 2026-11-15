"""Minimal ActiveSync (EAS) test client: WBXML encoder/decoder for the few commands needed to PROVE that a remote-wipe request reaches a device.

Provision (phase 1 request -> response with Status, Policies and, when an administrator requested it, RemoteWipe / AccountOnlyRemoteWipe),
the device's acknowledgement (Provision with RemoteWipe/Status=1) and FolderSync (the command a provisioned device uses afterwards).
Not an EAS client for real mail use: no policy enforcement, no data sync. TLS is always verified against the CA given by the caller;
the destination passes the same SSRF guard as every other outbound ICS request (via idprobe.ProbeConfig.guard).
"""
from dataclasses import dataclass

from . import idprobe

# WBXML global tokens
SWITCH_PAGE, END, STR_I, OPAQUE = 0x00, 0x01, 0x03, 0xC3
CP_FOLDERHIERARCHY, CP_PROVISION = 7, 14
PROVISION = {"Provision": 0x05, "Policies": 0x06, "Policy": 0x07, "PolicyType": 0x08, "PolicyKey": 0x09, "Data": 0x0A, "Status": 0x0B,
             "RemoteWipe": 0x0C, "EASProvisionDoc": 0x0D, "AccountOnlyRemoteWipe": 0x3B}
FOLDERHIER = {"FolderSync": 0x16, "SyncKey": 0x12}
HEADER = bytes([0x03, 0x01, 0x6A, 0x00])      # WBXML 1.3, unknown public id, UTF-8, no string table
POLICY_TYPE = "MS-EAS-Provisioning-WBXML"


def _s(text: str) -> bytes:
    return bytes([STR_I]) + text.encode() + b"\0"


def provision_request(policy_key: str | None = None, ack_wipe: bool = False, with_policy_ack: bool = False) -> bytes:
    """phase 1: ask for the policy (no PolicyKey). ack_wipe: only the RemoteWipe/Status=1 acknowledgement. with_policy_ack: phase 2 (PolicyKey, Status 1)."""
    p = PROVISION
    body = bytes([SWITCH_PAGE, CP_PROVISION, p["Provision"] | 0x40])
    if ack_wipe:
        body += bytes([p["RemoteWipe"] | 0x40, p["Status"] | 0x40]) + _s("1") + bytes([END, END])
    else:
        body += bytes([p["Policies"] | 0x40, p["Policy"] | 0x40, p["PolicyType"] | 0x40]) + _s(POLICY_TYPE) + bytes([END])
        if with_policy_ack:
            body += bytes([p["PolicyKey"] | 0x40]) + _s(policy_key or "0") + bytes([END, p["Status"] | 0x40]) + _s("1") + bytes([END])
        body += bytes([END, END])
    return HEADER + body + bytes([END])


def foldersync_request(sync_key: str = "0") -> bytes:
    f = FOLDERHIER
    return HEADER + bytes([SWITCH_PAGE, CP_FOLDERHIERARCHY, f["FolderSync"] | 0x40, f["SyncKey"] | 0x40]) + _s(sync_key) + bytes([END, END])


def decode(data: bytes) -> list[tuple[int, int, str | None]]:
    """Flat list of (codepage, tag, text) for every element start; text is the first inline string of the element (or None). Raises ValueError."""
    if len(data) < 4 or data[0] not in (1, 2, 3):
        raise ValueError("not WBXML")
    i = 3
    n, shift = 0, 0
    while True:          # string table length (mb_u_int32)
        b = data[i]; i += 1
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            break
        shift += 7
        if shift > 28:
            raise ValueError("bad string table length")
    i += n
    cp, out, last = 0, [], None
    while i < len(data):
        b = data[i]; i += 1
        if b == SWITCH_PAGE:
            cp = data[i]; i += 1
        elif b == END:
            last = None
        elif b == STR_I:
            j = data.index(b"\0", i)
            if last is not None and out[last][2] is None:
                out[last] = (out[last][0], out[last][1], data[i:j].decode("utf-8", "replace"))
            i = j + 1
        elif b == OPAQUE:
            ln = 0
            while True:
                c = data[i]; i += 1
                ln = (ln << 7) | (c & 0x7F)
                if not c & 0x80:
                    break
            i += ln
        else:
            out.append((cp, b & 0x3F, None))
            last = len(out) - 1
    return out


@dataclass
class ProvisionResult:
    http_status: int
    status: int | None = None
    policy_status: int | None = None
    policy_key: str | None = None
    remote_wipe: bool = False
    account_only_wipe: bool = False


def parse_provision(http_status: int, data: bytes) -> ProvisionResult:
    r = ProvisionResult(http_status)
    for cp, tag, text in decode(data):
        if cp != CP_PROVISION:
            continue
        if tag == PROVISION["RemoteWipe"]:
            r.remote_wipe = True
        elif tag == PROVISION["AccountOnlyRemoteWipe"]:
            r.account_only_wipe = True
        elif tag == PROVISION["PolicyKey"]:
            r.policy_key = text
        elif tag == PROVISION["Status"]:
            v = int(text) if text and text.isdigit() else None
            if r.status is None:
                r.status = v
            else:
                r.policy_status = v
    return r


class EasClient:
    def __init__(self, cfg: idprobe.ProbeConfig, mail: str, password: str, device_id: str, device_type: str = "OUProbe", version: str = "16.1"):
        self.cfg, self.mail, self.password, self.dev, self.dtype, self.ver = cfg, mail, password, device_id, device_type, version

    def _post(self, cmd: str, body: bytes):
        url = f"https://{self.cfg.mail_host}/Microsoft-Server-ActiveSync"
        params = {"Cmd": cmd, "User": self.mail, "DeviceId": self.dev, "DeviceType": self.dtype}
        return idprobe._http(self.cfg, url, self.cfg.mail_ca_pem, "POST", params=params, content=body, auth=(self.mail, self.password),
                             headers={"MS-ASProtocolVersion": self.ver, "Content-Type": "application/vnd.ms-sync.wbxml", "User-Agent": "OU-EAS-probe/1"})

    def provision(self, **kw) -> ProvisionResult | None:
        r = self._post("Provision", provision_request(**kw))
        if r is None:
            return None
        try:
            return parse_provision(r.status_code, r.content) if r.status_code == 200 else ProvisionResult(r.status_code)
        except (ValueError, IndexError):
            return ProvisionResult(r.status_code)

    def foldersync(self) -> int | None:
        r = self._post("FolderSync", foldersync_request())
        return None if r is None else r.status_code
