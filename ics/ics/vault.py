"""AES-256-GCM secrets vault. Any failure raises VaultError; there is no plaintext fallback."""
import os
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"


class VaultError(Exception):
    pass


def read_key_file(path: str, what: str = "vault key") -> bytes:
    """Read a 32-byte key file. Must be a regular file (no symlink), not world-accessible, not group-writable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        raise VaultError(f"cannot read {what} file: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise VaultError(f"{what} file must be a regular file")
        if st.st_mode & 0o007 or st.st_mode & 0o020:
            raise VaultError(f"{what} file must not be world-accessible or group-writable (use 0640 root:ics or 0600)")
        return os.read(fd, 4096)
    finally:
        os.close(fd)


class Vault:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise VaultError("vault key must be exactly 32 bytes")
        self._aes = AESGCM(key)
        self.key = key  # only for key-id derivation and master-key rotation; never logged

    @classmethod
    def from_file(cls, path: str) -> "Vault":
        return cls(read_key_file(path))

    def encrypt(self, plaintext: bytes, context: str) -> bytes:
        """`context` is bound as AAD, so a blob cannot be moved to another record/column."""
        nonce = os.urandom(12)
        return VERSION + nonce + self._aes.encrypt(nonce, plaintext, context.encode())

    def decrypt(self, blob: bytes, context: str) -> bytes:
        blob = bytes(blob)
        if len(blob) < 1 + 12 + 16 or blob[:1] != VERSION:
            raise VaultError("malformed vault blob")
        try:
            return self._aes.decrypt(blob[1:13], blob[13:], context.encode())
        except InvalidTag:
            raise VaultError("vault decryption failed (tampered data, wrong key or wrong context)") from None
