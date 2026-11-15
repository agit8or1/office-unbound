"""AES-256-GCM secrets vault. Any failure raises VaultError; there is no plaintext fallback."""
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = b"\x01"


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise VaultError("vault key must be exactly 32 bytes")
        self._aes = AESGCM(key)

    @classmethod
    def from_file(cls, path: str) -> "Vault":
        try:
            return cls(Path(path).read_bytes())
        except OSError as e:
            raise VaultError(f"cannot read vault key file: {e.strerror}") from None

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
