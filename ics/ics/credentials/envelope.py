"""Envelope encryption: a random 256-bit data key per credential encrypts the secret (AES-256-GCM); the data key is
wrapped by the master key (the vault key file). AAD for both layers binds credential id + provider + customer, so a
blob or wrapped key moved to another credential row fails to decrypt."""
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vault import Vault, VaultError

V = b"\x02"


def aad(cred_id, provider: str, customer_id) -> str:
    return f"credential:{cred_id}:{provider}:{customer_id}"


def vault_key_id(vault: Vault) -> str:
    return hashlib.sha256(b"ics-master-key-id:" + vault.key).hexdigest()[:16]


def seal(vault: Vault, secret: bytes, cred_id, provider: str, customer_id) -> tuple[bytes, bytes, str]:
    """-> (wrapped_key, secret_enc, master_key_id)"""
    a = aad(cred_id, provider, customer_id)
    dek = AESGCM.generate_key(256)
    nonce = os.urandom(12)
    enc = V + nonce + AESGCM(dek).encrypt(nonce, secret, a.encode())
    return vault.encrypt(dek, "dek:" + a), enc, vault_key_id(vault)


def unseal(vault: Vault, wrapped_key: bytes, secret_enc: bytes, cred_id, provider: str, customer_id) -> bytes:
    a = aad(cred_id, provider, customer_id)
    dek = vault.decrypt(wrapped_key, "dek:" + a)
    blob = bytes(secret_enc)
    if len(blob) < 1 + 12 + 16 or blob[:1] != V:
        raise VaultError("malformed credential blob")
    try:
        return AESGCM(dek).decrypt(blob[1:13], blob[13:], a.encode())
    except InvalidTag:
        raise VaultError("credential decryption failed (tampered data or wrong binding)") from None


def rewrap_key(old: Vault, new: Vault, wrapped_key: bytes, cred_id, provider: str, customer_id) -> tuple[bytes, str]:
    a = aad(cred_id, provider, customer_id)
    dek = old.decrypt(wrapped_key, "dek:" + a)
    return new.encrypt(dek, "dek:" + a), vault_key_id(new)
