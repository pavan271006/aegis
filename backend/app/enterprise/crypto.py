"""Envelope encryption helper.

Wraps a KEK (key-encryption key) to encrypt data-encryption material at rest:
RSA signing private keys and TOTP secrets. In production the KEK is fronted by
a cloud KMS (AWS KMS / GCP KMS / Vault transit) — swap `_fernet()` for a KMS
client and keep the same interface."""
import base64
import hashlib

from cryptography.fernet import Fernet

from .settings import get_settings


def _fernet() -> Fernet:
    raw = get_settings().kek.encode()
    # Derive a stable 32-byte urlsafe key from the configured KEK.
    key = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(key)


def encrypt(plaintext: bytes) -> bytes:
    return _fernet().encrypt(plaintext)


def decrypt(ciphertext: bytes) -> bytes:
    return _fernet().decrypt(ciphertext)
