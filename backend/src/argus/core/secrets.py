"""Credentials at rest: AES-256-GCM under a keyring from the environment.

Sealed values are stored as nonce || ciphertext, next to the id of the key that sealed them,
so keys rotate by adding a new current key and re-sealing rows over time. Every seal binds
associated data naming the row it belongs to (for example "connection:aws:123456789012"), so a
ciphertext copied into another row fails to open instead of decrypting into the wrong place.

Plaintext never leaves this module except as the return value of unseal(), which only the
worker calls, at the moment it needs the credential.
"""

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argus.core.config import get_settings

NONCE_BYTES = 12
KEY_BYTES = 32


class SecretsNotConfiguredError(RuntimeError):
    """The environment has no usable keyring, so no credential can be stored or used."""


@dataclass(frozen=True)
class Sealed:
    key_id: str
    blob: bytes  # nonce || ciphertext-with-tag


def _keyring() -> tuple[str, dict[str, bytes]]:
    settings = get_settings()
    if settings.secret_keys is None or not settings.secret_key_id:
        raise SecretsNotConfiguredError("ARGUS_SECRET_KEYS and ARGUS_SECRET_KEY_ID must be set")
    keys: dict[str, bytes] = {}
    for entry in settings.secret_keys.get_secret_value().split(","):
        key_id, _, encoded = entry.strip().partition(":")
        key = base64.b64decode(encoded, validate=True)
        if not key_id or len(key) != KEY_BYTES:
            raise SecretsNotConfiguredError(f"key {key_id!r} must be {KEY_BYTES} bytes, base64")
        keys[key_id] = key
    if settings.secret_key_id not in keys:
        raise SecretsNotConfiguredError(f"current key {settings.secret_key_id!r} not in keyring")
    return settings.secret_key_id, keys


def seal(plaintext: str, *, binding: str) -> Sealed:
    current, keys = _keyring()
    nonce = os.urandom(NONCE_BYTES)
    blob = nonce + AESGCM(keys[current]).encrypt(nonce, plaintext.encode(), binding.encode())
    return Sealed(key_id=current, blob=blob)


def unseal(sealed: Sealed, *, binding: str) -> str:
    _, keys = _keyring()
    if sealed.key_id not in keys:
        raise SecretsNotConfiguredError(f"key {sealed.key_id!r} is no longer in the keyring")
    nonce, ciphertext = sealed.blob[:NONCE_BYTES], sealed.blob[NONCE_BYTES:]
    return AESGCM(keys[sealed.key_id]).decrypt(nonce, ciphertext, binding.encode()).decode()


def new_key() -> str:
    """A fresh base64 key for ARGUS_SECRET_KEYS (used by docs and local setup)."""
    return base64.b64encode(os.urandom(KEY_BYTES)).decode()
