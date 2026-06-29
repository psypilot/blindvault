"""Encryption with a master password (envelope encryption).

We deliberately do *not* roll our own crypto. The building blocks are standard:

- **scrypt** (a memory-hard KDF) turns the master password + a random salt into a
  key-encryption key (KEK).
- A random **data key** actually encrypts the secrets, via ``cryptography.Fernet``
  (AES-128-CBC + HMAC-SHA256).
- The data key is **wrapped** (encrypted) with the KEK and only the wrapped form
  is written to disk.

Why envelope encryption? The password-derived KEK never touches the secrets
directly, and changing the master password only re-wraps the data key — we never
have to re-encrypt every secret. Crucially, **nothing on disk can be decrypted
without the master password**: an attacker (or an AI agent) who reads the vault
file finds only ciphertext, a salt, and the wrapped key.
"""

from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
KEY_LEN = 32
# scrypt cost for new vaults (2024+ guidance: N=2**17, r=8, p=1).
DEFAULT_SCRYPT_N = 2 ** 17
MIN_SCRYPT_N = 2 ** 14            # floor for real vaults
MAX_SCRYPT_MEMORY = 1 << 30      # 1 GiB ceiling so a tampered file can't DoS unlock
SCRYPT_R = 8
SCRYPT_P = 1


class VaultError(Exception):
    """Raised for vault problems with a human-readable message."""


class AuthError(VaultError):
    """Wrong master password, or an operation attempted while locked."""


def default_scrypt_n() -> int:
    """KDF cost for new vaults. A weak override is honored ONLY when the explicit
    unsafe flag is also set, so a stray ``BLINDVAULT_SCRYPT_N`` from CI cannot
    silently bake a weak production vault."""
    raw = os.environ.get("BLINDVAULT_SCRYPT_N")
    if raw and os.environ.get("BLINDVAULT_ALLOW_WEAK_KDF") == "1":
        try:
            n = int(raw)
            if n >= 2 and (n & (n - 1)) == 0:  # power of two, scrypt requirement
                return n
        except ValueError:
            pass
    return DEFAULT_SCRYPT_N


def validate_scrypt_params(n: int, r: int, p: int) -> None:
    """Reject malformed/abusive KDF params read from the vault file, so a tampered
    header cannot crash or exhaust memory during a password-free unlock attempt."""
    if not all(isinstance(x, int) for x in (n, r, p)):
        raise VaultError("Vault KDF parameters are malformed.")
    if n < 2 or (n & (n - 1)) != 0 or r < 1 or p < 1:
        raise VaultError("Vault KDF parameters are invalid.")
    if 128 * n * r > MAX_SCRYPT_MEMORY:
        raise VaultError("Vault KDF parameters exceed the memory limit.")


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_kek(password: str, salt: bytes, n: int, r: int = SCRYPT_R, p: int = SCRYPT_P) -> bytes:
    """Derive a Fernet-compatible key-encryption key from the password."""
    if not password:
        raise VaultError("Master password must not be empty.")
    validate_scrypt_params(n, r, p)
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def generate_data_key() -> bytes:
    """A fresh random key that actually encrypts the secrets."""
    return Fernet.generate_key()


def wrap_data_key(data_key: bytes, kek: bytes) -> str:
    return Fernet(kek).encrypt(data_key).decode("ascii")


def unwrap_data_key(wrapped: str, kek: bytes) -> bytes:
    try:
        return Fernet(kek).decrypt(wrapped.encode("ascii"))
    except InvalidToken as exc:
        raise AuthError("Wrong master password.") from exc


class Cipher:
    """Encrypts/decrypts individual secret values with the (unwrapped) data key."""

    def __init__(self, data_key: bytes) -> None:
        self._fernet = Fernet(data_key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:  # tampered or corrupted vault
            raise VaultError(
                "Could not decrypt a secret — the vault may be corrupted."
            ) from exc
