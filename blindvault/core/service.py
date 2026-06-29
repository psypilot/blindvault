"""High-level vault operations shared by the CLI and the desktop GUI.

A vault is **locked** until you supply the master password. While locked you can
still see secret *names* (metadata), but you cannot read, add, or change values.
Unlocking derives the data key from the password and keeps it in memory for the
lifetime of this ``Vault`` object.
"""

from __future__ import annotations

import base64
import json
import secrets as _random
import string

from . import config, store
from .crypto import (
    AuthError,
    Cipher,
    VaultError,
    default_scrypt_n,
    derive_kek,
    generate_data_key,
    new_salt,
    unwrap_data_key,
    wrap_data_key,
)

SOURCE_MANUAL = "manual"        # a human typed/pasted it
SOURCE_GENERATED = "generated"  # created by `gen` (often by the AI), never seen

_ALPHABET = string.ascii_letters + string.digits


def _encode_blob(name: str, value: str, policy: dict | None) -> str:
    """Bundle the name, value, and usage policy into one authenticated string.

    Binding the name inside the ciphertext means an attacker who can write the
    vault file cannot swap two secrets' ciphertexts (e.g. make STAGING resolve to
    the PROD value) without being detected — the recovered name won't match.
    """
    return json.dumps({"__bv__": 1, "name": name, "value": value, "policy": policy})


def _decode_blob(text: str, expected_name: str | None = None) -> tuple[str, dict | None]:
    """Inverse of ``_encode_blob``. Plain strings (pre-0.4.0 secrets) decode to
    themselves with no policy, so existing vaults keep working. If the blob carries
    a name and it does not match ``expected_name``, raise (tamper/swap detected)."""
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("__bv__") == 1:
            stored = obj.get("name")
            if expected_name is not None and stored is not None and stored != expected_name:
                raise VaultError(
                    f"Vault integrity error: the entry for '{expected_name}' does not match "
                    "its stored name (possible tampering or a swapped ciphertext)."
                )
            return obj.get("value", ""), obj.get("policy")
    except (ValueError, TypeError):
        pass
    return text, None


class Vault:
    """An opened vault. Locked until ``unlock_*`` is called."""

    def __init__(self, data: dict) -> None:
        self._data = data
        self._path = config.store_path()
        self._data_key: bytes | None = None
        self._cipher: Cipher | None = None

    # -- lifecycle -------------------------------------------------------- #
    @staticmethod
    def is_initialized() -> bool:
        path = config.store_path()
        if not path.exists():
            return False
        try:
            return "wrapped_key" in store.load(path)
        except (ValueError, OSError):
            return False

    @staticmethod
    def initialize(password: str, force: bool = False) -> None:
        path = config.store_path()
        if Vault.is_initialized() and not force:
            raise VaultError(f"A vault already exists at {config.vault_home()}.")
        if not password:
            raise VaultError("Master password must not be empty.")
        n = default_scrypt_n()
        salt = new_salt()
        kek = derive_kek(password, salt, n=n)
        data_key = generate_data_key()
        data = {
            "version": store.VERSION,
            "kdf": {
                "algo": "scrypt",
                "n": n,
                "r": 8,
                "p": 1,
                "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            },
            "wrapped_key": wrap_data_key(data_key, kek),
            "secrets": {},
        }
        store.save(path, data)

    @classmethod
    def open_locked(cls) -> "Vault":
        """Load the vault metadata without unlocking it."""
        path = config.store_path()
        if not path.exists():
            raise VaultError("No vault found. Run `blindvault init` first.")
        data = store.load(path)
        if "wrapped_key" not in data:
            raise VaultError(
                "This vault predates the master-password format. "
                "Please re-create it with `blindvault init`."
            )
        return cls(data)

    @staticmethod
    def location() -> str:
        return str(config.vault_home())

    # -- legacy (v1) migration -------------------------------------------- #
    @staticmethod
    def is_legacy_v1() -> bool:
        """True if a pre-0.2.0 vault (plaintext key.bin, no master password) exists."""
        path = config.store_path()
        if not path.exists():
            return False
        try:
            data = store.load(path)
        except (ValueError, OSError):
            return False
        return "wrapped_key" not in data and config.legacy_key_path().exists()

    @staticmethod
    def legacy_names() -> list[str]:
        try:
            data = store.load(config.store_path())
        except (ValueError, OSError):
            return []
        return sorted(data.get("secrets", {}))

    @staticmethod
    def migrate_from_v1(new_password: str) -> int:
        """Re-encrypt a v1 vault under a new master password; returns the count.

        Reads the old plaintext key, decrypts every value, writes a fresh v2
        vault, and deletes the old key file. Names/notes/origin are preserved.
        """
        if not new_password:
            raise VaultError("Master password must not be empty.")
        key_path = config.legacy_key_path()
        if not key_path.exists():
            raise VaultError("No legacy key found to migrate.")
        try:
            old_cipher = Cipher(key_path.read_bytes().strip())
        except ValueError as exc:
            raise VaultError("The legacy key file is invalid.") from exc
        data = store.load(config.store_path())

        try:
            decrypted = [
                (name, old_cipher.decrypt(meta["ciphertext"]),
                 meta.get("description", ""), meta.get("source", SOURCE_MANUAL),
                 meta.get("updated", store.now_iso()))
                for name, meta in data.get("secrets", {}).items()
            ]
        except (KeyError, TypeError) as exc:
            raise VaultError("The legacy vault is malformed; cannot migrate.") from exc

        n = default_scrypt_n()
        salt = new_salt()
        kek = derive_kek(new_password, salt, n=n)
        data_key = generate_data_key()
        cipher = Cipher(data_key)
        secrets = {
            name: {
                "ciphertext": cipher.encrypt(_encode_blob(name, value, None)),
                "description": desc,
                "source": source,
                "updated": updated,
            }
            for name, value, desc, source, updated in decrypted
        }
        store.save(config.store_path(), {
            "version": store.VERSION,
            "kdf": {"algo": "scrypt", "n": n, "r": 8, "p": 1,
                    "salt": base64.urlsafe_b64encode(salt).decode("ascii")},
            "wrapped_key": wrap_data_key(data_key, kek),
            "secrets": secrets,
        })
        try:
            key_path.unlink()
        except OSError:
            pass
        return len(secrets)

    # -- unlocking -------------------------------------------------------- #
    def _kek_from_password(self, password: str) -> bytes:
        kdf = self._data.get("kdf") or {}
        try:
            salt = base64.urlsafe_b64decode(kdf["salt"])
            n, r, p = kdf["n"], kdf["r"], kdf["p"]
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError("Vault KDF header is malformed.") from exc
        return derive_kek(password, salt, n=n, r=r, p=p)

    def unlock_with_password(self, password: str) -> "Vault":
        kek = self._kek_from_password(password)
        self._set_data_key(unwrap_data_key(self._data["wrapped_key"], kek))
        return self

    def unlock_with_data_key(self, data_key: bytes) -> "Vault":
        # Trusts a data key from a prior unlock (e.g. a session or the GUI).
        Cipher(data_key)  # validate shape early
        self._set_data_key(data_key)
        return self

    def _set_data_key(self, data_key: bytes) -> None:
        self._data_key = data_key
        self._cipher = Cipher(data_key)

    @property
    def is_locked(self) -> bool:
        return self._cipher is None

    @property
    def data_key(self) -> bytes:
        if self._data_key is None:
            raise AuthError("Vault is locked.")
        return self._data_key

    def _require_unlocked(self) -> Cipher:
        if self._cipher is None:
            raise AuthError("Vault is locked — unlock with your master password first.")
        return self._cipher

    def change_password(self, old_password: str, new_password: str, rekey: bool = False) -> None:
        if not new_password:
            raise VaultError("New master password must not be empty.")
        old_kek = self._kek_from_password(old_password)
        data_key = unwrap_data_key(self._data["wrapped_key"], old_kek)  # verifies old

        if rekey:
            # Rotate the data key and re-encrypt every secret, so a previously
            # exposed data key (or leaked session) can no longer decrypt anything.
            old_cipher = Cipher(data_key)
            data_key = generate_data_key()
            new_cipher = Cipher(data_key)
            for meta in self._data["secrets"].values():
                meta["ciphertext"] = new_cipher.encrypt(old_cipher.decrypt(meta["ciphertext"]))

        n = default_scrypt_n()
        salt = new_salt()
        new_kek = derive_kek(new_password, salt, n=n)
        self._data["kdf"] = {"algo": "scrypt", "n": n, "r": 8, "p": 1,
                             "salt": base64.urlsafe_b64encode(salt).decode("ascii")}
        self._data["wrapped_key"] = wrap_data_key(data_key, new_kek)
        store.save(self._path, self._data)
        self._set_data_key(data_key)  # keep this open Vault usable after a rekey

    # -- reads ------------------------------------------------------------ #
    def kdf_n(self) -> int | None:
        """The stored scrypt cost, so callers can warn about a weak vault."""
        return (self._data.get("kdf") or {}).get("n")

    def names(self) -> list[str]:
        return sorted(self._data["secrets"])

    def entries(self) -> list[dict]:
        """Metadata only — works while locked. Never includes plaintext."""
        rows = []
        for name in self.names():
            meta = self._data["secrets"][name]
            rows.append(
                {
                    "name": name,
                    "description": meta.get("description", ""),
                    "updated": meta.get("updated", ""),
                    "source": meta.get("source", SOURCE_MANUAL),
                }
            )
        return rows

    def exists(self, name: str) -> bool:
        return name in self._data["secrets"]

    def reveal(self, name: str) -> str:
        value, _ = self._open_blob(name)
        return value

    def resolve(self, name: str) -> tuple[str, dict | None]:
        """Return (value, policy) for use by ``bv run`` so it can enforce policy."""
        return self._open_blob(name)

    def _open_blob(self, name: str) -> tuple[str, dict | None]:
        cipher = self._require_unlocked()
        if name not in self._data["secrets"]:
            raise VaultError(f"No such secret: '{name}'")
        token = self._data["secrets"][name]["ciphertext"]
        return _decode_blob(cipher.decrypt(token), expected_name=name)

    def get_policy(self, name: str) -> dict | None:
        return self._open_blob(name)[1]

    def set_policy(self, name: str, allow_commands: list[str], allow_hosts: list[str]) -> None:
        cipher = self._require_unlocked()
        if name not in self._data["secrets"]:
            raise VaultError(f"No such secret: '{name}'")
        value, _ = self._open_blob(name)
        policy = None
        if allow_commands or allow_hosts:
            policy = {"allow_commands": list(allow_commands), "allow_hosts": list(allow_hosts)}
        meta = self._data["secrets"][name]
        meta["ciphertext"] = cipher.encrypt(_encode_blob(name, value, policy))
        meta["restricted"] = bool(policy)  # plaintext display hint only
        meta["updated"] = store.now_iso()
        store.save(self._path, self._data)

    # -- writes (require unlock) ------------------------------------------ #
    def _put(self, name: str, value: str, description: str, source: str,
             policy: dict | None = None) -> None:
        cipher = self._require_unlocked()
        if policy is None and name in self._data["secrets"]:
            # Preserve an existing usage policy when overwriting, so `set` and
            # `import` cannot silently strip a restriction.
            try:
                _, policy = self._open_blob(name)
            except VaultError:
                policy = None
        self._data["secrets"][name] = {
            "ciphertext": cipher.encrypt(_encode_blob(name, value, policy)),
            "description": description or "",
            "updated": store.now_iso(),
            "source": source,
            "restricted": bool(policy),
        }
        store.save(self._path, self._data)

    def add(self, name: str, value: str, description: str = "",
            source: str = SOURCE_MANUAL) -> None:
        if not name:
            raise VaultError("A secret needs a name.")
        if not value:
            raise VaultError("Refusing to store an empty value.")
        self._put(name, value, description, source)

    def generate(self, name: str, length: int = 32, description: str = "") -> None:
        if length < 1:
            raise VaultError("Length must be at least 1.")
        value = "".join(_random.choice(_ALPHABET) for _ in range(length))
        self._put(name, value, description, SOURCE_GENERATED)

    def set_description(self, name: str, description: str) -> None:
        self._require_unlocked()
        if name not in self._data["secrets"]:
            raise VaultError(f"No such secret: '{name}'")
        self._data["secrets"][name]["description"] = description or ""
        self._data["secrets"][name]["updated"] = store.now_iso()
        store.save(self._path, self._data)

    def delete(self, name: str) -> None:
        self._require_unlocked()  # deletion is a privileged change, not anonymous
        if name not in self._data["secrets"]:
            raise VaultError(f"No such secret: '{name}'")
        del self._data["secrets"][name]
        store.save(self._path, self._data)
