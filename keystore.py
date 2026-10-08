"""Encrypted storage helpers for the Python Keytool simulator."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


class StoreError(Exception):
    """Base class for expected keystore errors."""


class StorePasswordError(StoreError):
    """The keystore password is incorrect, or the file was altered."""


class StoreCorruptedError(StoreError):
    """The keystore file is missing, malformed, or unreadable."""


class AliasExistsError(StoreError):
    """An alias already exists in the keystore."""


class AliasNotFoundError(StoreError):
    """The requested alias does not exist."""


class AliasPasswordError(StoreError):
    """The alias password is incorrect or its private key is damaged."""


def validate_alias(alias: str) -> str:
    """Return a safe alias or raise ValueError for unsupported characters."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", alias) or alias in {".", ".."}:
        raise ValueError("El alias solo puede contener letras, números, punto, guion y guion bajo.")
    return alias


def _crypto():
    try:
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as error:
        raise RuntimeError(
            "Falta la dependencia 'cryptography'. Instálala con: python -m pip install -r requirements.txt"
        ) from error
    return Fernet, InvalidToken, hashes, PBKDF2HMAC


def _fernet(password: str, salt: bytes):
    Fernet, _, hashes, PBKDF2HMAC = _crypto()
    derivation = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = base64.urlsafe_b64encode(derivation.derive(password.encode("utf-8")))
    return Fernet(key)


def load_store(path: Path, password: str) -> dict[str, Any]:
    """Decrypt and return the alias records from a keystore file."""
    if not path.exists():
        raise StoreCorruptedError(f"No se encuentra el almacén: {path}")

    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if envelope.get("version") != 1:
            raise ValueError("versión de almacén desconocida")
        salt = base64.b64decode(envelope["salt"], validate=True)
        token = base64.b64decode(envelope["data"], validate=True)
        if len(salt) != 16:
            raise ValueError("sal inválida")
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        raise StoreCorruptedError("El almacén está dañado o tiene un formato no válido.") from error

    Fernet, InvalidToken, _, _ = _crypto()
    try:
        plaintext = _fernet(password, salt).decrypt(token)
    except InvalidToken as error:
        raise StorePasswordError("Contraseña incorrecta o almacén alterado.") from error

    try:
        contents = json.loads(plaintext.decode("utf-8"))
        if not isinstance(contents, dict) or not isinstance(contents.get("aliases"), dict):
            raise ValueError("estructura de almacén inválida")
        return contents
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise StoreCorruptedError("El contenido descifrado del almacén no es válido.") from error


def save_store(path: Path, password: str, contents: dict[str, Any]) -> None:
    """Encrypt the store and replace its file atomically."""
    salt = os.urandom(16)
    plaintext = json.dumps(contents, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = _fernet(password, salt).encrypt(plaintext)
    envelope = {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": base64.b64encode(token).decode("ascii"),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(envelope, temporary_file, separators=(",", ":"))
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def create_private_key(alias_password: str) -> bytes:
    """Generate a 2048-bit RSA private key encrypted by the alias password."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as error:
        raise RuntimeError(
            "Falta la dependencia 'cryptography'. Instálala con: python -m pip install -r requirements.txt"
        ) from error

    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(alias_password.encode("utf-8")),
    )


def decrypt_private_key(encrypted_key: bytes, alias_password: str):
    """Load a private key, translating password/PEM failures to a domain error."""
    try:
        from cryptography.hazmat.primitives import serialization

        return serialization.load_pem_private_key(encrypted_key, password=alias_password.encode("utf-8"))
    except (ImportError, TypeError, ValueError) as error:
        if isinstance(error, ImportError):
            raise RuntimeError(
                "Falta la dependencia 'cryptography'. Instálala con: python -m pip install -r requirements.txt"
            ) from error
        raise AliasPasswordError("Contraseña del alias incorrecta o clave privada dañada.") from error
