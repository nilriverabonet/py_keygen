"""Interactive command-line simulator of the essential Java keytool features."""

from __future__ import annotations

import argparse
import base64
import getpass
import sys
from pathlib import Path
from typing import Any

from keystore import (
    AliasExistsError,
    AliasNotFoundError,
    StoreError,
    create_private_key,
    decrypt_private_key,
    load_store,
    save_store,
    validate_alias,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Simulador Python de keytool: crea almacenes cifrados y solicitudes CSR."
    )
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--genkey", action="store_true", help="Genera una clave RSA de 2048 bits y la guarda.")
    commands.add_argument("--certreq", action="store_true", help="Genera una solicitud de certificado CSR en PEM.")
    parser.add_argument(
        "--store",
        type=Path,
        default=Path("keystore.pystore"),
        help="Ruta del almacén cifrado (por defecto: keystore.pystore).",
    )
    return parser


def _ask_password(prompt: str) -> str:
    password = getpass.getpass(prompt)
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    return password


def _ask_new_password(label: str) -> str:
    password = _ask_password(f"Contraseña nueva del {label}: ")
    confirmation = getpass.getpass(f"Confirma la contraseña del {label}: ")
    if password != confirmation:
        raise ValueError("Las contraseñas no coinciden.")
    return password


def _read_distinguished_name() -> list[tuple[str, str]]:
    fields = (
        ("CN", "Nombre común (CN)"),
        ("OU", "Unidad organizativa (OU)"),
        ("O", "Organización (O)"),
        ("L", "Localidad (L)"),
        ("ST", "Provincia o estado (ST)"),
        ("C", "País, código de 2 letras (C)"),
    )
    values: list[tuple[str, str]] = []
    for key, label in fields:
        value = input(f"{label}: ").strip()
        if key == "CN" and not value:
            raise ValueError("El campo CN no puede estar vacío.")
        if not value:
            continue
        if key == "C" and (len(value) != 2 or not value.isalpha()):
            raise ValueError("El país debe ser un código de dos letras, por ejemplo ES.")
        values.append((key, value))
    if not values:
        raise ValueError("Debe introducir al menos el campo CN.")
    return values


def _make_subject(values: list[tuple[str, str]]):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    name_oids = {
        "CN": NameOID.COMMON_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "C": NameOID.COUNTRY_NAME,
    }
    return x509.Name(
        [
            x509.NameAttribute(name_oids[key], value)
            for key, value in values
            if value and key in name_oids
        ]
    )


def _generate_key(store_path: Path) -> None:
    if store_path.exists():
        store_password = _ask_password("Contraseña del KeyStore: ")
        contents = load_store(store_path, store_password)
    else:
        store_password = _ask_new_password("KeyStore")
        contents = {"aliases": {}}

    alias = validate_alias(input("Alias de la clave: ").strip())
    aliases: dict[str, Any] = contents["aliases"]
    if alias in aliases:
        raise AliasExistsError(f"El alias '{alias}' ya existe en el almacén.")

    subject_values = _read_distinguished_name()
    alias_password = _ask_new_password(f"alias '{alias}'")
    encrypted_key = create_private_key(alias_password)
    aliases[alias] = {
        "subject": subject_values,
        "private_key": base64.b64encode(encrypted_key).decode("ascii"),
    }
    save_store(store_path, store_password, contents)
    print(f"Par RSA de 2048 bits guardado con el alias '{alias}' en {store_path}.")


def _generate_csr(store_path: Path) -> None:
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    alias = validate_alias(input("Alias de la clave: ").strip())
    record = contents["aliases"].get(alias)
    if record is None:
        raise AliasNotFoundError(f"No existe el alias '{alias}' en el almacén.")

    alias_password = _ask_password(f"Contraseña del alias '{alias}': ")
    try:
        encrypted_key = base64.b64decode(record["private_key"], validate=True)
        subject_values = record["subject"]
        subject = _make_subject([(str(key), str(value)) for key, value in subject_values])
    except (KeyError, TypeError, ValueError) as error:
        raise StoreError("El registro del alias está dañado.") from error

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = decrypt_private_key(encrypted_key, alias_password)
    request = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    csr_path = Path(f"{alias}.csr")
    csr_path.write_bytes(request.public_bytes(serialization.Encoding.PEM))
    print(f"Solicitud CSR creada: {csr_path}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.genkey:
            _generate_key(args.store)
        else:
            _generate_csr(args.store)
    except (StoreError, ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nOperación cancelada.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
