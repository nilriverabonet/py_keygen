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
    format_cert_info,
    format_csr_info,
    generate_key_materials,
    load_store,
    save_store,
    validate_alias,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador Python de Java Keytool: crea almacenes cifrados, claves RSA, certificados y solicitudes CSR.",
    )
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument(
        "--genkey",
        "--genkeypair",
        action="store_true",
        dest="genkey",
        help="Genera un par de claves RSA de 2048 bits con certificado autofirmado y lo almacena.",
    )
    commands.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de firma de certificado CSR en formato PEM.",
    )
    commands.add_argument(
        "--list",
        action="store_true",
        help="[Ampliación] Muestra el listado de alias, tipo de entrada y huellas digitales del KeyStore.",
    )
    commands.add_argument(
        "--exportcert",
        "--export",
        action="store_true",
        dest="exportcert",
        help="[Ampliación] Exporta el certificado X.509 de un alias a un archivo .crt.",
    )
    commands.add_argument(
        "--printcert",
        action="store_true",
        help="[Ampliación] Imprime la información criptográfica de un certificado (.crt) o solicitud (.csr).",
    )
    commands.add_argument(
        "--delete",
        action="store_true",
        help="[Ampliación] Elimina un alias del KeyStore de forma segura.",
    )
    parser.add_argument(
        "--store",
        "--keystore",
        type=Path,
        default=Path("keystore.pystore"),
        dest="store",
        help="Ruta del almacén cifrado (por defecto: keystore.pystore).",
    )
    parser.add_argument(
        "--alias",
        type=str,
        default=None,
        help="Alias de la clave (opcional; si se omite se solicitará de forma interactiva).",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Ruta de archivo de entrada o salida (para --certreq, --exportcert o --printcert).",
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


def _generate_key(store_path: Path, alias_arg: str | None = None) -> None:
    if store_path.exists():
        store_password = _ask_password("Contraseña del KeyStore: ")
        contents = load_store(store_path, store_password)
    else:
        store_password = _ask_new_password("KeyStore")
        contents = {"aliases": {}}

    raw_alias = alias_arg if alias_arg is not None else input("Alias de la clave: ").strip()
    alias = validate_alias(raw_alias)
    aliases: dict[str, Any] = contents.setdefault("aliases", {})
    if alias in aliases:
        raise AliasExistsError(f"El alias '{alias}' ya existe en el almacén.")

    subject_values = _read_distinguished_name()
    alias_password = _ask_new_password(f"alias '{alias}'")
    encrypted_key, public_key_pem, cert_pem = generate_key_materials(alias_password, subject_values)

    dname_str = ", ".join(f"{k}={v}" for k, v in subject_values)
    aliases[alias] = {
        "subject": subject_values,
        "dname": dname_str,
        "private_key": base64.b64encode(encrypted_key).decode("ascii"),
        "public_key": public_key_pem,
        "certificate": cert_pem,
    }
    save_store(store_path, store_password, contents)
    print(f"Par RSA de 2048 bits guardado con el alias '{alias}' en {store_path}.")


def _generate_csr(store_path: Path, alias_arg: str | None = None, file_arg: Path | None = None) -> None:
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    raw_alias = alias_arg if alias_arg is not None else input("Alias de la clave: ").strip()
    alias = validate_alias(raw_alias)
    record = contents.get("aliases", {}).get(alias)
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
    csr_path = file_arg if file_arg is not None else Path(f"{alias}.csr")
    csr_path.write_bytes(request.public_bytes(serialization.Encoding.PEM))
    print(f"Solicitud CSR creada: {csr_path}")


def _list_store(store_path: Path) -> None:
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    aliases: dict[str, Any] = contents.get("aliases", {})

    print(f"\nTipo de almacén: PYSTORE (Simulador Java Keytool)")
    print(f"Almacén: {store_path}")
    print(f"El almacén contiene {len(aliases)} entrada(s):\n")
    if not aliases:
        print("No hay entradas en el almacén.")
        return

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    for alias, record in sorted(aliases.items()):
        print(f"Nombre de alias: {alias}")
        print("Tipo de entrada: ClavePrivada (PrivateKeyEntry)")
        dname = record.get("dname")
        if not dname and "subject" in record:
            dname = ", ".join(f"{k}={v}" for k, v in record["subject"])
        print(f"Propietario (DName): {dname or 'N/A'}")

        cert_pem = record.get("certificate")
        if cert_pem:
            try:
                cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
                sha256_fp = ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))
                valid_until = cert.not_valid_after_utc.strftime("%d/%m/%Y")
                print(f"Certificado autofirmado: Válido hasta {valid_until}")
                print(f"Huella digital SHA-256: {sha256_fp}")
            except Exception:
                print("Huella digital SHA-256: (Certificado no legible)")
        else:
            print("Certificado: (No disponible en esta entrada)")
        print("-" * 50)


def _export_cert(store_path: Path, alias_arg: str | None = None, file_arg: Path | None = None) -> None:
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    raw_alias = alias_arg if alias_arg is not None else input("Alias de la clave: ").strip()
    alias = validate_alias(raw_alias)
    record = contents.get("aliases", {}).get(alias)
    if record is None:
        raise AliasNotFoundError(f"No existe el alias '{alias}' en el almacén.")

    cert_pem = record.get("certificate")
    if not cert_pem:
        raise StoreError(f"El alias '{alias}' no tiene un certificado X.509 exportable.")

    out_path = file_arg if file_arg is not None else Path(f"{alias}.crt")
    out_path.write_bytes(cert_pem.encode("ascii"))
    print(f"Certificado exportado en: {out_path}")


def _print_cert(file_arg: Path | None = None) -> None:
    if file_arg is None:
        path_str = input("Ruta del archivo (.crt o .csr): ").strip()
        file_arg = Path(path_str)
    if not file_arg.exists():
        raise FileNotFoundError(f"No se encuentra el archivo: {file_arg}")

    data = file_arg.read_bytes()
    if b"CERTIFICATE REQUEST" in data:
        info = format_csr_info(data)
    elif b"CERTIFICATE" in data:
        info = format_cert_info(data)
    else:
        try:
            info = format_cert_info(data)
        except ValueError:
            info = format_csr_info(data)

    print(f"\nArchivo: {file_arg}\n{info}")


def _delete_alias(store_path: Path, alias_arg: str | None = None) -> None:
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    raw_alias = alias_arg if alias_arg is not None else input("Alias a eliminar: ").strip()
    alias = validate_alias(raw_alias)
    aliases: dict[str, Any] = contents.get("aliases", {})
    if alias not in aliases:
        raise AliasNotFoundError(f"No existe el alias '{alias}' en el almacén.")

    confirmation = input(f"¿Desea realmente eliminar la entrada con el alias '{alias}'? (s/n): ").strip().lower()
    if confirmation not in ("s", "si", "sí", "y", "yes"):
        print("Operación de borrado cancelada.")
        return

    del aliases[alias]
    save_store(store_path, store_password, contents)
    print(f"La entrada con alias '{alias}' ha sido eliminada del almacén.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.genkey:
            _generate_key(args.store, args.alias)
        elif args.certreq:
            _generate_csr(args.store, args.alias, args.file)
        elif args.list:
            _list_store(args.store)
        elif args.exportcert:
            _export_cert(args.store, args.alias, args.file)
        elif args.printcert:
            _print_cert(args.file)
        elif args.delete:
            _delete_alias(args.store, args.alias)
    except (StoreError, ValueError, OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nOperación cancelada.", file=sys.stderr)
        return 130
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
