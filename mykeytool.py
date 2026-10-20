"""
Simulador interactivo por línea de comandos (CLI) de Java Keytool.
Permite generar pares de claves RSA, almacenes cifrados multicapa,
solicitudes de firma de certificados (CSR) y certificados X.509.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import sys
from pathlib import Path
from typing import Any

# Importamos las excepciones y funciones auxiliares desde keystore.py
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


# ==============================================================================
# Configuración del Analizador de Argumentos (CLI con argparse)
# ==============================================================================
def build_parser() -> argparse.ArgumentParser:
    """
    Configura y devuelve el analizador de argumentos de línea de comandos.
    Agrupa los comandos en un grupo mutuamente excluyente (--genkey, --certreq, etc.)
    y permite opciones adicionales como --store / --keystore, --alias y --file.
    """
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador Python de Java Keytool: crea almacenes cifrados, claves RSA, certificados y solicitudes CSR.",
    )
    
    # Comandos principales: solo se puede ejecutar uno a la vez (mutuamente excluyentes)
    commands = parser.add_mutually_exclusive_group(required=True)
    
    # 1. Generación de claves (admite --genkey y --genkeypair como en Java Keytool)
    commands.add_argument(
        "--genkey",
        "--genkeypair",
        action="store_true",
        dest="genkey",
        help="Genera un par de claves RSA de 2048 bits con certificado autofirmado y lo almacena.",
    )
    
    # 2. Generación de CSR para pedir firma a una Autoridad de Certificación
    commands.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de firma de certificado CSR en formato PEM.",
    )
    
    # --- Comandos de Ampliación ---
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

    # Argumentos opcionales para parametrizar rutas y alias
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
        help="Alias de la clave (opcional; si se omite o se deja en blanco, el valor por defecto es 'mykey').",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Ruta de archivo de entrada o salida (para --certreq, --exportcert o --printcert).",
    )
    return parser


# ==============================================================================
# Funciones Auxiliares para Captura Segura de Contraseñas y Datos
# ==============================================================================
def _resolve_alias(alias_arg: str | None, prompt: str = "Alias de la clave [mykey]: ") -> str:
    """
    Obtiene y valida el alias de la clave.
    Siguiendo la especificación oficial de Java Keytool:
    - Si no se especifica o se pulsa Enter en blanco, el valor por defecto es 'mykey'.
    - El alias es insensible a mayúsculas y minúsculas (se normaliza en minúsculas).
    """
    if alias_arg is not None and alias_arg.strip():
        raw_alias = alias_arg.strip()
    else:
        raw_alias = input(prompt).strip()
    if not raw_alias:
        raw_alias = "mykey"
    return validate_alias(raw_alias).lower()
def _ask_password(prompt: str) -> str:
    """
    Pide una contraseña usando getpass (sin mostrarla en pantalla).
    Valida la restricción estricta de Java Keytool: longitud mínima de 6 caracteres exactos.
    Permite cualquier carácter Unicode y espacios en blanco.
    """
    password = getpass.getpass(prompt)
    if len(password) < 6:
        raise ValueError("La contraseña es demasiado corta: debe tener al menos 6 caracteres (Keystore password is too short - must be at least 6 characters).")
    return password


def _ask_new_password(label: str) -> str:
    """Solicita una contraseña nueva y pide confirmarla para evitar erratas de escritura."""
    password = _ask_password(f"Contraseña nueva del {label}: ")
    confirmation = getpass.getpass(f"Confirma la contraseña del {label}: ")
    if password != confirmation:
        raise ValueError("Las contraseñas no coinciden.")
    return password


def _read_distinguished_name() -> list[tuple[str, str]]:
    """
    Solicita al usuario las 6 preguntas interactivas del Nombre Distinguido (DName) para el certificado/CSR.
    Igual que en Java Keytool:
    - Todos los campos se pueden dejar vacíos pulsando Enter.
    - El campo CN toma el valor por defecto literal 'Unknown'.
    - Los campos de organización y localidad opcionales vacíos se omiten o toman 'Unknown'.
    - El código de país (C) se normaliza a mayúsculas de 2 letras (ej. ES).
    """
    fields = (
        ("CN", "Nombre y apellidos o nombre común (CN) [Unknown]"),
        ("OU", "Nombre de la unidad organizativa (OU) [Unknown]"),
        ("O", "Nombre de la organización (O) [Unknown]"),
        ("L", "Nombre de la ciudad o localidad (L) [Unknown]"),
        ("ST", "Nombre del estado o provincia (ST) [Unknown]"),
        ("C", "Código de país de dos letras (C) [Unknown]"),
    )
    values: list[tuple[str, str]] = []
    for key, label in fields:
        value = input(f"{label}: ").strip()
        if key == "CN" and not value:
            # Si se deja vacío el CN, toma 'Unknown' como en Java Keytool en vez de fallar
            value = "Unknown"
        if not value:
            # Los campos opcionales vacíos se omiten
            continue
        if key == "C":
            value = value.upper()
            if len(value) != 2 or not value.isalpha():
                raise ValueError("El país debe ser un código de dos letras, por ejemplo ES.")
        values.append((key, value))
    return values


def _make_subject(values: list[tuple[str, str]]):
    """Construye un objeto x509.Name a partir de la lista de tuplas (clave, valor)."""
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


# ==============================================================================
# Operación 1: Generación de Claves y Almacén (--genkey / --genkeypair)
# ==============================================================================
def _generate_key(store_path: Path, alias_arg: str | None = None) -> None:
    """
    Flujo para crear un par RSA de 2048 bits:
    1. Si el almacén existe, pide la clave para abrirlo; si no, pide una nueva clave para crearlo.
    2. Pide y valida el alias (rechaza si ya existe).
    3. Pide los datos de identidad (DName).
    4. Pide la contraseña propia de este alias para proteger su clave privada.
    5. Genera la clave RSA 2048 bits y el certificado autofirmado X.509.
    6. Guarda todo cifrado en disco de forma segura.
    """
    if store_path.exists():
        store_password = _ask_password("Contraseña del KeyStore: ")
        contents = load_store(store_path, store_password)
    else:
        store_password = _ask_new_password("KeyStore")
        contents = {"aliases": {}}

    # Obtenemos el alias por argumento CLI o por prompt interactivo (por defecto 'mykey')
    alias = _resolve_alias(alias_arg)
    aliases: dict[str, Any] = contents.setdefault("aliases", {})
    if alias in aliases:
        raise AliasExistsError(f"El alias '{alias}' ya existe en el almacén.")

    # Captura de datos del titular y contraseña de la clave privada
    subject_values = _read_distinguished_name()
    alias_password = _ask_new_password(f"alias '{alias}'")
    
    # Generamos los componentes criptográficos (validez por defecto: 90 días en Keytool)
    encrypted_key, public_key_pem, cert_pem = generate_key_materials(alias_password, subject_values)

    dname_str = ", ".join(f"{k}={v}" for k, v in subject_values)
    aliases[alias] = {
        "subject": subject_values,
        "dname": dname_str,
        "private_key": base64.b64encode(encrypted_key).decode("ascii"),
        "public_key": public_key_pem,
        "certificate": cert_pem,
    }
    
    # Guardamos el almacén actualizado cifrado con Fernet + PBKDF2
    save_store(store_path, store_password, contents)
    print(f"Par RSA de 2048 bits guardado con el alias '{alias}' en {store_path}.")


# ==============================================================================
# Operación 2: Generación de Solicitud de Certificado CSR (--certreq)
# ==============================================================================
def _generate_csr(store_path: Path, alias_arg: str | None = None, file_arg: Path | None = None) -> None:
    """
    Flujo para generar una solicitud de firma CSR:
    1. Desbloquea el KeyStore con su contraseña.
    2. Busca el registro del alias especificado.
    3. Pide la contraseña individual del alias para descifrar la clave privada.
    4. Reconstruye el DName y genera la solicitud X.509 firmada con SHA-256.
    5. Exporta el archivo <alias>.csr en formato estándar PEM.
    """
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    alias = _resolve_alias(alias_arg)
    record = contents.get("aliases", {}).get(alias)
    if record is None:
        raise AliasNotFoundError(f"No existe el alias '{alias}' en el almacén.")

    # Pedimos la clave de este alias concreto para descifrar la clave privada
    alias_password = _ask_password(f"Contraseña del alias '{alias}': ")
    try:
        encrypted_key = base64.b64decode(record["private_key"], validate=True)
        subject_values = record["subject"]
        subject = _make_subject([(str(key), str(value)) for key, value in subject_values])
    except (KeyError, TypeError, ValueError) as error:
        raise StoreError("El registro del alias está dañado.") from error

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    # Desciframos la clave privada RSA
    private_key = decrypt_private_key(encrypted_key, alias_password)
    
    # Construimos y firmamos digitalmente la solicitud CSR
    request = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    csr_path = file_arg if file_arg is not None else Path(f"{alias}.csr")
    csr_path.write_bytes(request.public_bytes(serialization.Encoding.PEM))
    print(f"Solicitud CSR creada: {csr_path}")


# ==============================================================================
# Operación 3 [Ampliación]: Listar Entradas del Almacén (--list)
# ==============================================================================
def _list_store(store_path: Path) -> None:
    """
    Muestra en consola un resumen de todas las entradas del almacén:
    nombre del alias, tipo de entrada (PrivateKeyEntry), DName y huella digital SHA-256.
    Emula el comportamiento oficial de `keytool -list -v` de Java.
    """
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

        # Extraemos la huella digital SHA-256 del certificado si está guardado
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


# ==============================================================================
# Operación 4 [Ampliación]: Exportar Certificado Digital (--exportcert / --export)
# ==============================================================================
def _export_cert(store_path: Path, alias_arg: str | None = None, file_arg: Path | None = None) -> None:
    """
    Exporta el certificado público X.509 de un alias a un fichero `.crt` independiente.
    Este archivo contiene únicamente la clave pública y los datos de identidad.
    """
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    alias = _resolve_alias(alias_arg)
    record = contents.get("aliases", {}).get(alias)
    if record is None:
        raise AliasNotFoundError(f"No existe el alias '{alias}' en el almacén.")

    cert_pem = record.get("certificate")
    if not cert_pem:
        raise StoreError(f"El alias '{alias}' no tiene un certificado X.509 exportable.")

    out_path = file_arg if file_arg is not None else Path(f"{alias}.crt")
    out_path.write_bytes(cert_pem.encode("ascii"))
    print(f"Certificado exportado en: {out_path}")


# ==============================================================================
# Operación 5 [Ampliación]: Inspeccionar Archivo de Certificado o CSR (--printcert)
# ==============================================================================
def _print_cert(file_arg: Path | None = None) -> None:
    """
    Permite visualizar los datos técnicos de cualquier certificado `.crt` o solicitud `.csr`.
    No requiere contraseña porque la información de certificados y CSR es pública.
    """
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


# ==============================================================================
# Operación 6 [Ampliación]: Borrado Seguro de un Alias (--delete)
# ==============================================================================
def _delete_alias(store_path: Path, alias_arg: str | None = None) -> None:
    """
    Elimina una clave o entrada del almacén solicitando confirmación previa.
    """
    store_password = _ask_password("Contraseña del KeyStore: ")
    contents = load_store(store_path, store_password)
    raw_alias = alias_arg.strip() if alias_arg is not None else input("Alias a eliminar: ").strip()
    alias = validate_alias(raw_alias).lower()
    aliases: dict[str, Any] = contents.get("aliases", {})
    if alias not in aliases:
        raise AliasNotFoundError(f"No existe el alias '{alias}' en el almacén.")

    # Confirmación de seguridad
    confirmation = input(f"¿Desea realmente eliminar la entrada con el alias '{alias}'? (s/n): ").strip().lower()
    if confirmation not in ("s", "si", "sí", "y", "yes"):
        print("Operación de borrado cancelada.")
        return

    del aliases[alias]
    save_store(store_path, store_password, contents)
    print(f"La entrada con alias '{alias}' ha sido eliminada del almacén.")


# ==============================================================================
# Punto de Entrada Principal (main)
# ==============================================================================
def main(argv: list[str] | None = None) -> int:
    """
    Parsea los argumentos y ejecuta la operación solicitada.
    Controla todas las excepciones esperadas para mostrar mensajes claros y
    retornar códigos de salida adecuados (1 para error, 130 para cancelación).
    """
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
        # Error controlado de usuario o formato: imprimimos en stderr sin traceback
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        # El usuario pulsó Ctrl+C para cancelar
        print("\nOperación cancelada.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

