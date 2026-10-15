"""Encrypted storage helpers for the Python Keytool simulator."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


# ==============================================================================
# Clases de Excepciones Propias (Control de Errores)
# ==============================================================================
# Definimos nuestras propias excepciones heredando de StoreError.
# Así podemos capturarlas de forma centralizada en mykeytool.py y mostrar
# mensajes amigables al usuario sin soltar tracebacks feos de Python.

class StoreError(Exception):
    """Clase base para todos los errores controlados del almacén."""


class StorePasswordError(StoreError):
    """Se lanza cuando la contraseña del KeyStore es incorrecta o el archivo fue manipulado."""


class StoreCorruptedError(StoreError):
    """Se lanza cuando el archivo del KeyStore no existe o su formato JSON/Base64 está roto."""


class AliasExistsError(StoreError):
    """Se lanza si intentamos registrar un alias que ya está ocupado dentro del almacén."""


class AliasNotFoundError(StoreError):
    """Se lanza cuando se busca un alias que no existe en el KeyStore."""


class AliasPasswordError(StoreError):
    """Se lanza cuando la contraseña de la clave privada del alias no es correcta."""


# ==============================================================================
# Validación de Seguridad para Nombres de Alias
# ==============================================================================
def validate_alias(alias: str) -> str:
    """
    Comprueba que el alias solo tenga caracteres seguros.
    Evitamos barras o '..' para que nadie intente ataques de Path Traversal
    al generar archivos en disco como '<alias>.csr' o '<alias>.crt'.
    """
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", alias) or alias in {".", ".."}:
        raise ValueError("El alias solo puede contener letras, números, punto, guion y guion bajo.")
    return alias


# ==============================================================================
# Funciones Criptográficas Internas (PBKDF2 y Fernet)
# ==============================================================================
def _crypto():
    """Importa de forma diferida la librería cryptography para avisar si falta."""
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
    """
    Genera el cifrador Fernet a partir de la contraseña del usuario.
    Usamos PBKDF2 con SHA-256, sal aleatoria y 600.000 iteraciones (siguiendo OWASP)
    para estirar la clave y protegernos contra ataques de fuerza bruta en GPU.
    """
    Fernet, _, hashes, PBKDF2HMAC = _crypto()
    derivation = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # Fernet necesita una clave simétrica de 256 bits (32 bytes)
        salt=salt,          # Sal aleatoria de 16 bytes para evitar ataques con tablas Rainbow
        iterations=600_000, # Ralentiza enormemente los intentos de fuerza bruta
    )
    key = base64.urlsafe_b64encode(derivation.derive(password.encode("utf-8")))
    return Fernet(key)


# ==============================================================================
# Persistencia del Almacén: Carga y Guardado Seguro
# ==============================================================================
def load_store(path: Path, password: str) -> dict[str, Any]:
    """
    Lee y descifra el archivo del almacén (keystore.pystore / json).
    Verifica que el archivo exista, extrae la sal y el token cifrado, y
    lo descifra con Fernet. Si la contraseña no coincide, Fernet lanza InvalidToken.
    """
    if not path.exists():
        raise StoreCorruptedError(f"No se encuentra el almacén: {path}")

    # 1. Leemos el sobre exterior en formato JSON
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

    # 2. Desciframos con Fernet (AES-128-CBC + HMAC de autenticación)
    Fernet, InvalidToken, _, _ = _crypto()
    try:
        plaintext = _fernet(password, salt).decrypt(token)
    except InvalidToken as error:
        # Si la contraseña es errónea o el archivo se alteró, el HMAC no cuadra
        raise StorePasswordError("Contraseña incorrecta o almacén alterado.") from error

    # 3. Parseamos el JSON interior descifrado con los alias y certificados
    try:
        contents = json.loads(plaintext.decode("utf-8"))
        if not isinstance(contents, dict):
            raise ValueError("estructura de almacén inválida")
        # Compatibilidad: si el JSON usa 'keys' en vez de 'aliases', lo normalizamos
        if "aliases" not in contents and "keys" in contents and isinstance(contents["keys"], dict):
            contents["aliases"] = contents["keys"]
        if not isinstance(contents.get("aliases"), dict):
            raise ValueError("estructura de almacén inválida")
        return contents
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise StoreCorruptedError("El contenido descifrado del almacén no es válido.") from error


def save_store(path: Path, password: str, contents: dict[str, Any]) -> None:
    """
    Cifra y guarda el almacén en disco de forma atómica.
    Escribimos primero en un archivo temporal y luego hacemos os.replace()
    para garantizar que nunca nos quede un archivo corrupto si el guardado se corta.
    """
    # Generamos una sal criptográfica nueva de 16 bytes para este guardado
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
        # Creamos archivo temporal en el mismo directorio para asegurar reemplazo atómico
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temporary_file:
            temporary_path = temporary_file.name
            json.dump(envelope, temporary_file, separators=(",", ":"))
        os.replace(temporary_path, path)
    finally:
        # Limpieza por si ocurrió algún error antes de mover el archivo
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


# ==============================================================================
# Generación de Material Criptográfico (RSA 2048, Claves y Certificados)
# ==============================================================================
def generate_key_materials(
    alias_password: str,
    subject_values: list[tuple[str, str]] | None = None,
    days_valid: int = 365,
) -> tuple[bytes, str, str]:
    """
    Genera el par de claves RSA (2048 bits, e=65537) y un certificado autofirmado inicial.
    Retorna:
      - Clave privada cifrada con la contraseña del alias en formato PKCS#8 PEM.
      - Clave pública en formato PEM (SubjectPublicKeyInfo).
      - Certificado digital autofirmado X.509 v3 en formato PEM.
    """
    try:
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as error:
        raise RuntimeError(
            "Falta la dependencia 'cryptography'. Instálala con: python -m pip install -r requirements.txt"
        ) from error

    # 1. Generamos el par asimétrico RSA de 2048 bits
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2048)

    # 2. Ciframos la clave privada bajo el estándar PKCS#8 usando la clave del alias (AES-256)
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(alias_password.encode("utf-8")),
    )

    # 3. Extraemos la clave pública en formato PEM
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    # 4. Mapeamos los campos del DName (CN, OU, O, etc.) a los identificadores OID de X.509
    name_oids = {
        "CN": NameOID.COMMON_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "L": NameOID.LOCALITY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "C": NameOID.COUNTRY_NAME,
    }
    attributes = []
    if subject_values:
        for k, v in subject_values:
            if v and k in name_oids:
                attributes.append(x509.NameAttribute(name_oids[k], v))
    if not attributes:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, "Keytool Simulator User"))

    # 5. Creamos el certificado autofirmado inicial (como hace Java keytool con -genkeypair)
    subject_name = x509.Name(attributes)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name) # En autofirmados, el emisor y el sujeto son el mismo
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256()) # Firmado con la clave privada y SHA-256
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    return encrypted_key, public_key_pem, cert_pem


def create_private_key(alias_password: str) -> bytes:
    """Función de compatibilidad para generar la clave privada cifrada."""
    encrypted_key, _, _ = generate_key_materials(alias_password)
    return encrypted_key


def decrypt_private_key(encrypted_key: bytes, alias_password: str):
    """
    Descifra la clave privada PKCS#8 usando la contraseña del alias.
    Si la contraseña es incorrecta, captura la excepción y lanza AliasPasswordError.
    """
    try:
        from cryptography.hazmat.primitives import serialization

        return serialization.load_pem_private_key(encrypted_key, password=alias_password.encode("utf-8"))
    except (ImportError, TypeError, ValueError) as error:
        if isinstance(error, ImportError):
            raise RuntimeError(
                "Falta la dependencia 'cryptography'. Instálala con: python -m pip install -r requirements.txt"
            ) from error
        raise AliasPasswordError("Contraseña del alias incorrecta o clave privada dañada.") from error


# ==============================================================================
# Formateo e Inspección de Certificados X.509 y Solicitudes CSR
# ==============================================================================
def format_cert_info(cert_bytes: bytes) -> str:
    """
    Analiza un certificado X.509 (PEM o DER) y devuelve un resumen formateado
    con el sujeto, emisor, fechas de validez y huellas digitales SHA-256 / SHA-1.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError as error:
        raise RuntimeError("Falta la dependencia 'cryptography'.") from error

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
        except Exception as err:
            raise ValueError("El archivo no es un certificado X.509 válido en formato PEM o DER.") from err

    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    serial_hex = f"{cert.serial_number:X}"
    not_before = cert.not_valid_before_utc.strftime("%d/%m/%Y %H:%M:%S UTC")
    not_after = cert.not_valid_after_utc.strftime("%d/%m/%Y %H:%M:%S UTC")

    # Calculamos las huellas digitales en hexadecimal separado por dos puntos
    sha256_fp = ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))
    sha1_fp = ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA1()))
    key_size = getattr(cert.public_key(), "key_size", "Desconocido")
    key_type = "RSA" if "RSA" in type(cert.public_key()).__name__ else type(cert.public_key()).__name__
    sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "Desconocido"

    return (
        f"Propietario (Subject):   {subject_str}\n"
        f"Emisor (Issuer):         {issuer_str}\n"
        f"Número de serie:         {serial_hex}\n"
        f"Válido desde:            {not_before} hasta: {not_after}\n"
        f"Algoritmo de clave:      {key_type} ({key_size} bits)\n"
        f"Algoritmo de firma:      {sig_alg} con RSA\n"
        f"Huellas digitales del certificado:\n"
        f"     SHA-256: {sha256_fp}\n"
        f"     SHA-1:   {sha1_fp}"
    )


def format_csr_info(csr_bytes: bytes) -> str:
    """
    Analiza una solicitud de firma de certificado CSR (PKCS#10 PEM o DER)
    y devuelve la información del titular, clave pública y comprobación de firma.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError as error:
        raise RuntimeError("Falta la dependencia 'cryptography'.") from error

    try:
        csr = x509.load_pem_x509_csr(csr_bytes)
    except ValueError:
        try:
            csr = x509.load_der_x509_csr(csr_bytes)
        except Exception as err:
            raise ValueError("El archivo no es una solicitud CSR válida en formato PEM o DER.") from err

    subject_str = csr.subject.rfc4514_string()
    key_size = getattr(csr.public_key(), "key_size", "Desconocido")
    key_type = "RSA" if "RSA" in type(csr.public_key()).__name__ else type(csr.public_key()).__name__
    sig_alg = csr.signature_hash_algorithm.name.upper() if csr.signature_hash_algorithm else "Desconocido"
    is_valid = csr.is_signature_valid # Verifica si la firma interna del solicitante es legítima

    # Obtenemos la huella digital SHA-256 sobre la codificación DER binaria del CSR
    der_bytes = csr.public_bytes(serialization.Encoding.DER)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_bytes)
    sha256_fp = ":".join(f"{b:02X}" for b in digest.finalize())

    return (
        f"Solicitud de Certificado (CSR PKCS#10):\n"
        f"Sujeto (Titular):        {subject_str}\n"
        f"Algoritmo de clave:      {key_type} ({key_size} bits)\n"
        f"Algoritmo de firma:      {sig_alg} con RSA\n"
        f"Firma digital íntegra:   {'Sí (verificada correctamente)' if is_valid else 'No (firma inválida)'}\n"
        f"Huella digital SHA-256:\n"
        f"     SHA-256: {sha256_fp}"
    )


