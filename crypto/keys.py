"""
crypto/keys.py
==============
Gestion de pares de llaves Ed25519 para el SDDV.

Que hace este modulo:
  - Genera pares de llaves Ed25519 (privada + publica).
  - Guarda la llave PRIVADA cifrada en disco con AES-256-GCM + Argon2id.
    Nunca se almacena en texto plano.
  - Guarda la llave PUBLICA en formato PEM (texto claro, se puede compartir).
  - Carga ambas llaves desde disco.
  - Calcula el fingerprint de una llave publica (SHA-256 hex, 64 chars).
    El fingerprint sirve como ID de destinatario en D3 (cifrado hibrido).

Por que Ed25519:
  - Curvas elipticas de Bernstein (Curve25519). 128 bits de seguridad.
  - Llaves pequenas: privada = 32 bytes, publica = 32 bytes.
  - Firmas de 64 bytes, verificacion rapida.
  - Resistente a ataques de canal lateral por diseno.
  - Recomendado por NIST y ampliamente usado (SSH, TLS 1.3, Signal).

Como se protege la llave privada:
  - Se serializa a 32 bytes raw.
  - Se cifra con encrypt_file_with_password() de nuestro modulo AEAD.
  - La clave de cifrado se deriva del password del usuario con Argon2id
    (64 MB RAM, 3 iteraciones) — no se guarda en disco.
  - El archivo resultante es un contenedor SDDV v2 estandar.

Dependencia: pip install cryptography argon2-cffi
"""

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_public_key,
    load_der_private_key,
)


# ─────────────────────────────── constantes ──────────────────────────────────

PRIVATE_KEY_SUFFIX = ".sddv_priv"   # extension para llaves privadas cifradas
PUBLIC_KEY_SUFFIX  = ".sddv_pub"    # extension para llaves publicas PEM
KEY_FILENAME_PRIV  = "private_key"  # nombre por defecto (sin extension)
KEY_FILENAME_PUB   = "public_key"   # nombre por defecto (sin extension)


# ───────────────────────────── generacion de llaves ───────────────────────────

def generate_keypair():
    """
    Genera un par de llaves Ed25519 fresco usando el CSPRNG del SO.

    Retorna:
        (private_key, public_key) — objetos de la libreria cryptography.
        La llave privada contiene la publica; ambas se pueden serializar
        con save_private_key() y save_public_key().
    """
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return private_key, public_key


# ──────────────────────── serializacion / deserializacion ────────────────────

def _serialize_private_key_raw(private_key) -> bytes:
    """Extrae los 32 bytes raw de la llave privada Ed25519."""
    return private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )


def _serialize_public_key_pem(public_key) -> bytes:
    """Serializa la llave publica a formato PEM (texto, compartible)."""
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def _deserialize_private_key_raw(raw_bytes) -> Ed25519PrivateKey:
    """Reconstruye la llave privada desde 32 bytes raw."""
    return Ed25519PrivateKey.from_private_bytes(raw_bytes)


# ──────────────────────────── guardar en disco ────────────────────────────────

def save_private_key(private_key, path: str, password: str) -> None:
    """
    Guarda la llave privada cifrada en disco.

    La llave privada se serializa a 32 bytes raw y se cifra con
    encrypt_file_with_password() (AES-256-GCM + Argon2id).
    El archivo resultante es un contenedor SDDV v2 estandar.
    La llave NUNCA se almacena en texto plano.

    Parametros:
        private_key: objeto Ed25519PrivateKey
        path:        ruta del archivo de salida (se recomienda extension .sddv_priv)
        password:    password del usuario para cifrar la llave

    Lanza:
        ValueError — si el password esta vacio
    """
    from crypto.aead import encrypt_file_with_password

    raw_bytes = _serialize_private_key_raw(private_key)
    filename  = os.path.basename(path)    # va en el AAD del contenedor

    container = encrypt_file_with_password(raw_bytes, filename, password)

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(container)

    # Limpiar bytes de la llave de la memoria local (best-effort en Python)
    raw_bytes = b"\x00" * len(raw_bytes)


def save_public_key(public_key, path: str) -> None:
    """
    Guarda la llave publica en formato PEM (texto claro).

    La llave publica no necesita cifrarse — es seguro compartirla.
    Se guarda en formato PEM estandar (SubjectPublicKeyInfo), compatible
    con OpenSSL y la mayoria de herramientas criptograficas.

    Parametros:
        public_key: objeto Ed25519PublicKey
        path:       ruta del archivo de salida (se recomienda .sddv_pub)
    """
    pem_bytes = _serialize_public_key_pem(public_key)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)


# ──────────────────────────── cargar desde disco ──────────────────────────────

def load_private_key(path: str, password: str):
    """
    Carga y descifra la llave privada desde un archivo SDDV v2.

    Lee el contenedor, deriva la clave con Argon2id usando el password,
    descifra los 32 bytes raw y reconstruye el objeto Ed25519PrivateKey.

    Lanza:
        cryptography.exceptions.InvalidTag — password incorrecto
        FileNotFoundError — el archivo no existe
        ValueError — formato de archivo invalido
    """
    from crypto.aead import decrypt_file_with_password

    with open(path, "rb") as f:
        container = f.read()

    plaintext, _ = decrypt_file_with_password(container, password)
    return _deserialize_private_key_raw(plaintext)


def load_public_key(path: str):
    """
    Carga una llave publica desde un archivo PEM.

    Lanza:
        FileNotFoundError — el archivo no existe
        ValueError — formato PEM invalido
    """
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return load_pem_public_key(pem_bytes)


# ───────────────────────────── fingerprint ───────────────────────────────────

def get_fingerprint(public_key) -> str:
    """
    Calcula el fingerprint SHA-256 de una llave publica (64 chars hex).

    El fingerprint sirve como identificador unico de un destinatario
    en el cifrado hibrido de D3. Dado un fingerprint, siempre
    corresponde a la misma llave publica (determinista).

    Ejemplo: "a3f9c2...d841"  (64 caracteres hexadecimales)
    """
    raw_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return hashlib.sha256(raw_bytes).hexdigest()


def get_fingerprint_from_file(path: str) -> str:
    """Shortcut: carga la llave publica desde un archivo y calcula su fingerprint."""
    return get_fingerprint(load_public_key(path))


# ──────────────────────── flujo completo (helper) ────────────────────────────

def generate_and_save_keypair(base_path: str, password: str) -> dict:
    """
    Genera un par de llaves, las guarda en disco y retorna sus rutas y fingerprint.

    Crea dos archivos:
        {base_path}.sddv_priv — llave privada cifrada
        {base_path}.sddv_pub  — llave publica en PEM

    Retorna:
        {
          "private_key_path": str,
          "public_key_path":  str,
          "fingerprint":      str,   # SHA-256 hex de la llave publica
        }
    """
    private_key, public_key = generate_keypair()

    priv_path = base_path + PRIVATE_KEY_SUFFIX
    pub_path  = base_path + PUBLIC_KEY_SUFFIX

    save_private_key(private_key, priv_path, password)
    save_public_key(public_key,  pub_path)

    return {
        "private_key_path": priv_path,
        "public_key_path":  pub_path,
        "fingerprint":      get_fingerprint(public_key),
    }
