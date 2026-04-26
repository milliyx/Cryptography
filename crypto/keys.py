"""
crypto/keys.py
==============
Gestion de pares de llaves Ed25519 para el SDDV.

Que hace este modulo:
  - Genera pares de llaves Ed25519 (privada + publica).
  - Guarda la llave PRIVADA cifrada en disco en formato PEM cifrado (PKCS8).
    Nunca se almacena en texto plano.
  - Guarda la llave PUBLICA en formato PEM (texto claro, se puede compartir).
  - Carga ambas llaves desde disco.
  - Calcula el fingerprint de una llave publica (SHA-256 hex, 64 chars).

Por que Ed25519:
  - Curvas elipticas de Bernstein (Curve25519). 128 bits de seguridad.
  - Llaves pequenas: privada = 32 bytes, publica = 32 bytes.
  - Firmas de 64 bytes, verificacion rapida.
  - Resistente a ataques de canal lateral por diseno.

Como se protege la llave privada:
  - Se serializa en formato PEM cifrado estandar (PKCS8 + AES-256-CBC).
  - La contrasena del usuario protege el archivo; sin ella no se puede cargar.
  - El formato es compatible con OpenSSL y otras herramientas estandar.

Dependencia: pip install cryptography
"""

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


# ── constantes ────────────────────────────────────────────────────────────────

PRIVATE_KEY_SUFFIX = ".sddv_priv"
PUBLIC_KEY_SUFFIX  = ".sddv_pub"
KEY_FILENAME_PRIV  = "private_key"
KEY_FILENAME_PUB   = "public_key"


# ── generacion de llaves ──────────────────────────────────────────────────────

def generate_keypair():
    """
    Genera un par de llaves Ed25519 fresco usando el CSPRNG del SO.

    Retorna:
        (private_key, public_key) -- objetos de la libreria cryptography.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return private_key, public_key


# ── guardar en disco ──────────────────────────────────────────────────────────

def save_private_key(private_key, path: str, password: str) -> None:
    """
    Guarda la llave privada cifrada en formato PEM (PKCS8 + AES-256-CBC).

    La llave se protege con la contrasena del usuario usando el cifrado
    estandar PKCS8. El archivo resultante es un PEM cifrado compatible con
    OpenSSL. La llave NUNCA se almacena en texto plano.

    Parametros:
        private_key: objeto Ed25519PrivateKey
        path:        ruta del archivo de salida
        password:    contrasena del usuario

    Lanza:
        ValueError -- si el password esta vacio
    """
    if not password:
        raise ValueError("El password no puede estar vacio")

    pem_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(password.encode("utf-8")),
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)


def save_public_key(public_key, path: str) -> None:
    """
    Guarda la llave publica en formato PEM (SubjectPublicKeyInfo).

    La llave publica no necesita cifrarse -- es seguro compartirla.

    Parametros:
        public_key: objeto Ed25519PublicKey
        path:       ruta del archivo de salida
    """
    pem_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(pem_bytes)


# ── cargar desde disco ────────────────────────────────────────────────────────

def load_private_key(path: str, password: str):
    """
    Carga y descifra la llave privada desde un PEM cifrado (PKCS8).

    Lanza:
        FileNotFoundError -- el archivo no existe
        ValueError        -- password incorrecto o formato invalido
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontro el archivo de llave: {path}")
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return load_pem_private_key(pem_bytes, password=password.encode("utf-8"))


def load_public_key(path: str):
    """
    Carga una llave publica desde un archivo PEM.

    Lanza:
        FileNotFoundError -- el archivo no existe
        ValueError        -- formato PEM invalido
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No se encontro el archivo de llave: {path}")
    with open(path, "rb") as f:
        pem_bytes = f.read()
    return load_pem_public_key(pem_bytes)


# ── fingerprint ───────────────────────────────────────────────────────────────

def get_fingerprint(public_key) -> str:
    """
    Calcula el fingerprint SHA-256 de una llave publica (64 chars hex).

    El fingerprint identifica univocamente a un destinatario y se usa
    como recipiente ID en el cifrado hibrido D3.
    """
    raw_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return hashlib.sha256(raw_bytes).hexdigest()


def get_fingerprint_from_file(path: str) -> str:
    """Shortcut: carga la llave publica desde archivo y calcula su fingerprint."""
    return get_fingerprint(load_public_key(path))


# ── flujo completo (helper) ───────────────────────────────────────────────────

def generate_and_save_keypair(base_path: str, password: str) -> dict:
    """
    Genera un par de llaves, las guarda en disco y retorna rutas y fingerprint.

    Crea:
        {base_path}.sddv_priv -- llave privada cifrada (PEM PKCS8)
        {base_path}.sddv_pub  -- llave publica (PEM)

    Retorna:
        {"private_key_path": str, "public_key_path": str, "fingerprint": str}
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
