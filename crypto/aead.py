"""
crypto/aead.py
==============
Módulo AEAD para la Bóveda Digital Segura de Documentos (SDDV).

Soporta dos modos:
  Modo RAW (v1):      clave pasada directamente o generada con os.urandom.
  Modo PASSWORD (v2): clave derivada de password con Argon2id (KDF).

Dependencias: pip install cryptography argon2-cffi
"""

import os
import struct
import time
from enum import IntEnum
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAGIC            = b"SDDV"
VERSION_RAW      = 1
VERSION_PASSWORD = 2

NONCE_SIZE = 12
TAG_SIZE   = 16
KEY_SIZE   = 32


class Algorithm(IntEnum):
    AES_256_GCM       = 1
    CHACHA20_POLY1305 = 2


def _build_header(filename, algo, timestamp=None, kdf_params=None):
    if timestamp is None:
        timestamp = int(time.time())
    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 0xFFFF:
        raise ValueError("Nombre de archivo demasiado largo")
    version = VERSION_PASSWORD if kdf_params else VERSION_RAW
    header = (
        MAGIC
        + bytes([version, int(algo)])
        + struct.pack(">Q", timestamp)
        + struct.pack(">H", len(fname_bytes))
        + fname_bytes
    )
    if kdf_params:
        header += kdf_params
    return header


def _parse_header(data):
    if len(data) < 16:
        raise ValueError("Contenedor demasiado corto")
    if data[:4] != MAGIC:
        raise ValueError("Magic bytes invalidos - es esto un contenedor SDDV?")
    version = data[4]
    if version not in (VERSION_RAW, VERSION_PASSWORD):
        raise ValueError(f"Version no soportada: {version}")
    algo      = Algorithm(data[5])
    timestamp = struct.unpack(">Q", data[6:14])[0]
    fname_len = struct.unpack(">H", data[14:16])[0]
    header_end = 16 + fname_len
    if len(data) < header_end:
        raise ValueError("Cabecera truncada")
    filename = data[16:header_end].decode("utf-8")
    kdf_info = None
    if version == VERSION_PASSWORD:
        KDF_SIZE = 16 + 4 + 4 + 2
        if len(data) < header_end + KDF_SIZE:
            raise ValueError("Cabecera v2 truncada: faltan parametros KDF")
        pos         = header_end
        salt        = data[pos:pos+16]
        memory_cost = struct.unpack(">I", data[pos+16:pos+20])[0]
        time_cost   = struct.unpack(">I", data[pos+20:pos+24])[0]
        parallelism = struct.unpack(">H", data[pos+24:pos+26])[0]
        kdf_info    = {"salt": salt, "memory_cost": memory_cost,
                       "time_cost": time_cost, "parallelism": parallelism}
        header_end += KDF_SIZE
    metadata = {"version": version, "algo": algo, "timestamp": timestamp,
                "filename": filename, "kdf": kdf_info}
    return metadata, header_end


def generate_key(algo=Algorithm.AES_256_GCM):
    """Genera clave de 256 bits con CSPRNG del SO (modo RAW)."""
    return os.urandom(KEY_SIZE)


# ── Modo RAW (v1) ────────────────────────────────────────────────────────────

def encrypt_file(plaintext, filename, key=None, algo=Algorithm.AES_256_GCM, timestamp=None):
    """Cifra con clave directa. Si key es None se genera una nueva."""
    if key is None:
        key = generate_key(algo)
    if len(key) != KEY_SIZE:
        raise ValueError(f"Tamano de clave incorrecto: se esperaban {KEY_SIZE} bytes, se recibieron {len(key)}")
    header      = _build_header(filename, algo, timestamp)
    nonce       = os.urandom(NONCE_SIZE)
    cipher      = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    ct_with_tag = cipher.encrypt(nonce, plaintext, header)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    container   = header + nonce + struct.pack(">I", len(ciphertext)) + ciphertext + tag
    return container, key


def decrypt_file(container, key):
    """Descifra un contenedor v1. Lanza InvalidTag si falla la autenticacion."""
    metadata, header_end = _parse_header(container)
    header = container[:header_end]
    algo   = metadata["algo"]
    pos    = header_end
    if len(container) < pos + NONCE_SIZE + 4:
        raise ValueError("Contenedor truncado: faltan nonce o ct_len")
    nonce  = container[pos:pos+NONCE_SIZE]; pos += NONCE_SIZE
    ct_len = struct.unpack(">I", container[pos:pos+4])[0]; pos += 4
    if len(container) < pos + ct_len + TAG_SIZE:
        raise ValueError("Contenedor truncado: faltan ciphertext o tag")
    ciphertext = container[pos:pos+ct_len]; pos += ct_len
    tag        = container[pos:pos+TAG_SIZE]; pos += TAG_SIZE
    if pos != len(container):
        raise ValueError(f"Contenedor con {len(container)-pos} bytes sobrantes")
    cipher    = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext + tag, header)
    return plaintext, metadata


# ── Modo PASSWORD (v2) ───────────────────────────────────────────────────────

def encrypt_file_with_password(plaintext, filename, password, algo=Algorithm.AES_256_GCM,
                                timestamp=None, memory_cost=65536, time_cost=3, parallelism=1):
    """
    Cifra derivando la clave desde password con Argon2id (contenedor v2).

    El salt KDF se genera aleatoriamente y se almacena en el AAD del contenedor.
    La clave derivada nunca se guarda en disco. El usuario solo necesita su password.

    Retorna: container_bytes
    """
    from crypto.kdf import derive_key, serialize_kdf_params
    key, salt  = derive_key(password, memory_cost=memory_cost,
                            time_cost=time_cost, parallelism=parallelism)
    kdf_params = serialize_kdf_params(salt, memory_cost, time_cost, parallelism)
    header      = _build_header(filename, algo, timestamp, kdf_params=kdf_params)
    nonce       = os.urandom(NONCE_SIZE)
    cipher      = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    ct_with_tag = cipher.encrypt(nonce, plaintext, header)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    container   = header + nonce + struct.pack(">I", len(ciphertext)) + ciphertext + tag
    key = b"\x00" * KEY_SIZE  # limpiar clave de memoria (best-effort)
    return container


def decrypt_file_with_password(container, password):
    """
    Descifra un contenedor v2. Recalcula la clave con Argon2id usando el salt
    almacenado en el contenedor. Lanza InvalidTag si el password es incorrecto.

    Retorna: (plaintext, metadata)
    """
    from crypto.kdf import derive_key
    metadata, header_end = _parse_header(container)
    if metadata["version"] != VERSION_PASSWORD:
        raise ValueError("Contenedor v1: usa decrypt_file() con la clave directa.")
    kdf    = metadata["kdf"]
    header = container[:header_end]
    algo   = metadata["algo"]
    key, _ = derive_key(password, salt=kdf["salt"], memory_cost=kdf["memory_cost"],
                        time_cost=kdf["time_cost"], parallelism=kdf["parallelism"])
    pos    = header_end
    if len(container) < pos + NONCE_SIZE + 4:
        raise ValueError("Contenedor truncado")
    nonce  = container[pos:pos+NONCE_SIZE]; pos += NONCE_SIZE
    ct_len = struct.unpack(">I", container[pos:pos+4])[0]; pos += 4
    if len(container) < pos + ct_len + TAG_SIZE:
        raise ValueError("Contenedor truncado: faltan ciphertext o tag")
    ciphertext = container[pos:pos+ct_len]; pos += ct_len
    tag        = container[pos:pos+TAG_SIZE]; pos += TAG_SIZE
    if pos != len(container):
        raise ValueError(f"Contenedor con {len(container)-pos} bytes sobrantes")
    cipher    = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext + tag, header)
    key = b"\x00" * KEY_SIZE
    return plaintext, metadata
