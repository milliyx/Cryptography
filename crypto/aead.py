"""
crypto/aead.py
==============
Modulo AEAD para la Boveda Digital Segura de Documentos (SDDV).

Cifra archivos con autenticacion integrada usando AES-256-GCM o
ChaCha20-Poly1305. La clave se pasa directamente (256 bits generados
con os.urandom o derivados externamente).

Por que AEAD (Authenticated Encryption with Associated Data):
  - Confidencialidad: el contenido del archivo es ilegible sin la clave.
  - Integridad: cualquier modificacion al ciphertext o a los metadatos
    (filename, timestamp, algoritmo) invalida el tag de autenticacion.
  - El tag se verifica ANTES de devolver cualquier byte del plaintext,
    por lo que nunca se exponen datos si el contenedor fue manipulado.

Formato del contenedor (binario, version 1):
  MAGIC(4)      b"SDDV"
  VERSION(1)    = 1
  ALGO_ID(1)    0x01 = AES-256-GCM, 0x02 = ChaCha20-Poly1305
  TIMESTAMP(8)  Unix time big-endian uint64
  FNAME_LEN(2)  longitud del nombre, big-endian uint16
  FILENAME      variable, UTF-8
  --- fin del AAD ---
  NONCE(12)     aleatorio, CSPRNG del SO
  CT_LEN(4)     longitud del ciphertext, big-endian uint32
  CIPHERTEXT    variable
  TAG(16)       tag de autenticacion AEAD

La cabecera completa (MAGIC..FILENAME) es el AAD: se autentica pero no
se cifra. Modificar cualquier byte de la cabecera invalida el TAG.

Dependencias: pip install cryptography
"""

import os
import struct
import time
from enum import IntEnum
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAGIC   = b"SDDV"
VERSION = 1

NONCE_SIZE     = 12
TAG_SIZE       = 16
KEY_SIZE       = 32
VALID_MAGIC    = {b"SDDV", b"SDDH"}
VALID_ALGO_ID  = {0x01, 0x02}
MIN_HEADER_LEN = 16


class Algorithm(IntEnum):
    AES_256_GCM       = 1
    CHACHA20_POLY1305 = 2


# -- Validacion de entrada -----------------------------------------------------

def _validate_container_header(data: bytes) -> None:
    """
    Rechaza input invalido antes de cualquier parsing.

    Usa un mensaje generico unico para evitar filtrar informacion
    a traves de mensajes de error distinguibles (CWE-209).

    Lanza ValueError('Invalid container') si:
      - data no es bytes o bytearray
      - data tiene menos de MIN_HEADER_LEN bytes
      - los primeros 4 bytes no son un magic valido (SDDV o SDDH)
      - el byte de algo_id (indice 5) no es 0x01 ni 0x02
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Invalid container")
    if len(data) < MIN_HEADER_LEN:
        raise ValueError("Invalid container")
    if bytes(data[:4]) not in VALID_MAGIC:
        raise ValueError("Invalid container")
    if data[5] not in VALID_ALGO_ID:
        raise ValueError("Invalid container")


# -- Construccion y parseo de cabecera ----------------------------------------

def _build_header(
    filename: str,
    algo: Algorithm,
    timestamp: Optional[int] = None,
) -> bytes:
    """Construye la cabecera del contenedor (= AAD del cifrado AEAD)."""
    if timestamp is None:
        timestamp = int(time.time())
    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 0xFFFF:
        raise ValueError("Nombre de archivo demasiado largo")
    return (
        MAGIC
        + bytes([VERSION, int(algo)])
        + struct.pack(">Q", timestamp)
        + struct.pack(">H", len(fname_bytes))
        + fname_bytes
    )


def _parse_header(data: bytes) -> Tuple[dict, int]:
    """
    Parsea la cabecera del contenedor y retorna (metadata, header_end_offset).

    Lanza ValueError si el formato es invalido.
    """
    if len(data) < 16:
        raise ValueError("Contenedor demasiado corto")
    if data[:4] != MAGIC:
        raise ValueError("Magic bytes invalidos - es esto un contenedor SDDV?")
    version = data[4]
    if version != VERSION:
        raise ValueError(f"Version no soportada: {version}")
    algo      = Algorithm(data[5])
    timestamp = struct.unpack(">Q", data[6:14])[0]
    fname_len = struct.unpack(">H", data[14:16])[0]
    header_end = 16 + fname_len
    if len(data) < header_end:
        raise ValueError("Cabecera truncada")
    filename = data[16:header_end].decode("utf-8")
    metadata = {
        "version":   version,
        "algo":      algo,
        "timestamp": timestamp,
        "filename":  filename,
    }
    return metadata, header_end


# -- API publica --------------------------------------------------------------

def generate_key(algo: Algorithm = Algorithm.AES_256_GCM) -> bytes:
    """Genera una clave de 256 bits con el CSPRNG del SO."""
    return os.urandom(KEY_SIZE)


def encrypt_file(
    plaintext: bytes,
    filename: str,
    key: Optional[bytes] = None,
    algo: Algorithm = Algorithm.AES_256_GCM,
    timestamp: Optional[int] = None,
) -> Tuple[bytes, bytes]:
    """
    Cifra plaintext y retorna (container, key).

    Si key es None se genera una clave aleatoria de 256 bits.
    La clave generada se incluye en el retorno para que el llamador
    pueda almacenarla o distribuirla a los destinatarios.

    Parametros:
        plaintext : bytes a cifrar
        filename  : nombre del archivo (autenticado en el AAD)
        key       : clave de 32 bytes; None genera una nueva
        algo      : AES_256_GCM (default) o CHACHA20_POLY1305
        timestamp : Unix timestamp; None usa time.time()

    Retorna: (container_bytes, key_bytes)

    Lanza:
        ValueError -- si la clave no tiene 32 bytes
    """
    if key is None:
        key = generate_key(algo)
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Tamano de clave incorrecto: se esperaban {KEY_SIZE} bytes, "
            f"se recibieron {len(key)}"
        )
    header      = _build_header(filename, algo, timestamp)
    nonce       = os.urandom(NONCE_SIZE)
    cipher      = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    ct_with_tag = cipher.encrypt(nonce, plaintext, header)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]
    container   = header + nonce + struct.pack(">I", len(ciphertext)) + ciphertext + tag
    return container, key


def decrypt_file(container: bytes, key: bytes) -> Tuple[bytes, dict]:
    """
    Descifra un contenedor SDDV y retorna (plaintext, metadata).

    Verifica el tag de autenticacion ANTES de devolver datos.
    Si el tag no verifica (clave incorrecta o contenedor manipulado)
    lanza InvalidTag sin exponer ningun byte del plaintext.

    Parametros:
        container : bytes del contenedor SDDV
        key       : clave de 32 bytes usada al cifrar

    Retorna: (plaintext, metadata_dict)

    Lanza:
        InvalidTag  -- clave incorrecta o contenedor manipulado
        ValueError  -- formato invalido o bytes sobrantes
    """
    _validate_container_header(container)  # fix: reject invalid input early
    metadata, header_end = _parse_header(container)
    header = container[:header_end]
    algo   = metadata["algo"]
    pos    = header_end
    if len(container) < pos + NONCE_SIZE + 4:
        raise ValueError("Contenedor truncado: faltan nonce o ct_len")
    nonce  = container[pos : pos + NONCE_SIZE]; pos += NONCE_SIZE
    ct_len = struct.unpack(">I", container[pos : pos + 4])[0]; pos += 4
    if len(container) < pos + ct_len + TAG_SIZE:
        raise ValueError("Contenedor truncado: faltan ciphertext o tag")
    ciphertext = container[pos : pos + ct_len]; pos += ct_len
    tag        = container[pos : pos + TAG_SIZE]; pos += TAG_SIZE
    if pos != len(container):
        raise ValueError(f"Contenedor con {len(container) - pos} bytes sobrantes")
    cipher    = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext + tag, header)
    return plaintext, metadata
