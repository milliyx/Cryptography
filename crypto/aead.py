"""
crypto/aead.py
==============
Módulo AEAD para la Bóveda Digital Segura de Documentos (SDDV).

Implementa cifrado autenticado de archivos para un solo dueño usando
AES-256-GCM o ChaCha20-Poly1305. Cada archivo recibe su propia clave
efímera y un nonce fresco generado con el CSPRNG del sistema operativo.

Garantías:
  - Confidencialidad: sin la clave, el ciphertext no revela nada del plaintext.
  - Integridad:       cualquier modificación al ciphertext se detecta con el tag.
  - Autenticidad de metadatos: el AAD vincula los metadatos al tag AEAD;
                               modificar el nombre, timestamp o versión
                               invalida el contenedor.

Dependencia: pip install cryptography
"""

import os
import struct
import time
from enum import IntEnum
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# ─────────────────────────────── constantes ─────────────────────────────────

MAGIC = b"SDDV"         # Firma del formato — los primeros 4 bytes de todo contenedor
CURRENT_VERSION = 1     # Versión del formato de serialización

NONCE_SIZE  = 12        # 96 bits — recomendación NIST SP 800-38D para AES-GCM
TAG_SIZE    = 16        # 128 bits — longitud del tag de autenticación GCM/Poly1305
KEY_SIZE    = 32        # 256 bits — tanto para AES-256-GCM como para ChaCha20-Poly1305


class Algorithm(IntEnum):
    """Identificadores de algoritmo almacenados en la cabecera del contenedor."""
    AES_256_GCM        = 1
    CHACHA20_POLY1305  = 2


# ──────────────────────────── formato del contenedor ─────────────────────────
#
#  ┌────────────────────────────────────────────────────────────┐
#  │            CABECERA — AAD (texto claro, autenticada)       │
#  ├─────────────────┬──────────────────────────────────────────┤
#  │  MAGIC          │  4 bytes  — b"SDDV"                      │
#  │  VERSION        │  1 byte   — versión del formato          │
#  │  ALGO_ID        │  1 byte   — algoritmo AEAD               │
#  │  TIMESTAMP      │  8 bytes  — Unix time, big-endian uint64 │
#  │  FILENAME_LEN   │  2 bytes  — longitud del nombre, uint16  │
#  │  FILENAME       │  variable — UTF-8                        │
#  ├─────────────────┴──────────────────────────────────────────┤
#  │                 SECCIÓN CIFRADA                            │
#  ├────────────────────────────────────────────────────────────┤
#  │  NONCE          │ 12 bytes  — 96 bits CSPRNG               │
#  │  CT_LEN         │  4 bytes  — longitud del ciphertext      │
#  │  CIPHERTEXT     │  variable — datos cifrados               │
#  │  TAG            │ 16 bytes  — tag de autenticación 128-bit │
#  └────────────────────────────────────────────────────────────┘
#
#  El TAG cubre: CIPHERTEXT completo + CABECERA (AAD) completa.
#  Modificar cualquier byte de cualquier sección invalida el TAG.


# ─────────────────────────── serialización de la cabecera ───────────────────

def _build_header(
    filename:  str,
    algo:      Algorithm,
    timestamp: Optional[int] = None,
) -> bytes:
    """
    Serializa la cabecera del contenedor que se usa como AAD.

    Todo lo que va aquí queda autenticado pero NO cifrado: el tag GCM cubre
    estos bytes, por lo que cualquier modificación (nombre de archivo, versión,
    algoritmo, timestamp) hace fallar la verificación al descifrar.
    """
    if timestamp is None:
        timestamp = int(time.time())

    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 0xFFFF:
        raise ValueError("Nombre de archivo demasiado largo (máx 65 535 bytes UTF-8)")

    return (
        MAGIC
        + bytes([CURRENT_VERSION, int(algo)])
        + struct.pack(">Q", timestamp)           # uint64 big-endian
        + struct.pack(">H", len(fname_bytes))    # uint16 big-endian
        + fname_bytes
    )


def _parse_header(data: bytes) -> Tuple[dict, int]:
    """
    Deserializa la cabecera y devuelve (metadata_dict, bytes_consumidos).

    No verifica el tag aquí — eso lo hace decrypt_file() con la clave.
    Lanza ValueError si la cabecera está malformada (formato inválido).
    """
    # Mínimo: magic(4) + version(1) + algo(1) + ts(8) + fname_len(2) = 16 bytes
    if len(data) < 16:
        raise ValueError("Contenedor demasiado corto para tener cabecera válida")

    if data[:4] != MAGIC:
        raise ValueError(
            "Magic bytes inválidos — ¿es esto un contenedor SDDV?"
        )

    version = data[4]
    if version != CURRENT_VERSION:
        raise ValueError(f"Versión de formato no soportada: {version}")

    # Algorithm() lanza ValueError si el byte no corresponde a un valor conocido
    algo = Algorithm(data[5])

    timestamp = struct.unpack(">Q", data[6:14])[0]
    fname_len = struct.unpack(">H", data[14:16])[0]

    header_end = 16 + fname_len
    if len(data) < header_end:
        raise ValueError("Cabecera truncada: faltan bytes del nombre de archivo")

    filename = data[16:header_end].decode("utf-8")

    metadata = {
        "version":   version,
        "algo":      algo,
        "timestamp": timestamp,
        "filename":  filename,
    }
    return metadata, header_end


# ─────────────────────────────── interfaz pública ───────────────────────────

def generate_key(algo: Algorithm = Algorithm.AES_256_GCM) -> bytes:
    """
    Genera una clave simétrica fresca de 256 bits usando os.urandom() (CSPRNG del SO).

    Nunca usar random.random(), secrets.token_bytes() con semilla fija ni ningún
    otro generador predecible. os.urandom() delega al kernel:
      - Linux/macOS: /dev/urandom (entropía del kernel)
      - Windows: CryptGenRandom / BCryptGenRandom
    """
    return os.urandom(KEY_SIZE)


def encrypt_file(
    plaintext:  bytes,
    filename:   str,
    key:        Optional[bytes] = None,
    algo:       Algorithm = Algorithm.AES_256_GCM,
    timestamp:  Optional[int] = None,
) -> Tuple[bytes, bytes]:
    """
    Cifra `plaintext` y devuelve (contenedor_bytes, clave).

    Si no se pasa `key`, se genera automáticamente una clave fresca por archivo
    (modo normal de operación). Esta decisión garantiza que, incluso si dos
    archivos distintos tuvieran el mismo nonce (probabilidad ínfima), no habría
    reutilización de (clave, nonce) porque las claves son independientes.

    El nonce se genera con os.urandom(12) — 96 bits de entropía aleatoria —
    en cada llamada, y NUNCA se reutiliza. Ver docs/D2_Encryption_Design.md
    para la explicación completa de por qué la reutilización de nonce es
    catastrófica en AES-GCM.

    Parámetros:
        plaintext:  bytes del archivo original
        filename:   nombre del archivo (se almacena en el AAD)
        key:        clave de 256 bits; si es None se genera una nueva
        algo:       algoritmo AEAD a usar
        timestamp:  timestamp Unix; si es None se usa time.time()

    Retorna:
        (container_bytes, key)
        donde container_bytes es el contenedor SDDV listo para guardar en disco.

    Lanza:
        ValueError — si la clave tiene el tamaño incorrecto o el filename es inválido
    """
    if key is None:
        key = generate_key(algo)

    if len(key) != KEY_SIZE:
        raise ValueError(
            f"Tamaño de clave incorrecto: se esperaban {KEY_SIZE} bytes, "
            f"se recibieron {len(key)}"
        )

    # ── 1. Construir cabecera (AAD) ──────────────────────────────────────────
    # Los metadatos van aquí: no se cifran pero SÍ se autentican.
    # Si alguien modifica el filename, la versión o el timestamp, el tag falla.
    header = _build_header(filename, algo, timestamp)

    # ── 2. Generar nonce fresco con CSPRNG ───────────────────────────────────
    # Cada cifrado usa un nonce distinto. No hay contador, no hay IV fijo.
    # La probabilidad de colisión en 2^32 nonces es ≈ 2^-32 (birthday bound).
    nonce = os.urandom(NONCE_SIZE)

    # ── 3. Cifrar con AEAD ───────────────────────────────────────────────────
    # encrypt(nonce, plaintext, aad) → ciphertext ‖ tag (los últimos 16 bytes)
    # El tag cubre el ciphertext Y el header (AAD) en una sola operación atómica.
    if algo == Algorithm.AES_256_GCM:
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    ct_with_tag = cipher.encrypt(nonce, plaintext, header)

    # Separar ciphertext y tag para serializarlos explícitamente
    ciphertext = ct_with_tag[:-TAG_SIZE]
    tag        = ct_with_tag[-TAG_SIZE:]

    # ── 4. Serializar el contenedor completo ─────────────────────────────────
    container = (
        header                              # cabecera (AAD)
        + nonce                             # nonce de 96 bits
        + struct.pack(">I", len(ciphertext))  # longitud del ciphertext (uint32 BE)
        + ciphertext                        # datos cifrados
        + tag                               # tag de autenticación de 128 bits
    )

    return container, key


def decrypt_file(container: bytes, key: bytes) -> Tuple[bytes, dict]:
    """
    Descifra y verifica un contenedor SDDV.

    FALLA de forma segura si:
      - La clave es incorrecta                  → InvalidTag
      - El ciphertext fue modificado            → InvalidTag
      - Los metadatos (AAD/cabecera) cambiaron  → InvalidTag
      - El tag de autenticación no coincide     → InvalidTag
      - El formato del contenedor es inválido   → ValueError

    En ningún caso se devuelve plaintext si la verificación del tag falla.
    Esto evita que un atacante use el sistema como oráculo de descifrado.

    Parámetros:
        container:  bytes del contenedor cifrado
        key:        clave simétrica de 256 bits

    Retorna:
        (plaintext, metadata_dict)

    Lanza:
        InvalidTag  — autenticación fallida (clave incorrecta o manipulación)
        ValueError  — formato inválido
    """
    # ── 1. Parsear la cabecera (AAD) ─────────────────────────────────────────
    metadata, header_end = _parse_header(container)
    header = container[:header_end]
    algo   = metadata["algo"]

    # ── 2. Parsear nonce, longitud del CT y resto ────────────────────────────
    pos = header_end

    if len(container) < pos + NONCE_SIZE + 4:
        raise ValueError("Contenedor truncado: no hay suficientes bytes para nonce y ct_len")

    nonce  = container[pos : pos + NONCE_SIZE]
    pos   += NONCE_SIZE

    ct_len = struct.unpack(">I", container[pos : pos + 4])[0]
    pos   += 4

    if len(container) < pos + ct_len + TAG_SIZE:
        raise ValueError("Contenedor truncado: faltan ciphertext o tag")

    ciphertext = container[pos : pos + ct_len]
    pos       += ct_len

    tag = container[pos : pos + TAG_SIZE]
    pos += TAG_SIZE

    # Detectar bytes sobrantes al final (posible manipulación o formato incorrecto)
    if pos != len(container):
        raise ValueError(
            f"Contenedor con {len(container) - pos} bytes sobrantes — "
            "posible manipulación o formato incorrecto"
        )

    # ── 3. Descifrar y verificar ─────────────────────────────────────────────
    # La librería `cryptography` verifica el tag ANTES de devolver el plaintext.
    # Si el tag no coincide (clave incorrecta, ciphertext modificado o AAD
    # modificado), lanza cryptography.exceptions.InvalidTag sin devolver nada.
    ct_with_tag = ciphertext + tag

    if algo == Algorithm.AES_256_GCM:
        cipher = AESGCM(key)
    else:
        cipher = ChaCha20Poly1305(key)

    # decrypt(nonce, ct_with_tag, aad) verifica el tag sobre (ciphertext + header)
    # Si falla → InvalidTag. Si pasa → plaintext autenticado e íntegro.
    plaintext = cipher.decrypt(nonce, ct_with_tag, header)

    return plaintext, metadata
