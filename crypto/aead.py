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
import posixpath
import struct
import time
from enum import IntEnum
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MAGIC   = b"SDDV"
VERSION = 1

NONCE_SIZE = 12
TAG_SIZE   = 16
KEY_SIZE   = 32

# Limite de longitud para filename (filesystems mainstream limitan a 255 bytes)
MAX_FILENAME_LEN = 255

# Parametros de validacion de freshness (CWE-294 — Replay Attacks)
DEFAULT_MAX_AGE = 7 * 24 * 60 * 60   # 7 dias por defecto
MAX_FUTURE_SKEW = 5 * 60             # 5 minutos de tolerancia hacia el futuro

# Tope superior del ciphertext en un contenedor (CWE-770 — Resource Exhaustion).
# El campo CT_LEN es uint32 (hasta 4 GiB), pero permitir esa magnitud abre la
# puerta a DoS por agotamiento de memoria al construir el slice. 100 MiB es
# suficiente para el caso de uso (documentos) y atrapa containers hostiles.
MAX_CIPHERTEXT_SIZE = 100 * 1024 * 1024  # 100 MiB


def validate_timestamp(timestamp: int, max_age_seconds: Optional[int]) -> None:
    """
    Valida freshness del timestamp (CWE-294 — Replay Attack).

    Si max_age_seconds es None, no se valida edad (modo legacy/explicito).
    Si max_age_seconds es int, rechaza:
      - timestamps mas viejos que max_age_seconds (replay)
      - timestamps mas de MAX_FUTURE_SKEW segundos en el futuro (clock skew abuse)

    Lanza ValueError si el timestamp esta fuera de ventana.
    """
    if max_age_seconds is None:
        return
    now = int(time.time())
    age = now - timestamp
    if age > max_age_seconds:
        raise ValueError(
            f"timestamp demasiado antiguo: {age} segundos "
            f"(max permitido: {max_age_seconds})"
        )
    if age < -MAX_FUTURE_SKEW:
        raise ValueError(
            f"timestamp en el futuro: {-age} segundos "
            f"(max skew permitido: {MAX_FUTURE_SKEW})"
        )


def validate_ciphertext_length(ct_len: int) -> None:
    """
    Valida que ct_len no exceda MAX_CIPHERTEXT_SIZE (CWE-770 / CWE-400).

    El campo CT_LEN del contenedor es uint32 (hasta 4 GiB). Sin tope, un
    contenedor manipulado con ct_len enorme provoca asignacion de memoria
    proporcional al valor — DoS trivial. Atajamos antes de cualquier slice.

    Lanza ValueError si ct_len excede el tope.
    """
    if ct_len > MAX_CIPHERTEXT_SIZE:
        raise ValueError(
            f"ciphertext demasiado grande: {ct_len} bytes "
            f"(maximo permitido: {MAX_CIPHERTEXT_SIZE})"
        )


def safe_path_join(out_dir: str, filename: str) -> str:
    """
    Construye un path seguro out_dir/filename garantizando que el resultado
    permanezca dentro de out_dir (CWE-22 — defensa adicional al consumir
    metadata['filename'] de un contenedor descifrado).

    Aplica validate_filename y verifica con realpath que el path final tenga
    a out_dir como prefijo. Esto cubre casos donde el filename ya estaba en
    un contenedor antiguo sin validacion (compatibilidad hacia atras).

    Lanza ValueError si el filename es inseguro o si el path final escapa
    del directorio destino.

    Retorna: ruta absoluta segura.
    """
    validate_filename(filename)
    out_dir_abs  = os.path.realpath(out_dir)
    candidate    = os.path.realpath(os.path.join(out_dir_abs, filename))
    # Asegurar terminador de path para que prefix-check no acepte
    # /tmp/out_dirEVIL como dentro de /tmp/out_dir.
    out_dir_norm = out_dir_abs + os.sep
    if not (candidate == out_dir_abs or candidate.startswith(out_dir_norm)):
        raise ValueError(
            f"path resultante escapa del directorio destino: {candidate!r} "
            f"no esta dentro de {out_dir_abs!r}"
        )
    return candidate


def validate_filename(filename: str) -> None:
    """
    Valida que el filename sea seguro para uso en filesystem.

    Rechaza (CWE-22 — Path Traversal):
      - separadores de path: '/', '\\\\'
      - referencias a directorio padre: '..'
      - rutas absolutas (Unix '/' o Windows 'C:')
      - bytes nulos (truncamiento de path en C-strings)
      - caracteres de control
      - longitud > 255 bytes

    Lanza ValueError si el filename es inseguro.
    """
    if not isinstance(filename, str):
        raise ValueError("filename debe ser str")
    if not filename:
        raise ValueError("filename no puede estar vacio")
    if len(filename.encode("utf-8")) > MAX_FILENAME_LEN:
        raise ValueError(f"filename excede {MAX_FILENAME_LEN} bytes")
    if "\x00" in filename:
        raise ValueError("filename contiene byte nulo (null byte injection)")
    if any(ord(c) < 0x20 for c in filename):
        raise ValueError("filename contiene caracteres de control")
    if "/" in filename or "\\" in filename:
        raise ValueError("filename contiene separadores de path")
    if filename in (".", ".."):
        raise ValueError("filename no puede ser '.' o '..'")
    if len(filename) >= 2 and filename[1] == ":":
        raise ValueError("filename parece ruta absoluta de Windows")
    if posixpath.normpath(filename) != filename:
        raise ValueError("filename contiene componentes de path no canonicos")


class Algorithm(IntEnum):
    AES_256_GCM       = 1
    CHACHA20_POLY1305 = 2


# -- Construccion y parseo de cabecera ----------------------------------------

def _build_header_prefix(
    magic: bytes,
    version: int,
    algo: Algorithm,
    filename: str,
    timestamp: Optional[int],
) -> bytes:
    """
    Prefijo comun de cabecera SDDV/SDDH.
    Layout: MAGIC(4) + VERSION(1) + ALGO(1) + TS(8) + FNAME_LEN(2) + FNAME.
    Valida filename, asigna timestamp si es None, y revisa longitud de filename.
    """
    validate_filename(filename)
    if timestamp is None:
        timestamp = int(time.time())
    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 0xFFFF:
        raise ValueError("Nombre de archivo demasiado largo")
    return (
        magic
        + bytes([version, int(algo)])
        + struct.pack(">Q", timestamp)
        + struct.pack(">H", len(fname_bytes))
        + fname_bytes
    )


def _build_header(
    filename: str,
    algo: Algorithm,
    timestamp: Optional[int] = None,
) -> bytes:
    """Construye la cabecera del contenedor (= AAD del cifrado AEAD)."""
    return _build_header_prefix(MAGIC, VERSION, algo, filename, timestamp)


def _parse_header(data: bytes) -> Tuple[dict, int]:
    """
    Parsea la cabecera del contenedor y retorna (metadata, header_end_offset).

    Lanza ValueError si el formato es invalido.
    """
    if len(data) < 16:
        raise ValueError("Contenedor demasiado corto")
    if data[:4] != MAGIC:
        # Detectar el caso comun de pasar un contenedor hibrido a la API SDDV
        if data[:4] == b"SDDH":
            raise ValueError(
                "Contenedor hibrido SDDH pasado a decrypt_file (D2). "
                "Use decrypt_for_recipient (crypto.hybrid) para SDDH."
            )
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
    # Defense-in-depth: rechazar filenames inseguros aun si el contenedor fue
    # cifrado con una version vulnerable de encrypt_file (CWE-22).
    validate_filename(filename)
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


def decrypt_file(
    container: bytes,
    key: bytes,
    max_age_seconds: Optional[int] = DEFAULT_MAX_AGE,
) -> Tuple[bytes, dict]:
    """
    Descifra un contenedor SDDV y retorna (plaintext, metadata).

    Verifica el tag de autenticacion ANTES de devolver datos.
    Si el tag no verifica (clave incorrecta o contenedor manipulado)
    lanza InvalidTag sin exponer ningun byte del plaintext.

    Parametros:
        container       : bytes del contenedor SDDV
        key             : clave de 32 bytes usada al cifrar
        max_age_seconds : ventana de freshness en segundos. Si el timestamp
                          del contenedor es mas antiguo que esto, se rechaza
                          (proteccion contra replay attacks, CWE-294).
                          Default: 7 dias. Pasar None deshabilita la
                          validacion (no recomendado en produccion).

    Retorna: (plaintext, metadata_dict)

    Lanza:
        InvalidTag  -- clave incorrecta o contenedor manipulado
        ValueError  -- formato invalido, filename inseguro, timestamp fuera
                       de la ventana de freshness, o bytes sobrantes
    """
    metadata, header_end = _parse_header(container)
    validate_timestamp(metadata["timestamp"], max_age_seconds)
    header = container[:header_end]
    algo   = metadata["algo"]
    pos    = header_end
    if len(container) < pos + NONCE_SIZE + 4:
        raise ValueError("Contenedor truncado: faltan nonce o ct_len")
    nonce  = container[pos : pos + NONCE_SIZE]; pos += NONCE_SIZE
    ct_len = struct.unpack(">I", container[pos : pos + 4])[0]; pos += 4
    # Tope superior antes del slice (CWE-770).
    validate_ciphertext_length(ct_len)
    if len(container) < pos + ct_len + TAG_SIZE:
        raise ValueError("Contenedor truncado: faltan ciphertext o tag")
    ciphertext = container[pos : pos + ct_len]; pos += ct_len
    tag        = container[pos : pos + TAG_SIZE]; pos += TAG_SIZE
    if pos != len(container):
        raise ValueError(f"Contenedor con {len(container) - pos} bytes sobrantes")
    cipher    = AESGCM(key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext + tag, header)
    return plaintext, metadata
