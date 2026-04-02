"""
crypto/hybrid.py
================
Cifrado hibrido multi-destinatario para la Boveda Digital Segura de Documentos (SDDV).
Entregable D3 del proyecto.

Protocolo KEM+DEM:
  1. Generar file_key aleatorio de 256 bits.
  2. Cifrar el plaintext con AES-256-GCM o ChaCha20-Poly1305 (DEM) usando file_key
     y el AAD completo (cabecera entera, incluida la lista de destinatarios).
  3. Para cada destinatario (KEM por X25519 ECDH):
     a. Generar par efimero X25519 (eph_priv, eph_pub).
     b. shared = ECDH(eph_priv, recipient_x25519_pub)  — 32 bytes
     c. wrapping_key = HKDF-SHA256(shared, salt=fingerprint, info=b"SDDV-D3-wrap")
     d. wrapped = AESGCM(wrapping_key).encrypt(nonce, file_key, aad=None)
     e. Almacenar (fingerprint, eph_pub, nonce, wrapped) en la cabecera.
  4. La cabecera completa (incluyendo la lista de destinatarios) es el AAD del DEM.
     Cualquier modificacion a la lista invalida el tag del contenido.

Para descifrar:
  1. El destinatario busca su fingerprint en la cabecera.
  2. Reconstruye shared = ECDH(recipient_x25519_priv, eph_pub).
  3. Reconstruye wrapping_key con HKDF.
  4. Descifra wrapped para obtener file_key.
  5. Descifra el payload con file_key usando el AAD = cabecera completa.

Formato del contenedor:
  MAGIC(4)          b"SDDH"
  VERSION(1)        = 1
  ALGO_ID(1)        0x01=AES-256-GCM, 0x02=ChaCha20-Poly1305
  TIMESTAMP(8)      Unix time big-endian uint64
  FILENAME_LEN(2)   big-endian uint16
  FILENAME          variable, UTF-8
  RECIPIENT_COUNT(2) big-endian uint16
  [Por cada destinatario — 124 bytes fijos:]
    FINGERPRINT(32)   SHA-256 del raw X25519 public key del destinatario
    EPH_PUB(32)       clave publica X25519 efimera para este destinatario
    WRAP_NONCE(12)    nonce para el AES-GCM de envolvimiento
    WRAPPED_KEY(48)   file_key cifrado: ciphertext(32) + tag(16)
  --- FIN DEL AAD ---
  NONCE(12)         nonce para el DEM
  CT_LEN(4)         longitud del ciphertext big-endian uint32
  CIPHERTEXT        variable
  TAG(16)           tag de autenticacion del DEM

El TAG del DEM cubre: CIPHERTEXT + AAD(cabecera completa con lista de destinatarios).
Modificar cualquier byte de cualquier seccion invalida el TAG.

Dependencias: cryptography
"""

import hashlib
import os
import struct
import time
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.aead import Algorithm, NONCE_SIZE, TAG_SIZE, KEY_SIZE

MAGIC_HYBRID    = b"SDDH"
VERSION_HYBRID  = 1

# Tamanios fijos dentro de cada entrada de destinatario
FINGERPRINT_SIZE = 32            # SHA-256(raw X25519 pubkey)
EPH_PUB_SIZE     = 32            # X25519 public key raw
WRAP_NONCE_SIZE  = 12            # nonce para AES-GCM de envolvimiento
WRAPPED_KEY_SIZE = KEY_SIZE + TAG_SIZE   # 32 ct + 16 tag = 48

RECIPIENT_ENTRY_SIZE = FINGERPRINT_SIZE + EPH_PUB_SIZE + WRAP_NONCE_SIZE + WRAPPED_KEY_SIZE
# = 32 + 32 + 12 + 48 = 124 bytes por destinatario


# ── Gestion de claves X25519 ─────────────────────────────────────────────────

def generate_x25519_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """Genera un par de claves X25519 para cifrado hibrido."""
    private_key = X25519PrivateKey.generate()
    public_key  = private_key.public_key()
    return private_key, public_key


def get_x25519_fingerprint(public_key: X25519PublicKey) -> str:
    """
    Retorna el fingerprint SHA-256 de la clave publica X25519 como hex de 64 caracteres.
    Identifica univocamente a un destinatario sin revelar la clave completa.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def get_x25519_fingerprint_bytes(public_key: X25519PublicKey) -> bytes:
    """Retorna el fingerprint SHA-256 como 32 bytes (para incluir en el contenedor)."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).digest()


def x25519_public_key_to_bytes(public_key: X25519PublicKey) -> bytes:
    """Serializa una clave publica X25519 a 32 bytes raw."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_key_from_bytes(data: bytes) -> X25519PublicKey:
    """Deserializa una clave publica X25519 desde 32 bytes raw."""
    return X25519PublicKey.from_public_bytes(data)


# ── KEM: Key Encapsulation Mechanism ─────────────────────────────────────────

def _derive_wrapping_key(shared_secret: bytes, fingerprint_bytes: bytes) -> bytes:
    """
    Deriva la clave de envolvimiento usando HKDF-SHA256.
    El fingerprint del destinatario actua como salt, enlazando la clave derivada
    a la identidad del destinatario.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=fingerprint_bytes,
        info=b"SDDV-D3-wrap",
    )
    return hkdf.derive(shared_secret)


def _wrap_file_key(
    file_key: bytes,
    recipient_pub: X25519PublicKey,
) -> Tuple[bytes, bytes, bytes]:
    """
    Envuelve (cifra) el file_key para un destinatario especifico usando X25519 ECDH + AES-GCM.

    Retorna:
        eph_pub_bytes : 32 bytes — clave publica efimera a incluir en el contenedor
        wrap_nonce    : 12 bytes — nonce del AES-GCM de envolvimiento
        wrapped       : 48 bytes — ciphertext(32) + tag(16) del file_key cifrado
    """
    fingerprint_bytes = get_x25519_fingerprint_bytes(recipient_pub)

    # Par efimero X25519 fresco para este destinatario (forward secrecy)
    eph_priv = X25519PrivateKey.generate()
    eph_pub  = eph_priv.public_key()

    # ECDH: secreto compartido de 32 bytes
    shared_secret = eph_priv.exchange(recipient_pub)

    # Derivar wrapping key con HKDF
    wrapping_key = _derive_wrapping_key(shared_secret, fingerprint_bytes)

    # Cifrar el file_key con AES-GCM sin AAD adicional
    wrap_nonce = os.urandom(WRAP_NONCE_SIZE)
    aes        = AESGCM(wrapping_key)
    wrapped    = aes.encrypt(wrap_nonce, file_key, None)   # 48 bytes: 32 ct + 16 tag

    return x25519_public_key_to_bytes(eph_pub), wrap_nonce, wrapped


def _unwrap_file_key(
    recipient_priv: X25519PrivateKey,
    eph_pub_bytes: bytes,
    wrap_nonce: bytes,
    wrapped: bytes,
    fingerprint_bytes: bytes,
) -> bytes:
    """
    Desenvuelve el file_key usando la clave privada X25519 del destinatario.
    Lanza InvalidTag si la clave o los datos son incorrectos.
    """
    eph_pub       = x25519_public_key_from_bytes(eph_pub_bytes)
    shared_secret = recipient_priv.exchange(eph_pub)
    wrapping_key  = _derive_wrapping_key(shared_secret, fingerprint_bytes)
    aes           = AESGCM(wrapping_key)
    return aes.decrypt(wrap_nonce, wrapped, None)


# ── Construccion y parseo del contenedor hibrido ─────────────────────────────

def _build_hybrid_header(
    filename: str,
    algo: Algorithm,
    recipients_data: bytes,
    n_recipients: int,
    timestamp: Optional[int] = None,
) -> bytes:
    """
    Construye la cabecera del contenedor hibrido.
    La cabecera completa se usa como AAD del DEM.

    Formato:
      MAGIC(4) + VERSION(1) + ALGO(1) + TIMESTAMP(8) +
      FNAME_LEN(2) + FNAME + RECIPIENT_COUNT(2) + [ENTRY x N]
    """
    if timestamp is None:
        timestamp = int(time.time())
    fname_bytes = filename.encode("utf-8")
    if len(fname_bytes) > 0xFFFF:
        raise ValueError("Nombre de archivo demasiado largo")
    return (
        MAGIC_HYBRID
        + bytes([VERSION_HYBRID, int(algo)])
        + struct.pack(">Q", timestamp)
        + struct.pack(">H", len(fname_bytes))
        + fname_bytes
        + struct.pack(">H", n_recipients)
        + recipients_data
    )


def _parse_hybrid_header(data: bytes) -> Tuple[dict, int]:
    """
    Parsea la cabecera del contenedor hibrido.

    Retorna: (metadata_dict, header_end_offset)
    """
    if len(data) < 18:
        raise ValueError("Contenedor demasiado corto")
    if data[:4] != MAGIC_HYBRID:
        raise ValueError(
            f"Magic bytes invalidos - se esperaba {MAGIC_HYBRID!r}, "
            f"se recibio {data[:4]!r}"
        )
    version = data[4]
    if version != VERSION_HYBRID:
        raise ValueError(f"Version no soportada: {version}")
    algo      = Algorithm(data[5])
    timestamp = struct.unpack(">Q", data[6:14])[0]
    fname_len = struct.unpack(">H", data[14:16])[0]
    pos       = 16 + fname_len
    if len(data) < pos + 2:
        raise ValueError("Cabecera truncada: falta RECIPIENT_COUNT")
    filename     = data[16:pos].decode("utf-8")
    n_recipients = struct.unpack(">H", data[pos : pos + 2])[0]
    pos += 2

    recipients = []
    for i in range(n_recipients):
        if len(data) < pos + RECIPIENT_ENTRY_SIZE:
            raise ValueError(f"Cabecera truncada: falta entrada de destinatario {i}")
        fp_bytes  = data[pos                              : pos + FINGERPRINT_SIZE]
        eph_bytes = data[pos + FINGERPRINT_SIZE           : pos + FINGERPRINT_SIZE + EPH_PUB_SIZE]
        w_nonce   = data[pos + FINGERPRINT_SIZE + EPH_PUB_SIZE
                         : pos + FINGERPRINT_SIZE + EPH_PUB_SIZE + WRAP_NONCE_SIZE]
        wrapped   = data[pos + FINGERPRINT_SIZE + EPH_PUB_SIZE + WRAP_NONCE_SIZE
                         : pos + RECIPIENT_ENTRY_SIZE]
        recipients.append({
            "fingerprint_bytes": fp_bytes,
            "fingerprint":       fp_bytes.hex(),
            "eph_pub_bytes":     eph_bytes,
            "wrap_nonce":        w_nonce,
            "wrapped":           wrapped,
        })
        pos += RECIPIENT_ENTRY_SIZE

    metadata = {
        "version":    version,
        "algo":       algo,
        "timestamp":  timestamp,
        "filename":   filename,
        "recipients": recipients,
    }
    return metadata, pos


# ── API publica ───────────────────────────────────────────────────────────────

def encrypt_for_recipients(
    plaintext: bytes,
    filename: str,
    recipients: List[X25519PublicKey],
    algo: Algorithm = Algorithm.AES_256_GCM,
    timestamp: Optional[int] = None,
) -> bytes:
    """
    Cifra plaintext para una lista de destinatarios X25519 (KEM+DEM).

    Cualquiera de los destinatarios puede descifrar usando su clave privada.
    La lista de destinatarios y todos los metadatos quedan vinculados al tag AEAD:
    modificar la lista invalida el contenido.

    Parametros:
        plaintext  : bytes a cifrar
        filename   : nombre del archivo (autenticado en el AAD)
        recipients : lista de claves publicas X25519 de los destinatarios autorizados
        algo       : AES_256_GCM (default) o CHACHA20_POLY1305
        timestamp  : timestamp Unix opcional; si es None se usa time.time()

    Retorna: container_bytes (contenedor SDDH completo)

    Lanza:
        ValueError — si la lista de destinatarios esta vacia
    """
    if not recipients:
        raise ValueError("Se necesita al menos un destinatario")

    # 1. Generar file_key aleatorio (DEM key)
    file_key = os.urandom(KEY_SIZE)

    # 2. KEM: envolver file_key para cada destinatario
    recipient_entries = b""
    for pub in recipients:
        fp_bytes                       = get_x25519_fingerprint_bytes(pub)
        eph_pub_bytes, wrap_nonce, wrapped = _wrap_file_key(file_key, pub)
        recipient_entries += fp_bytes + eph_pub_bytes + wrap_nonce + wrapped

    # 3. Construir cabecera (= AAD del DEM)
    header = _build_hybrid_header(filename, algo, recipient_entries, len(recipients), timestamp)

    # 4. DEM: cifrar plaintext con file_key; el AAD es la cabecera completa
    nonce       = os.urandom(NONCE_SIZE)
    cipher      = AESGCM(file_key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(file_key)
    ct_with_tag = cipher.encrypt(nonce, plaintext, header)
    ciphertext  = ct_with_tag[:-TAG_SIZE]
    tag         = ct_with_tag[-TAG_SIZE:]

    return header + nonce + struct.pack(">I", len(ciphertext)) + ciphertext + tag


def decrypt_for_recipient(
    container: bytes,
    private_key: X25519PrivateKey,
) -> Tuple[bytes, dict]:
    """
    Descifra un contenedor hibrido usando la clave privada X25519 del destinatario.

    Parametros:
        container   : bytes del contenedor SDDH
        private_key : clave privada X25519 del destinatario

    Retorna: (plaintext, metadata)

    Lanza:
        ValueError  — si el contenedor esta malformado o el destinatario no esta en la lista
        InvalidTag  — si la clave es incorrecta o alguna parte del contenedor fue manipulada
    """
    metadata, header_end = _parse_hybrid_header(container)
    header = container[:header_end]
    algo   = metadata["algo"]

    # Identificar entrada del destinatario por su fingerprint
    my_fp_bytes = get_x25519_fingerprint_bytes(private_key.public_key())
    entry = next(
        (e for e in metadata["recipients"] if e["fingerprint_bytes"] == my_fp_bytes),
        None,
    )
    if entry is None:
        raise ValueError("Este destinatario no esta autorizado en el contenedor")

    # KEM: desenvolver file_key
    file_key = _unwrap_file_key(
        private_key,
        entry["eph_pub_bytes"],
        entry["wrap_nonce"],
        entry["wrapped"],
        entry["fingerprint_bytes"],
    )

    # Parsear seccion cifrada
    pos = header_end
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

    # DEM: descifrar con file_key; el AAD (header) autentica los metadatos y la lista
    cipher    = AESGCM(file_key) if algo == Algorithm.AES_256_GCM else ChaCha20Poly1305(file_key)
    plaintext = cipher.decrypt(nonce, ciphertext + tag, header)

    return plaintext, metadata


def get_recipient_fingerprints(container: bytes) -> List[str]:
    """
    Retorna la lista de fingerprints (hex de 64 chars) de los destinatarios autorizados.
    No requiere clave — la informacion esta en texto claro en el contenedor.
    """
    metadata, _ = _parse_hybrid_header(container)
    return [e["fingerprint"] for e in metadata["recipients"]]


def is_hybrid_container(data: bytes) -> bool:
    """Retorna True si los datos corresponden a un contenedor hibrido SDDH."""
    return len(data) >= 4 and data[:4] == MAGIC_HYBRID
