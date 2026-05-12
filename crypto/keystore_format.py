"""
crypto/keystore_format.py
=========================
Formato JSON del keystore D6 y envelope AEAD que protege las llaves
privadas en disco.

Responsabilidades:
  - Serializar / deserializar el bundle de llaves privadas
    (Ed25519 + X25519) hacia bytes.
  - Cifrar / descifrar ese bundle con AES-256-GCM usando una clave
    derivada por crypto.kdf.
  - Construir el dict JSON v1 del keystore y validar el esquema al
    leerlo desde disco.

Lo que NO hace este modulo:
  - Pedir passwords ni manejar I/O de archivos (eso vive en
    crypto/keystore.py, Fase 2).
  - Derivar claves desde el password (eso vive en crypto/kdf.py).
  - Decisiones de ciclo de vida (rotacion, revocacion, etc.).
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

from . import kdf as _kdf


# ── constantes ────────────────────────────────────────────────────────────────

KEYSTORE_VERSION = 1
ENVELOPE_NONCE_SIZE = 12   # 96 bits, requerido por AES-GCM
ENVELOPE_TAG_SIZE   = 16

VALID_STATUS = {"active", "rotated", "revoked"}


# ── helpers base64 ────────────────────────────────────────────────────────────

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    if not isinstance(data, str):
        raise ValueError("se esperaba string base64")
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ValueError(f"base64 invalido: {exc}") from exc


# ── serializacion del bundle privado ──────────────────────────────────────────
#
# El bundle es un JSON pequenito con las dos llaves privadas en raw
# (32 bytes cada una). Se cifra entero con AES-GCM. El JSON es interno
# del envelope; el formato exterior del keystore es el del bloque mas
# abajo.

def _serialize_private_bundle(
    ed25519_priv: Ed25519PrivateKey,
    x25519_priv:  Optional[X25519PrivateKey],
) -> bytes:
    ed_raw = ed25519_priv.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    bundle = {
        "ed25519_priv_b64": _b64e(ed_raw),
    }
    if x25519_priv is not None:
        x_raw = x25519_priv.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )
        bundle["x25519_priv_b64"] = _b64e(x_raw)
    return json.dumps(bundle, separators=(",", ":")).encode("utf-8")


def _deserialize_private_bundle(
    plaintext: bytes,
) -> Tuple[Ed25519PrivateKey, Optional[X25519PrivateKey]]:
    try:
        bundle = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"bundle privado corrupto: {exc}") from exc
    if not isinstance(bundle, dict) or "ed25519_priv_b64" not in bundle:
        raise ValueError("bundle privado: falta ed25519_priv_b64")

    ed = Ed25519PrivateKey.from_private_bytes(_b64d(bundle["ed25519_priv_b64"]))
    x  = None
    if "x25519_priv_b64" in bundle:
        x = X25519PrivateKey.from_private_bytes(_b64d(bundle["x25519_priv_b64"]))
    return ed, x


# ── envelope AEAD ─────────────────────────────────────────────────────────────

def encrypt_private_bundle(
    bundle_plaintext: bytes,
    derived_key: bytes,
) -> Tuple[bytes, bytes, bytes]:
    """
    Cifra el bundle privado con AES-256-GCM.

    Retorna (nonce, ciphertext_sin_tag, tag).

    AAD no se usa: toda la informacion publica vive en el JSON exterior
    y NO necesita estar ligada al bundle porque el bundle se identifica
    univocamente por (salt, kdf_params, nonce). Una manipulacion de los
    campos publicos del JSON resulta en una clave derivada distinta o
    en un nonce/tag inconsistentes -> InvalidTag al descifrar.
    """
    if len(derived_key) != 32:
        raise ValueError(f"derived_key debe ser 32 bytes, recibido {len(derived_key)}")

    aes = AESGCM(derived_key)
    nonce = os.urandom(ENVELOPE_NONCE_SIZE)
    full = aes.encrypt(nonce, bundle_plaintext, associated_data=None)
    ciphertext = full[:-ENVELOPE_TAG_SIZE]
    tag        = full[-ENVELOPE_TAG_SIZE:]
    return nonce, ciphertext, tag


def decrypt_private_bundle(
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    derived_key: bytes,
) -> bytes:
    """
    Descifra el bundle. Lanza InvalidTag si:
      - el password (o la derivacion) es incorrecto,
      - el ciphertext / nonce / tag fueron manipulados.
    """
    if len(derived_key) != 32:
        raise ValueError(f"derived_key debe ser 32 bytes, recibido {len(derived_key)}")
    if len(nonce) != ENVELOPE_NONCE_SIZE:
        raise ValueError(f"nonce debe ser {ENVELOPE_NONCE_SIZE} bytes, recibido {len(nonce)}")
    if len(tag) != ENVELOPE_TAG_SIZE:
        raise ValueError(f"tag debe ser {ENVELOPE_TAG_SIZE} bytes, recibido {len(tag)}")
    aes = AESGCM(derived_key)
    return aes.decrypt(nonce, ciphertext + tag, associated_data=None)


# ── construccion del JSON del keystore ────────────────────────────────────────

def public_key_fingerprints(
    ed25519_pub: Ed25519PublicKey,
    x25519_pub:  Optional[X25519PublicKey],
) -> Dict[str, str]:
    """SHA-256 hex de las llaves publicas, formato de identidad (D5)."""
    import hashlib
    ed_raw = ed25519_pub.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    fps = {"ed25519": hashlib.sha256(ed_raw).hexdigest()}
    if x25519_pub is not None:
        x_raw = x25519_pub.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw,
        )
        fps["x25519"] = hashlib.sha256(x_raw).hexdigest()
    return fps


def build_keystore_dict(
    name: str,
    ed25519_priv: Ed25519PrivateKey,
    x25519_priv:  Optional[X25519PrivateKey],
    derived_key:  bytes,
    salt:         bytes,
    kdf_params:   Dict[str, int],
    *,
    status:       str = "active",
    expires_at:   Optional[str] = None,
    comment:      str = "",
    rotated_from: Optional[str] = None,
    created_at:   Optional[str] = None,
) -> dict:
    """
    Construye el dict JSON v1 del keystore para una identidad recien
    creada o re-cifrada. No escribe nada en disco: solo retorna el dict.
    """
    if status not in VALID_STATUS:
        raise ValueError(f"status invalido: {status} (esperado: {sorted(VALID_STATUS)})")
    _kdf.validate_params(kdf_params)
    if len(salt) < 8:
        raise ValueError("salt debe ser >= 8 bytes")

    bundle_plain = _serialize_private_bundle(ed25519_priv, x25519_priv)
    nonce, ciphertext, tag = encrypt_private_bundle(bundle_plain, derived_key)

    ed25519_pub = ed25519_priv.public_key()
    x25519_pub  = x25519_priv.public_key() if x25519_priv is not None else None

    pub_block = {
        "ed25519_pub_b64": _b64e(ed25519_pub.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw,
        )),
    }
    if x25519_pub is not None:
        pub_block["x25519_pub_b64"] = _b64e(x25519_pub.public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw,
        ))

    return {
        "version":    KEYSTORE_VERSION,
        "name":       name,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status":     status,
        "kdf": {
            "algorithm": "scrypt",
            "salt_b64":  _b64e(salt),
            "n":         kdf_params["n"],
            "r":         kdf_params["r"],
            "p":         kdf_params["p"],
            "dklen":     kdf_params["dklen"],
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "nonce_b64": _b64e(nonce),
            "tag_b64":   _b64e(tag),
        },
        "encrypted_private_key": _b64e(ciphertext),
        "public_keys":  pub_block,
        "fingerprints": public_key_fingerprints(ed25519_pub, x25519_pub),
        "metadata": {
            "comment":      comment,
            "expires_at":   expires_at,
            "rotated_from": rotated_from,
        },
    }


# ── validacion del esquema al leer ────────────────────────────────────────────

_REQUIRED_TOP_KEYS = {
    "version", "name", "created_at", "status",
    "kdf", "encryption", "encrypted_private_key",
    "public_keys", "fingerprints", "metadata",
}
_REQUIRED_KDF_KEYS   = {"algorithm", "salt_b64", "n", "r", "p", "dklen"}
_REQUIRED_ENC_KEYS   = {"algorithm", "nonce_b64", "tag_b64"}
_REQUIRED_META_KEYS  = {"comment", "expires_at", "rotated_from"}


def validate_keystore_schema(data: dict) -> None:
    """
    Valida estructura del dict del keystore. Lanza ValueError con
    mensaje especifico si algo falla. NO descifra nada.
    """
    if not isinstance(data, dict):
        raise ValueError("keystore: se esperaba un objeto JSON")

    missing = _REQUIRED_TOP_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"keystore: faltan campos {sorted(missing)}")

    if data["version"] != KEYSTORE_VERSION:
        raise ValueError(
            f"keystore: version no soportada {data['version']!r} "
            f"(este sistema usa v{KEYSTORE_VERSION})"
        )
    if not isinstance(data["name"], str) or not data["name"]:
        raise ValueError("keystore: campo 'name' invalido")
    if data["status"] not in VALID_STATUS:
        raise ValueError(f"keystore: status invalido {data['status']!r}")

    kdf = data["kdf"]
    if not isinstance(kdf, dict) or _REQUIRED_KDF_KEYS - set(kdf.keys()):
        raise ValueError(f"keystore.kdf: faltan campos {sorted(_REQUIRED_KDF_KEYS - set(kdf.keys()))}")
    if kdf["algorithm"] != "scrypt":
        raise ValueError(f"keystore.kdf: algoritmo no soportado {kdf['algorithm']!r}")

    enc = data["encryption"]
    if not isinstance(enc, dict) or _REQUIRED_ENC_KEYS - set(enc.keys()):
        raise ValueError(f"keystore.encryption: faltan campos")
    if enc["algorithm"] != "AES-256-GCM":
        raise ValueError(f"keystore.encryption: algoritmo no soportado {enc['algorithm']!r}")

    if not isinstance(data["encrypted_private_key"], str):
        raise ValueError("keystore.encrypted_private_key: se esperaba base64 string")

    meta = data["metadata"]
    if not isinstance(meta, dict) or _REQUIRED_META_KEYS - set(meta.keys()):
        raise ValueError("keystore.metadata: faltan campos")


# ── desempaquetado completo (validar + derivar + descifrar) ───────────────────

def unlock_keystore_dict(
    data: dict,
    password: str,
) -> Tuple[Ed25519PrivateKey, Optional[X25519PrivateKey]]:
    """
    Pipeline completo:
      1. validar esquema
      2. derivar clave con scrypt(password, salt, params)
      3. descifrar con AES-256-GCM
      4. deserializar bundle de llaves privadas

    Lanza:
        ValueError     -- esquema invalido o parametros KDF malos
        InvalidTag     -- password incorrecto o keystore modificado
                          (proviene de cryptography.exceptions; no se
                          atrapa aqui para que el caller distinga
                          'password equivocado' de 'estructura rota')
    """
    validate_keystore_schema(data)

    salt   = _b64d(data["kdf"]["salt_b64"])
    params = {
        "n": data["kdf"]["n"],
        "r": data["kdf"]["r"],
        "p": data["kdf"]["p"],
        "dklen": data["kdf"]["dklen"],
    }
    nonce      = _b64d(data["encryption"]["nonce_b64"])
    tag        = _b64d(data["encryption"]["tag_b64"])
    ciphertext = _b64d(data["encrypted_private_key"])

    derived = _kdf.derive_key(password, salt, params)
    plain   = decrypt_private_bundle(ciphertext, nonce, tag, derived)
    return _deserialize_private_bundle(plain)
