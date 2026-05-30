"""
sddv_api.py — wrapper que expone funciones de src/ a JavaScript via Pyodide.

Cada funcion retorna dicts/bytes/strings sencillos para que `.toJs()` los
convierta sin friccion. Excepciones suben tal cual; el lado JS las atrapa.
"""
from __future__ import annotations
import base64
import json
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from src import kdf as _kdf
from src import keystore_format as _ksf
from src.keystore import KeyStore, IdentityAlreadyExistsError
from src.keystore_backup import export_backup, import_backup
from src.secure_send import (
    encrypt_and_sign_from_keystore,
    verify_and_decrypt_from_keystore,
)


# El keystore vive bajo /keystore (montado en IndexedDB por el runtime JS).
KEYSTORE_DIR = "/keystore"


def _ks() -> KeyStore:
    return KeyStore(KEYSTORE_DIR)


# ──────────────────────────────────────────────────────────────────────────
# Identidades
# ──────────────────────────────────────────────────────────────────────────

def create_identity(name: str, password: str, comment: str = "") -> dict:
    ks = _ks()
    info = ks.init_identity(name, password, comment=comment)
    return dict(info)


def list_identities() -> list:
    return list(_ks().list_identities())


def get_public_info(name: str) -> dict:
    """Devuelve la info publica de una identidad: fingerprints + pub keys en hex."""
    pub = _ks().get_public_keys(name)
    ed_raw = pub["ed25519_pub"].public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    ) if pub["ed25519_pub"] else None
    x_raw = pub["x25519_pub"].public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    ) if pub["x25519_pub"] else None
    return {
        "name":          name,
        "fingerprints":  dict(pub["fingerprints"]),
        "ed25519_pub_hex": ed_raw.hex() if ed_raw else None,
        "x25519_pub_hex":  x_raw.hex()  if x_raw  else None,
        "status":        pub["status"],
        "expires_at":    pub["expires_at"],
    }


def revoke_identity(name: str, reason: str = "") -> None:
    _ks().revoke(name, reason=reason)


def rotate_identity(name: str, password: str) -> dict:
    return dict(_ks().rotate_keys(name, password))


def change_password(name: str, old_password: str, new_password: str) -> None:
    """Re-cifra la identidad con un nuevo password (mismo material clave)."""
    _ks().change_password(name, old_password, new_password)


def delete_identity(name: str, password: str) -> None:
    _ks().delete(name, password)


# ──────────────────────────────────────────────────────────────────────────
# Cifrado + firma (D5 flow)
# ──────────────────────────────────────────────────────────────────────────

def encrypt_and_sign(
    sender_name: str,
    sender_password: str,
    recipient_x25519_hex_list: List[str],
    plaintext: bytes,
    filename: str,
) -> bytes:
    """Cifra para destinatarios (por sus pub X25519 raw en hex) y firma con la
    identidad del remitente. Devuelve el contenedor SDDH firmado."""
    recipients = []
    for hex_pub in recipient_x25519_hex_list:
        try:
            raw = bytes.fromhex(hex_pub.strip())
        except ValueError as e:
            raise ValueError(f"X25519 pub no es hex valido: {e}")
        if len(raw) != 32:
            raise ValueError(f"X25519 pub debe ser 32 bytes (64 hex), recibido {len(raw)}")
        recipients.append(X25519PublicKey.from_public_bytes(raw))

    if not recipients:
        raise ValueError("Sin destinatarios")

    container = encrypt_and_sign_from_keystore(
        keystore=_ks(),
        sender_name=sender_name,
        sender_password=sender_password,
        plaintext=bytes(plaintext),
        filename=filename,
        recipients_x25519=recipients,
    )
    return container


def verify_and_decrypt(
    recipient_name: str,
    recipient_password: str,
    signed_container: bytes,
    expected_signer_ed25519_hex: str,
) -> dict:
    """Verifica firma y descifra. Lanza si la firma no es del firmante esperado.

    Devuelve { plaintext: bytes, metadata: dict (filename, timestamp, ...) }
    """
    try:
        ed_raw = bytes.fromhex(expected_signer_ed25519_hex.strip())
    except ValueError as e:
        raise ValueError(f"Fingerprint Ed25519 esperado no es hex valido: {e}")
    if len(ed_raw) != 32:
        raise ValueError("La llave Ed25519 esperada debe ser 32 bytes (64 hex)")

    pub = Ed25519PublicKey.from_public_bytes(ed_raw)
    plaintext, metadata = verify_and_decrypt_from_keystore(
        keystore=_ks(),
        recipient_name=recipient_name,
        recipient_password=recipient_password,
        signed_container=bytes(signed_container),
        expected_signer_pub=pub,
    )
    # metadata trae cosas no-serializables (Algorithm IntEnum); simplificamos
    meta_out = {
        "filename":  metadata.get("filename"),
        "timestamp": int(metadata.get("timestamp", 0)),
        "algorithm": int(metadata["algo"]) if "algo" in metadata else None,
        "recipients_fp": [r["fingerprint"] for r in metadata.get("recipients", [])],
    }
    return {"plaintext": plaintext, "metadata": meta_out}


# ──────────────────────────────────────────────────────────────────────────
# Backup / restore
# ──────────────────────────────────────────────────────────────────────────

def backup_export(name: str, active_pwd: str, backup_pwd: str) -> str:
    """Exporta un backup a un archivo temporal y retorna su contenido JSON."""
    tmp = f"/tmp_backup_{name}.sddv_backup"
    Path("/").mkdir(parents=True, exist_ok=True)
    path = export_backup(_ks(), name, active_pwd, backup_pwd, tmp)
    text = Path(path).read_text(encoding="utf-8")
    try:
        Path(path).unlink()
    except OSError:
        pass
    return text


def backup_import(
    backup_json_text: str,
    backup_pwd: str,
    new_active_pwd: str,
    as_name: Optional[str] = None,
) -> dict:
    tmp = "/tmp_backup_in.sddv_backup"
    Path(tmp).write_text(backup_json_text, encoding="utf-8")
    try:
        return dict(import_backup(_ks(), tmp, backup_pwd, new_active_pwd, name=as_name or None))
    finally:
        try:
            Path(tmp).unlink()
        except OSError:
            pass
