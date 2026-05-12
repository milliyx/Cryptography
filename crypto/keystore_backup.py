"""
crypto/keystore_backup.py
=========================
Backup y recuperacion de identidades del keystore D6.

Un backup es un archivo `.sddv_backup` que contiene el mismo bundle
de llaves privadas re-cifrado con un PASSWORD DE BACKUP independiente
del password activo. Esto permite:

  - Almacenar el backup en un medio distinto (USB, gestor de
    contrasenas, papel) con un password aparte que el operativo.
  - Restaurar una identidad si el keystore activo se pierde.
  - Renombrar la identidad al restaurar (`--name` en la CLI).

Por que NO copiar tal cual el JSON del keystore:

  Si solo copiaramos `<name>.json`, una persona con acceso al
  backup podria correr ataque offline con el mismo password activo
  del usuario. Re-cifrar con un password de backup obliga al
  atacante a:
    a) romper el password de backup (uno mas), o
    b) romper el password activo Y obtener el keystore activo.
  Esto es defense-in-depth: la separacion de secretos.

Formato del backup (`.sddv_backup`):

  Es un JSON con la misma estructura que el keystore + dos campos:
    "backup_of":  "<nombre_original>"
    "backup_at":  "<iso8601 UTC>"
  El bloque `kdf` y `encryption` se generan frescos al exportar.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from . import kdf as _kdf
from . import keystore_format as _ksf
from .keys import validate_password_strength
from .keystore import KeyStore, KeyStoreError, IdentityAlreadyExistsError


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# ── export ────────────────────────────────────────────────────────────────────

def export_backup(
    keystore: KeyStore,
    name: str,
    active_password: str,
    backup_password: str,
    out_path: str,
    *,
    force_weak_backup_password: bool = False,
) -> str:
    """
    Exporta la identidad `name` a un archivo `.sddv_backup` cifrado con
    `backup_password` (independiente del activo).

    El proceso descifra el bundle con `active_password`, re-deriva una
    clave nueva con `backup_password` y re-cifra. Las llaves privadas
    NUNCA se escriben en claro: la transicion ocurre completamente en
    memoria.

    Retorna la ruta del archivo creado (str).
    """
    if not force_weak_backup_password:
        validate_password_strength(backup_password)
    elif not backup_password:
        raise ValueError("backup_password vacio")

    # 1. Abrir la identidad activa (verifica autoria de quien hace backup)
    ed_priv = keystore.unlock_signing_key(name, active_password)
    # X25519 puede no existir si la identidad fue creada con with_x25519=False
    try:
        x_priv = keystore.unlock_encryption_key(name, active_password)
    except KeyStoreError:
        x_priv = None

    # 2. Re-cifrar con material fresco bajo el backup_password
    params = dict(_kdf.DEFAULT_KDF_PARAMS)
    # En tests podemos querer parametros rapidos; respetamos los del keystore.
    if getattr(keystore, "_kdf_params", None):
        params = dict(keystore._kdf_params)
    salt = _kdf.generate_salt()
    dk   = _kdf.derive_key(backup_password, salt, params)

    # Preservamos metadatos relevantes del original para auditoria.
    orig = keystore._read(name)
    backup_dict = _ksf.build_keystore_dict(
        name=name,
        ed25519_priv=ed_priv,
        x25519_priv=x_priv,
        derived_key=dk,
        salt=salt,
        kdf_params=params,
        comment=orig["metadata"].get("comment", ""),
        expires_at=orig["metadata"].get("expires_at"),
        rotated_from=orig["metadata"].get("rotated_from"),
        created_at=orig["created_at"],
    )
    # Marcadores extra que identifican el archivo como backup.
    backup_dict["backup_of"] = name
    backup_dict["backup_at"] = _now_iso()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(backup_dict, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(out)


# ── import ────────────────────────────────────────────────────────────────────

def import_backup(
    keystore: KeyStore,
    backup_path: str,
    backup_password: str,
    new_active_password: str,
    *,
    name: str = None,
    force_weak_active_password: bool = False,
) -> Dict[str, str]:
    """
    Restaura una identidad desde un archivo `.sddv_backup` al keystore.

    El proceso:
      1. Lee el JSON del backup.
      2. Descifra con `backup_password`.
      3. Re-cifra con `new_active_password` (nuevo salt + nuevo nonce).
      4. Persiste como `<name>.json` en el directorio del keystore.

    Lanza:
        InvalidTag                   -- backup_password incorrecto o
                                        archivo de backup corrupto.
        IdentityAlreadyExistsError   -- ya hay `<name>.json` (no
                                        sobreescribe; renombrar primero).
        ValueError                   -- el archivo no es un backup valido.
    """
    if not force_weak_active_password:
        validate_password_strength(new_active_password)
    elif not new_active_password:
        raise ValueError("new_active_password vacio")

    path = Path(backup_path)
    if not path.is_file():
        raise FileNotFoundError(f"backup no encontrado: {backup_path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"backup ilegible: {exc}") from exc

    if "backup_of" not in data:
        raise ValueError("el archivo no parece ser un backup SDDV (.sddv_backup)")

    # Validar y descifrar con backup_password.
    # InvalidTag (de cryptography) sube tal cual si el password es malo.
    ed_priv, x_priv = _ksf.unlock_keystore_dict(data, backup_password)

    target_name = name or data.get("name") or data["backup_of"]

    if keystore.exists(target_name):
        raise IdentityAlreadyExistsError(
            f"ya existe '{target_name}' en el keystore; usa --name para renombrar"
        )

    # Re-cifrar para el keystore activo.
    params = dict(getattr(keystore, "_kdf_params", _kdf.DEFAULT_KDF_PARAMS))
    salt   = _kdf.generate_salt()
    dk     = _kdf.derive_key(new_active_password, salt, params)
    new_data = _ksf.build_keystore_dict(
        name=target_name,
        ed25519_priv=ed_priv,
        x25519_priv=x_priv,
        derived_key=dk,
        salt=salt,
        kdf_params=params,
        comment=data["metadata"].get("comment", ""),
        expires_at=data["metadata"].get("expires_at"),
        rotated_from=data["metadata"].get("rotated_from"),
        created_at=data["created_at"],
    )
    keystore._write(target_name, new_data, overwrite=False)

    return {
        "name":           target_name,
        "ed25519_fp":     new_data["fingerprints"]["ed25519"],
        "x25519_fp":      new_data["fingerprints"].get("x25519", ""),
        "restored_from":  str(path),
    }
