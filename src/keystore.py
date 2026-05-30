"""
src/keystore.py
==================
Capa de gestion del keystore D6.

La clase `KeyStore` maneja un directorio con un archivo JSON por
identidad (`<name>.json`) y expone las operaciones del ciclo de
vida: crear, listar, leer publicas, abrir privadas con password,
cambiar password, rotar llaves, revocar y borrar.

Backup y recuperacion (export_backup / import_backup) viven en
src/keystore_backup.py (Fase 3 del plan D6).

Principios:
  - **No caching**: cada `unlock_*` re-lee el JSON, re-deriva la
    clave con scrypt y descifra. La clave derivada vive solo en el
    stack frame que llamo.
  - **Fail-closed**: cualquier inconsistencia (esquema invalido,
    archivo faltante, status != active) lanza una excepcion
    especifica antes de tocar el cifrado.
  - **Identidad consistente**: el nombre del archivo coincide con
    el campo `name` del JSON. Renombrar archivos no es soportado;
    para "renombrar" se usa `rotate_keys` o se borra y se crea.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
    PublicFormat,
)

from . import kdf as _kdf
from . import keystore_format as _ksf
from .keys import validate_password_strength


# ── excepciones especificas ───────────────────────────────────────────────────

class KeyStoreError(Exception):
    """Base para errores del keystore."""


class IdentityNotFoundError(KeyStoreError):
    """No existe `<name>.json` en el directorio."""


class IdentityAlreadyExistsError(KeyStoreError):
    """Ya existe `<name>.json`; init_identity no sobreescribe."""


class IdentityRevokedError(KeyStoreError):
    """status == 'revoked'; bloquea unlock_*."""


class IdentityExpiredError(KeyStoreError):
    """metadata.expires_at ya paso."""


# ── helpers internos ──────────────────────────────────────────────────────────

def _validate_name(name: str) -> None:
    """
    Asegura que el nombre se traduzca a un filename seguro.
    Bloquea separadores de path, `..`, `.`, vacios y filenames absurdos.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("nombre de identidad vacio")
    # No permitir caracteres que rompen el filename o que invitan a
    # path traversal. Reusamos la misma lista negra que aead.validate_filename
    # usa para los filenames del AAD.
    forbidden = set("\\/<>:\"|?*\0")
    if any(c in forbidden for c in name):
        raise ValueError(f"nombre de identidad invalido: {name!r}")
    if name in (".", "..") or name.startswith("."):
        raise ValueError(f"nombre de identidad invalido: {name!r}")
    if len(name) > 64:
        raise ValueError("nombre de identidad demasiado largo (max 64)")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _b64_to_bytes(s: str) -> bytes:
    import base64
    return base64.b64decode(s, validate=True)


# ── KeyStore ──────────────────────────────────────────────────────────────────

class KeyStore:
    """
    Maneja un directorio `<dir>/<name>.json` por identidad.

    Construccion:
        ks = KeyStore("keystore")           # crea el directorio si falta
        ks = KeyStore("keystore", create=False)  # exige que exista

    El parametro `kdf_params` permite override (util para tests rapidos);
    en produccion se ignora y se usa `DEFAULT_KDF_PARAMS`.
    """

    def __init__(
        self,
        directory: str,
        *,
        create: bool = True,
        kdf_params: Optional[Dict[str, int]] = None,
    ):
        self.dir = Path(directory)
        if create:
            self.dir.mkdir(parents=True, exist_ok=True)
        elif not self.dir.is_dir():
            raise FileNotFoundError(f"keystore directorio no existe: {self.dir}")
        self._kdf_params = dict(kdf_params or _kdf.DEFAULT_KDF_PARAMS)

    # ----- rutas internas -----

    def _path(self, name: str) -> Path:
        _validate_name(name)
        return self.dir / f"{name}.json"

    def _path_rotated(self, name: str, ts: str) -> Path:
        _validate_name(name)
        return self.dir / f"{name}.rotated-{ts}.json"

    # ----- I/O JSON -----

    def _read(self, name: str) -> dict:
        path = self._path(name)
        if not path.is_file():
            raise IdentityNotFoundError(f"identidad no encontrada: {name}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise KeyStoreError(f"identidad corrupta: {name}: {exc}") from exc
        _ksf.validate_keystore_schema(data)
        if data["name"] != name:
            raise KeyStoreError(
                f"keystore inconsistente: archivo {name}.json contiene name={data['name']!r}"
            )
        return data

    def _write(self, name: str, data: dict, *, overwrite: bool = False) -> None:
        _ksf.validate_keystore_schema(data)
        path = self._path(name)
        if path.exists() and not overwrite:
            raise IdentityAlreadyExistsError(f"ya existe: {name}")
        # Escritura "atomica" en el espiritu de POSIX: tmp -> rename.
        # Windows tambien soporta rename atomico cuando ambos archivos
        # estan en el mismo volumen.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(data, indent=2, sort_keys=False, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(tmp, path)

    # ----- consultas (sin password) -----

    def exists(self, name: str) -> bool:
        try:
            return self._path(name).is_file()
        except ValueError:
            return False

    def list_identities(self) -> List[Dict[str, str]]:
        """
        Lista la metadata publica de todas las identidades del directorio.
        NO descifra nada. Util para `python -m src list`.
        """
        out = []
        for p in sorted(self.dir.glob("*.json")):
            # Saltarse los archivos .rotated-*.json (son archivos historicos).
            if ".rotated-" in p.name:
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                _ksf.validate_keystore_schema(data)
            except Exception:
                # Lo ignoramos en la lista pero no lo borramos.
                continue
            out.append({
                "name":           data["name"],
                "status":         data["status"],
                "created_at":     data["created_at"],
                "ed25519_fp":     data["fingerprints"]["ed25519"],
                "x25519_fp":      data["fingerprints"].get("x25519", ""),
                "expires_at":     data["metadata"].get("expires_at"),
                "rotated_from":   data["metadata"].get("rotated_from"),
            })
        return out

    def get_public_keys(self, name: str) -> Dict[str, object]:
        """
        Retorna las llaves publicas + fingerprints + metadata, SIN pedir password.
        Util para que un remitente recupere la X25519 publica de un destinatario.
        """
        data = self._read(name)
        pub = data["public_keys"]
        ed_pub = Ed25519PublicKey.from_public_bytes(_b64_to_bytes(pub["ed25519_pub_b64"]))
        x_pub: Optional[X25519PublicKey] = None
        if "x25519_pub_b64" in pub:
            x_pub = X25519PublicKey.from_public_bytes(_b64_to_bytes(pub["x25519_pub_b64"]))
        return {
            "ed25519_pub":  ed_pub,
            "x25519_pub":   x_pub,
            "fingerprints": dict(data["fingerprints"]),
            "status":       data["status"],
            "expires_at":   data["metadata"].get("expires_at"),
        }

    # ----- creacion -----

    def init_identity(
        self,
        name: str,
        password: str,
        *,
        with_x25519: bool = True,
        expires_at: Optional[str] = None,
        comment: str = "",
        kdf_params: Optional[Dict[str, int]] = None,
        force_weak_password: bool = False,
    ) -> Dict[str, str]:
        """
        Genera un par Ed25519 (+X25519 si with_x25519) y persiste la
        identidad cifrada con el password.

        Retorna {"name", "ed25519_fp", "x25519_fp", "path"}.
        """
        _validate_name(name)
        if self.exists(name):
            raise IdentityAlreadyExistsError(f"ya existe: {name}")

        if force_weak_password:
            if not password:
                raise ValueError("El password no puede estar vacio")
        else:
            validate_password_strength(password)

        params = dict(kdf_params or self._kdf_params)
        salt   = _kdf.generate_salt()
        dk     = _kdf.derive_key(password, salt, params)

        ed_priv = Ed25519PrivateKey.generate()
        x_priv  = X25519PrivateKey.generate() if with_x25519 else None

        data = _ksf.build_keystore_dict(
            name=name,
            ed25519_priv=ed_priv,
            x25519_priv=x_priv,
            derived_key=dk,
            salt=salt,
            kdf_params=params,
            comment=comment,
            expires_at=expires_at,
        )
        self._write(name, data, overwrite=False)
        # No mantenemos referencia a dk ni a las privadas; salen del scope.
        return {
            "name":       name,
            "path":       str(self._path(name)),
            "ed25519_fp": data["fingerprints"]["ed25519"],
            "x25519_fp":  data["fingerprints"].get("x25519", ""),
        }

    # ----- uso (con password) -----

    def _check_usable(self, data: dict) -> None:
        """Bloquea uso de identidades revocadas o expiradas."""
        if data["status"] == "revoked":
            raise IdentityRevokedError(f"identidad revocada: {data['name']}")
        exp = data["metadata"].get("expires_at")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            except ValueError as e:
                raise KeyStoreError(f"expires_at invalido: {exp!r}") from e
            if datetime.now(timezone.utc) >= exp_dt:
                raise IdentityExpiredError(f"identidad expirada: {data['name']} (expires_at={exp})")
        # status == "rotated" tambien bloquea unlock (la nueva esta en
        # otra entrada; la rotated solo se conserva para verificar firmas
        # historicas via get_public_keys).
        if data["status"] == "rotated":
            raise IdentityRevokedError(
                f"identidad rotada: {data['name']} (usar la version vigente)"
            )

    def _unlock_both(self, name: str, password: str) -> Tuple[Ed25519PrivateKey, Optional[X25519PrivateKey]]:
        data = self._read(name)
        self._check_usable(data)
        return _ksf.unlock_keystore_dict(data, password)

    def unlock_signing_key(self, name: str, password: str) -> Ed25519PrivateKey:
        """
        Devuelve la Ed25519PrivateKey recien descifrada. NO cachea.
        Cada llamada vuelve a derivar la clave con scrypt (costo deliberado).
        """
        ed_priv, _ = self._unlock_both(name, password)
        return ed_priv

    def unlock_encryption_key(self, name: str, password: str) -> X25519PrivateKey:
        """
        Devuelve la X25519PrivateKey recien descifrada. NO cachea.

        Lanza KeyStoreError si la identidad fue creada con with_x25519=False.
        """
        _, x_priv = self._unlock_both(name, password)
        if x_priv is None:
            raise KeyStoreError(f"identidad {name} no tiene clave X25519")
        return x_priv

    # ----- cambio de password (re-cifrado, MISMAS llaves) -----

    def change_password(
        self,
        name: str,
        old_password: str,
        new_password: str,
        *,
        force_weak_password: bool = False,
    ) -> None:
        """
        Re-cifra el bundle con un salt y nonce nuevos, derivando con el
        nuevo password. Las llaves publicas y los fingerprints NO cambian.
        """
        if not force_weak_password:
            validate_password_strength(new_password)
        else:
            if not new_password:
                raise ValueError("El password no puede estar vacio")

        data = self._read(name)
        self._check_usable(data)
        ed_priv, x_priv = _ksf.unlock_keystore_dict(data, old_password)

        params  = dict(self._kdf_params)
        salt    = _kdf.generate_salt()
        dk      = _kdf.derive_key(new_password, salt, params)
        new_data = _ksf.build_keystore_dict(
            name=name,
            ed25519_priv=ed_priv,
            x25519_priv=x_priv,
            derived_key=dk,
            salt=salt,
            kdf_params=params,
            status=data["status"],
            expires_at=data["metadata"].get("expires_at"),
            comment=data["metadata"].get("comment", ""),
            rotated_from=data["metadata"].get("rotated_from"),
            created_at=data["created_at"],  # preserve original
        )
        self._write(name, new_data, overwrite=True)

    # ----- rotacion (nuevas llaves; archivar las viejas) -----

    def rotate_keys(self, name: str, password: str) -> Dict[str, str]:
        """
        Genera un par nuevo, marca el viejo como 'rotated' y lo guarda
        en `<name>.rotated-<timestamp>.json`. El archivo `<name>.json`
        contiene las nuevas llaves (status='active').

        El campo `metadata.rotated_from` apunta al fingerprint Ed25519
        anterior para trazabilidad.
        """
        old = self._read(name)
        self._check_usable(old)
        # Validamos el password descifrando con el viejo bundle (verifica
        # autoria del que rota).
        _ksf.unlock_keystore_dict(old, password)

        old_fp = old["fingerprints"]["ed25519"]
        ts = _now_iso().replace(":", "").replace("-", "")

        # Archivar el viejo con status="rotated".
        archived = dict(old)
        archived["status"] = "rotated"
        archived_path = self._path_rotated(name, ts)
        archived_path.write_text(
            json.dumps(archived, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # Generar nueva identidad bajo el MISMO nombre y MISMO password.
        new_ed = Ed25519PrivateKey.generate()
        had_x  = "x25519_pub_b64" in old["public_keys"]
        new_x  = X25519PrivateKey.generate() if had_x else None

        params = dict(self._kdf_params)
        salt   = _kdf.generate_salt()
        dk     = _kdf.derive_key(password, salt, params)
        new_data = _ksf.build_keystore_dict(
            name=name,
            ed25519_priv=new_ed,
            x25519_priv=new_x,
            derived_key=dk,
            salt=salt,
            kdf_params=params,
            comment=old["metadata"].get("comment", ""),
            expires_at=old["metadata"].get("expires_at"),
            rotated_from=old_fp,
        )
        self._write(name, new_data, overwrite=True)

        return {
            "name":              name,
            "old_ed25519_fp":    old_fp,
            "new_ed25519_fp":    new_data["fingerprints"]["ed25519"],
            "archived_path":     str(archived_path),
        }

    # ----- revocacion -----

    def revoke(self, name: str, *, reason: str = "") -> None:
        """
        Marca la identidad como revocada. Las llaves publicas siguen
        accesibles via `get_public_keys` (para verificar firmas viejas),
        pero `unlock_*` queda bloqueado.
        """
        data = self._read(name)
        data["status"] = "revoked"
        if reason:
            existing = data["metadata"].get("comment", "")
            sep = " | " if existing else ""
            data["metadata"]["comment"] = f"{existing}{sep}revoked: {reason}"
        self._write(name, data, overwrite=True)

    # ----- borrado (con password como prueba de autoria) -----

    def delete(self, name: str, password: str) -> None:
        """
        Borra la identidad. Exige el password correcto como prueba de
        que quien borra puede abrir la clave. Esto evita que un
        proceso con acceso de escritura pero sin password (un script
        de limpieza) borre identidades por error.
        """
        data = self._read(name)
        # No usamos _check_usable: queremos poder borrar revocadas/rotadas.
        _ksf.unlock_keystore_dict(data, password)  # lanza si pwd malo
        self._path(name).unlink()
