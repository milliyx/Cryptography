"""
src/__main__.py
==================
CLI del modulo src (D6 — gestion de llaves).

Subcomandos:
    init [name]
    list
    fingerprint <name>
    rotate <name>
    change-password <name>
    revoke <name> [--reason TEXT]
    delete <name>
    backup <name> <out_path>      (Fase 3)
    restore <backup_path> <name>  (Fase 3)

Todas las operaciones que necesitan password lo piden con
`getpass.getpass` para que NUNCA aparezca en historiales de shell ni
en `ps aux`. La contrasena vive solo en el frame de la funcion que
deriva la clave.

Estructura de archivos:
    keystore/<name>.json                     (identidad activa)
    keystore/<name>.rotated-<timestamp>.json (versiones rotadas)
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Optional

from . import keystore as _ks
from .keystore import (
    IdentityAlreadyExistsError,
    IdentityExpiredError,
    IdentityNotFoundError,
    IdentityRevokedError,
    KeyStore,
    KeyStoreError,
)


DEFAULT_KEYSTORE_DIR = "keystore"


def _prompt_password(label: str, *, confirm: bool = False) -> str:
    pwd = getpass.getpass(f"{label}: ")
    if confirm:
        again = getpass.getpass(f"{label} (de nuevo): ")
        if pwd != again:
            print("Las contrasenas no coinciden.", file=sys.stderr)
            raise SystemExit(2)
    return pwd


# ── subcomandos ───────────────────────────────────────────────────────────────

def _cmd_init(args) -> int:
    ks = KeyStore(args.keystore)
    pwd = _prompt_password("Password para la nueva identidad", confirm=True)
    info = ks.init_identity(
        args.name,
        pwd,
        with_x25519=not args.no_x25519,
        comment=args.comment or "",
        expires_at=args.expires_at,
    )
    print(f"Identidad creada: {info['name']}")
    print(f"  Archivo:    {info['path']}")
    print(f"  Ed25519 fp: {info['ed25519_fp']}")
    if info['x25519_fp']:
        print(f"  X25519  fp: {info['x25519_fp']}")
    return 0


def _cmd_list(args) -> int:
    ks = KeyStore(args.keystore, create=False)
    rows = ks.list_identities()
    if not rows:
        print("(keystore vacio)")
        return 0
    # Tabla simple
    print(f"{'NAME':<20} {'STATUS':<10} {'ED25519 FINGERPRINT':<64}  CREATED")
    for r in rows:
        print(f"{r['name']:<20} {r['status']:<10} {r['ed25519_fp']:<64}  {r['created_at']}")
    return 0


def _cmd_fingerprint(args) -> int:
    ks = KeyStore(args.keystore, create=False)
    info = ks.get_public_keys(args.name)
    fps = info["fingerprints"]
    print(f"ed25519: {fps['ed25519']}")
    if "x25519" in fps:
        print(f"x25519:  {fps['x25519']}")
    return 0


def _cmd_rotate(args) -> int:
    ks = KeyStore(args.keystore, create=False)
    pwd = _prompt_password(f"Password actual de '{args.name}'")
    result = ks.rotate_keys(args.name, pwd)
    print(f"Identidad rotada: {result['name']}")
    print(f"  Anterior:     {result['old_ed25519_fp']}")
    print(f"  Nueva:        {result['new_ed25519_fp']}")
    print(f"  Archivado en: {result['archived_path']}")
    return 0


def _cmd_change_password(args) -> int:
    ks = KeyStore(args.keystore, create=False)
    old = _prompt_password(f"Password actual de '{args.name}'")
    new = _prompt_password(f"Nuevo password para '{args.name}'", confirm=True)
    ks.change_password(args.name, old, new)
    print(f"Password actualizado para '{args.name}'")
    return 0


def _cmd_revoke(args) -> int:
    ks = KeyStore(args.keystore, create=False)
    ks.revoke(args.name, reason=args.reason or "")
    print(f"Identidad revocada: {args.name}")
    return 0


def _cmd_delete(args) -> int:
    ks = KeyStore(args.keystore, create=False)
    pwd = _prompt_password(f"Password de '{args.name}' (confirma borrado)")
    ks.delete(args.name, pwd)
    print(f"Identidad borrada: {args.name}")
    return 0


def _cmd_backup(args) -> int:
    # Implementado en Fase 3.
    from . import keystore_backup as _kb
    ks = KeyStore(args.keystore, create=False)
    active_pwd = _prompt_password(f"Password actual de '{args.name}'")
    backup_pwd = _prompt_password("Password DEL BACKUP", confirm=True)
    out = _kb.export_backup(ks, args.name, active_pwd, backup_pwd, args.out_path)
    print(f"Backup creado: {out}")
    return 0


def _cmd_restore(args) -> int:
    # Implementado en Fase 3.
    from . import keystore_backup as _kb
    ks = KeyStore(args.keystore)
    backup_pwd = _prompt_password("Password del archivo de backup")
    new_active = _prompt_password("Password para la identidad restaurada", confirm=True)
    info = _kb.import_backup(ks, args.backup_path, backup_pwd, new_active, name=args.name)
    print(f"Identidad restaurada: {info['name']}")
    return 0


# ── parser ────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src",
        description="CLI del SDDV — D6 Key Management",
    )
    parser.add_argument(
        "--keystore",
        default=DEFAULT_KEYSTORE_DIR,
        help=f"Directorio del keystore (default: {DEFAULT_KEYSTORE_DIR})",
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("init", help="Crea una identidad nueva")
    p.add_argument("name")
    p.add_argument("--no-x25519", action="store_true", help="Crear solo Ed25519 (firma)")
    p.add_argument("--comment", default="")
    p.add_argument("--expires-at", default=None, help="ISO8601 UTC, ej 2027-01-01T00:00:00Z")
    p.set_defaults(func=_cmd_init)

    p = sub.add_parser("list", help="Lista las identidades")
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("fingerprint", help="Muestra fingerprints publicos")
    p.add_argument("name")
    p.set_defaults(func=_cmd_fingerprint)

    p = sub.add_parser("rotate", help="Genera un par nuevo y archiva el viejo")
    p.add_argument("name")
    p.set_defaults(func=_cmd_rotate)

    p = sub.add_parser("change-password", help="Cambia la contrasena que protege la identidad")
    p.add_argument("name")
    p.set_defaults(func=_cmd_change_password)

    p = sub.add_parser("revoke", help="Marca la identidad como revocada")
    p.add_argument("name")
    p.add_argument("--reason", default="")
    p.set_defaults(func=_cmd_revoke)

    p = sub.add_parser("delete", help="Borra la identidad (requiere password)")
    p.add_argument("name")
    p.set_defaults(func=_cmd_delete)

    p = sub.add_parser("backup", help="Exporta un backup cifrado")
    p.add_argument("name")
    p.add_argument("out_path")
    p.set_defaults(func=_cmd_backup)

    p = sub.add_parser("restore", help="Restaura una identidad desde un backup")
    p.add_argument("backup_path")
    p.add_argument("--name", default=None, help="Renombrar al restaurar (default: nombre original)")
    p.set_defaults(func=_cmd_restore)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except IdentityAlreadyExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except IdentityNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except IdentityRevokedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except IdentityExpiredError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyStoreError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        # Cualquier otra excepcion (incluye InvalidTag por password malo)
        print(f"Error: {e.__class__.__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
