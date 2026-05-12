"""
crypto/__main__.py
==================
CLI del modulo crypto. En D6 expone operaciones sobre el keystore:

    python -m crypto init <name>
    python -m crypto list
    python -m crypto fingerprint <name>
    python -m crypto rotate <name>
    python -m crypto change-password <name>
    python -m crypto revoke <name>
    python -m crypto backup <name> <out_path>
    python -m crypto restore <backup_path>

Las contrasenas se piden con getpass para que nunca aparezcan en
historiales de shell ni en `ps`.

En la Fase 0 este archivo es solo el esqueleto -- los subcomandos
estan stubbed y se implementan en la Fase 2.
"""

import argparse
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m crypto",
        description="CLI del SDDV (gestion de llaves D6)",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Crea una identidad nueva en el keystore")
    sub.add_parser("list", help="Lista las identidades del keystore")
    sub.add_parser("fingerprint", help="Muestra el fingerprint de una identidad")
    sub.add_parser("rotate", help="Genera un par de llaves nuevo y archiva el viejo")
    sub.add_parser("change-password", help="Cambia el password que protege una identidad")
    sub.add_parser("revoke", help="Marca una identidad como revocada")
    sub.add_parser("backup", help="Exporta un backup cifrado de la identidad")
    sub.add_parser("restore", help="Restaura una identidad desde un backup cifrado")

    return parser


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    # Stub Fase 0: los subcomandos se implementan en Fase 2.
    print(
        f"[D6 stub] subcomando '{args.command}' aun no implementado. "
        "Se completara en la Fase 2 del plan D6.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
