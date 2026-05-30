"""
demo_d6.py
==========
Demo del ciclo de vida completo del key management D6.

Recorre, en este orden:

  1. Crear identidades para Alice y Bob en el keystore.
  2. Mostrar el JSON del keystore (campos visibles, privada cifrada).
  3. Intento de unlock con password incorrecto -> falla.
  4. Cifrar+firmar un documento de Alice para Bob usando el keystore.
  5. Bob abre el documento desde su keystore.
  6. Rotacion de las llaves de Alice (cambio de fingerprint).
  7. Backup de Alice -> borrar -> restore -> sigue funcionando.

Notas para la presentacion:
  - Los passwords se hardcodean SOLO para el demo. En la CLI se piden
    con getpass; aqui los pasamos como string por reproducibilidad.
  - Los parametros KDF son los DEFAULT (n=2**15) -> cada init/unlock
    toma ~150 ms en una laptop. Esto es DELIBERADO: hace caro un ataque
    offline tras robar el keystore.
  - El directorio del keystore se crea bajo `./demo_keystore/`.
    Si ya existe se borra primero.

Para correr:
    python demo_d6.py
"""

from __future__ import annotations

import json
import shutil
import os
import sys
from pathlib import Path

# Configurar sys.path para resolver el modulo 'src' en el directorio padre
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.keystore import KeyStore
from src.keystore_backup import export_backup, import_backup
from src.secure_send import (
    encrypt_and_sign_from_keystore,
    verify_and_decrypt_from_keystore,
)


KEYSTORE_DIR = Path("demo_keystore")
BACKUP_PATH  = Path("demo_keystore_backups") / "alice.sddv_backup"

ALICE_PASSWORD       = "passwordSeguroDeAlice_2026!"
BOB_PASSWORD         = "passwordSeguroDeBob_2026!"
BACKUP_PASSWORD      = "passwordDeBackup_Independiente_2026!"
NEW_ALICE_PASSWORD   = "passwordRestauradoDeAlice_2026!"

DOCUMENT = b"""
ASUNTO: Plan trimestral confidencial
DE: alice@unam.mx
PARA: bob@unam.mx

Este documento contiene la informacion del plan trimestral. No
debe filtrarse fuera del grupo.
""".strip()


def banner(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main() -> None:
    # Limpiamos el directorio del demo para que sea reproducible.
    if KEYSTORE_DIR.exists():
        shutil.rmtree(KEYSTORE_DIR)
    if BACKUP_PATH.parent.exists():
        shutil.rmtree(BACKUP_PATH.parent)

    # ── 1. Crear identidades ──────────────────────────────────────────────
    banner("1. Crear identidades en el keystore")
    ks = KeyStore(KEYSTORE_DIR)
    alice = ks.init_identity("alice", ALICE_PASSWORD, comment="alice@unam.mx")
    bob   = ks.init_identity("bob",   BOB_PASSWORD,   comment="bob@unam.mx")
    print(f"alice -> archivo {alice['path']}")
    print(f"         fingerprint Ed25519: {alice['ed25519_fp']}")
    print(f"         fingerprint X25519 : {alice['x25519_fp']}")
    print(f"bob   -> archivo {bob['path']}")
    print(f"         fingerprint Ed25519: {bob['ed25519_fp']}")
    print(f"         fingerprint X25519 : {bob['x25519_fp']}")

    # ── 2. Inspeccion del JSON del keystore ──────────────────────────────
    banner("2. Estructura del keystore en disco")
    raw = json.loads((KEYSTORE_DIR / "alice.json").read_text(encoding="utf-8"))
    summary = {
        "version":              raw["version"],
        "name":                 raw["name"],
        "status":               raw["status"],
        "kdf.algorithm":        raw["kdf"]["algorithm"],
        "kdf.n,r,p,dklen":      [raw["kdf"]["n"], raw["kdf"]["r"], raw["kdf"]["p"], raw["kdf"]["dklen"]],
        "encryption.algorithm": raw["encryption"]["algorithm"],
        "encrypted_private_key (longitud b64)": len(raw["encrypted_private_key"]),
        "public_keys.ed25519_pub_b64 (primeros 16 chars)": raw["public_keys"]["ed25519_pub_b64"][:16] + "...",
    }
    for k, v in summary.items():
        print(f"  {k:55s} {v}")
    print("  (la privada raw NO esta en el JSON; solo el ciphertext y su tag)")

    # ── 3. Intento de unlock con password incorrecto ─────────────────────
    banner("3. Unlock con password incorrecto debe fallar")
    try:
        ks.unlock_signing_key("alice", "passwordEquivocado_xyz!")
        print("  [FALLO] el sistema acepto un password incorrecto!")
    except Exception as exc:
        print(f"  OK: el sistema rechazo el password incorrecto ({type(exc).__name__})")

    # ── 4. Alice firma+cifra un documento para Bob ───────────────────────
    banner("4. Alice firma y cifra un documento para Bob")
    bob_x_pub = ks.get_public_keys("bob")["x25519_pub"]
    container = encrypt_and_sign_from_keystore(
        ks, "alice", ALICE_PASSWORD,
        plaintext=DOCUMENT,
        filename="plan_trimestral.txt",
        recipients_x25519=[bob_x_pub],
    )
    print(f"  Contenedor producido: {len(container)} bytes")

    # ── 5. Bob verifica+descifra ─────────────────────────────────────────
    banner("5. Bob verifica y descifra desde su propio keystore")
    alice_ed_pub = ks.get_public_keys("alice")["ed25519_pub"]
    plaintext, metadata = verify_and_decrypt_from_keystore(
        ks, "bob", BOB_PASSWORD,
        signed_container=container,
        expected_signer_pub=alice_ed_pub,
    )
    print(f"  filename:    {metadata['filename']}")
    print(f"  recipients:  {metadata['recipients']}")
    print(f"  plaintext (primera linea): {plaintext.decode().splitlines()[0]}")

    # ── 6. Rotacion de las llaves de Alice ───────────────────────────────
    banner("6. Rotacion de las llaves de Alice")
    rot = ks.rotate_keys("alice", ALICE_PASSWORD)
    print(f"  Old Ed25519 fp: {rot['old_ed25519_fp']}")
    print(f"  New Ed25519 fp: {rot['new_ed25519_fp']}")
    print(f"  Archivado en:   {rot['archived_path']}")

    # ── 7. Backup y restore ──────────────────────────────────────────────
    banner("7. Backup -> borrar -> restore (con passwords distintos)")
    out = export_backup(ks, "alice", ALICE_PASSWORD, BACKUP_PASSWORD, str(BACKUP_PATH))
    print(f"  Backup escrito en: {out}")
    ks.delete("alice", ALICE_PASSWORD)
    print(f"  alice borrada del keystore activo. exists -> {ks.exists('alice')}")
    info = import_backup(ks, str(BACKUP_PATH), BACKUP_PASSWORD, NEW_ALICE_PASSWORD)
    print(f"  alice restaurada con NUEVO password activo:")
    print(f"    fingerprint Ed25519: {info['ed25519_fp']}")
    print(f"    fingerprint X25519 : {info['x25519_fp']}")

    # Verificacion final: el bundle restaurado puede firmar.
    sig = ks.unlock_signing_key("alice", NEW_ALICE_PASSWORD).sign(b"prueba post-restore")
    ks.get_public_keys("alice")["ed25519_pub"].verify(sig, b"prueba post-restore")
    print("  Firma post-restore verifica contra la publica del keystore: OK")

    banner("Demo D6 completo")


if __name__ == "__main__":
    main()
