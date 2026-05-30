"""
audit/vuln2_replay.py
=====================
Reproduccion de la Vulnerabilidad 2: Replay Attack por falta de validacion
de freshness (timestamp).

CWE-294: Authentication Bypass by Capture-replay

Descripcion:
  El campo 'timestamp' del contenedor (SDDV/SDDH) se almacena dentro del AAD
  y por lo tanto es autenticado, pero las funciones de descifrado y
  verificacion (decrypt_file, decrypt_for_recipient, secure_verify_and_decrypt)
  NUNCA validan que el timestamp sea reciente. Un atacante que capture un
  contenedor firmado valido puede re-entregarlo dias, meses o anios despues
  y el sistema lo aceptara como autentico.

Severidad: MEDIUM
  - Impacto: Autenticidad/freshness — un mensaje viejo se acepta como nuevo
  - Vector: requiere captura de un contenedor previo legitimo
  - Prerequisitos: acceso pasivo al canal de transmision o al storage

Reproduccion:
  1. Alice firma y envia un contenedor a Bob el dia X (legitimo).
  2. Atacante observa/captura el contenedor.
  3. Tiempo despues (1 hora, 1 dia, 1 anio) el atacante reentrega el mismo
     contenedor a Bob.
  4. Bob verifica con secure_verify_and_decrypt — la firma sigue valida
     porque Ed25519 es deterministico y el contenido no cambia. Bob acepta
     el mensaje como si fuera reciente.
"""

import time
from datetime import datetime, timezone

from src.aead import encrypt_file, decrypt_file
from src.hybrid import (
    encrypt_for_recipients,
    decrypt_for_recipient,
    generate_x25519_keypair,
)
from src.keys import generate_keypair
from src.secure_send import secure_encrypt_and_sign, secure_verify_and_decrypt


def banner(text):
    print("\n" + "=" * 72)
    print(f"  {text}")
    print("=" * 72)


def fmt_ts(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ───── Caso 1: Replay de SDDV simple ─────────────────────────────────────────

def reproducir_replay_sddv():
    banner("CASO 1 — Replay sobre SDDV (src/aead.py)")

    plaintext = b"Transferir $1000 de Alice a Bob"

    # Atacante captura un contenedor cifrado en el ano 2020
    timestamp_antiguo = int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp())
    print(f"\n  Alice cifra un mensaje con timestamp del 2020-01-01:")
    container, key = encrypt_file(plaintext, "transferencia.txt", timestamp=timestamp_antiguo)
    print(f"    timestamp embebido: {fmt_ts(timestamp_antiguo)}")
    print(f"    contenido: {plaintext!r}")

    # Tiempo despues, el atacante reentrega el mismo contenedor
    print(f"\n  Tiempo presente: {fmt_ts(int(time.time()))}")
    print(f"  Atacante reentrega el mismo contenedor (sin modificarlo).")
    print(f"  Bob descifra:")
    try:
        plaintext_recovered, meta = decrypt_file(container, key)
        print(f"    timestamp leido: {fmt_ts(meta['timestamp'])}")
        print(f"    edad del mensaje: {(time.time() - meta['timestamp']) / 86400:.0f} dias")
        print(f"    contenido recuperado: {plaintext_recovered!r}")
        print(f"\n  [!!! VULNERABLE - VULNERABILIDAD CONFIRMADA !!!]")
        print(f"  El sistema acepto un mensaje cuyo timestamp es de hace mas de")
        print(f"  {(time.time() - meta['timestamp']) / 86400:.0f} dias sin protestar.")
    except Exception as e:
        print(f"\n  [PARCHE - REPLAY BLOQUEADO]")
        print(f"  decrypt_file rechazo el contenedor antiguo:")
        print(f"  {type(e).__name__}: {e}")


# ───── Caso 2: Replay de contenedor firmado D5 (caso real) ───────────────────

def reproducir_replay_d5_signed():
    banner("CASO 2 — Replay sobre contenedor firmado D5 (escenario realista)")

    # Setup: Alice firma, Bob es destinatario
    alice_sign_priv, alice_sign_pub = generate_keypair()
    bob_priv, bob_pub               = generate_x25519_keypair()

    # Mensaje firmado en el ano 2024
    mensaje = b"Autorizo la transferencia de fondos. - Alice"
    timestamp_antiguo = int(datetime(2024, 6, 15, 10, 30, tzinfo=timezone.utc).timestamp())

    print(f"\n  ESCENARIO:")
    print(f"  - Alice firma el mensaje el {fmt_ts(timestamp_antiguo)}")
    print(f"  - Atacante captura el contenedor pasando por la red")
    print(f"  - Tiempo despues, atacante reentrega EL MISMO contenedor a Bob")

    signed_container = secure_encrypt_and_sign(
        plaintext=mensaje,
        filename="autorizacion.txt",
        recipients=[bob_pub],
        signer_priv=alice_sign_priv,
        timestamp=timestamp_antiguo,
    )

    print(f"\n  Contenedor capturado por el atacante: {len(signed_container)} bytes")
    print(f"  La firma Ed25519 cubre el timestamp como parte del AAD.")
    print(f"  La firma es deterministica — el atacante NO puede modificar el timestamp")
    print(f"  para hacer parecer reciente al mensaje. Pero NO necesita hacerlo.")

    # Bob recibe el mensaje "ahora" (2026)
    print(f"\n  Bob recibe el contenedor en {fmt_ts(int(time.time()))}:")
    print(f"  >>> secure_verify_and_decrypt(signed_container, alice_sign_pub, bob_priv)")

    try:
        plaintext, meta = secure_verify_and_decrypt(signed_container, alice_sign_pub, bob_priv)

        edad_segundos = time.time() - meta["timestamp"]
        edad_dias     = edad_segundos / 86400

        print(f"\n  RESULTADO:")
        print(f"    [OK firma]   sistema acepto la firma como valida")
        print(f"    [OK descifre] sistema devolvio el plaintext: {plaintext!r}")
        print(f"    edad real del mensaje: {edad_dias:.0f} dias ({edad_segundos/86400/365:.1f} anios)")

        print(f"\n  [!!! VULNERABLE - VULNERABILIDAD CONFIRMADA !!!]")
        print(f"  Bob acepto como autentico un mensaje firmado hace {edad_dias:.0f} dias.")
    except Exception as e:
        print(f"\n  [PARCHE - REPLAY BLOQUEADO]")
        print(f"  secure_verify_and_decrypt rechazo el contenedor antiguo:")
        print(f"  {type(e).__name__}: {e}")


# ───── Caso 3: Replay con timestamp futuro (clock skew abuse) ────────────────

def reproducir_replay_timestamp_futuro():
    banner("CASO 3 — Aceptacion de timestamps imposibles (futuro)")

    plaintext = b"Mensaje con timestamp del futuro"

    # Crear contenedor con timestamp del ano 2099
    ts_futuro = int(datetime(2099, 12, 31, tzinfo=timezone.utc).timestamp())
    print(f"\n  Atacante (o cliente con reloj mal configurado) cifra un mensaje")
    print(f"  con timestamp del FUTURO: {fmt_ts(ts_futuro)}")

    container, key = encrypt_file(plaintext, "futuro.txt", timestamp=ts_futuro)
    try:
        plaintext_rec, meta = decrypt_file(container, key)
        print(f"\n  Bob descifra y obtiene metadata['timestamp'] = {fmt_ts(meta['timestamp'])}")
        print(f"  El sistema NO rechaza este timestamp imposible.")
        print(f"\n  [!!! VULNERABLE - VULNERABILIDAD COMPLEMENTARIA !!!]")
        print(f"  El sistema deberia rechazar timestamps significativamente en el futuro.")
    except Exception as e:
        print(f"\n  [PARCHE - TIMESTAMP FUTURO BLOQUEADO]")
        print(f"  decrypt_file rechazo el contenedor con timestamp del futuro:")
        print(f"  {type(e).__name__}: {e}")


# ───── main ───────────────────────────────────────────────────────────────────

def main():
    print("\n" + "#" * 72)
    print("#" + "  REPRODUCCION VULN-002: Replay Attack (no freshness)".center(70) + "#")
    print("#" + "  CWE-294 — Severidad MEDIUM".center(70) + "#")
    print("#" * 72)

    reproducir_replay_sddv()
    reproducir_replay_d5_signed()
    reproducir_replay_timestamp_futuro()

    print("\n" + "=" * 72)
    print("  CONCLUSION:")
    print("  El sistema almacena timestamps en el AAD pero nunca los valida")
    print("  contra el tiempo actual. Esto permite:")
    print("    1. Replay indefinido de mensajes capturados")
    print("    2. Aceptacion de timestamps en el futuro (no hay limite superior)")
    print("    3. Aceptacion de timestamps muy antiguos (no hay limite inferior)")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
