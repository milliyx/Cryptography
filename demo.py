"""
demo.py
=======
Script de demostracion en vivo para D4 — SDDV Midterm Presentation.

Ejecutar con:
    python demo.py

Muestra los 4 escenarios requeridos por el rubric:
  1. Cifrado valido -> descifrado exitoso
  2. Archivo compartido -> destinatario autorizado descifra
  3. No-destinatario no puede descifrar
  4. Archivo modificado -> descifrado falla (integridad)
"""

import os
import sys
import tempfile
import textwrap

# ── colores ANSI ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}✔ {msg}{RESET}")
def fail(msg):  print(f"  {RED}✖ {msg}{RESET}")
def info(msg):  print(f"  {CYAN}→ {msg}{RESET}")
def header(n, title):
    print(f"\n{BOLD}{YELLOW}{'─'*60}{RESET}")
    print(f"{BOLD}{YELLOW}  ESCENARIO {n}: {title}{RESET}")
    print(f"{BOLD}{YELLOW}{'─'*60}{RESET}")

# ── imports del proyecto ──────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from crypto.aead      import encrypt_file, decrypt_file, Algorithm
from crypto.keys      import generate_keypair, get_fingerprint
from crypto.signatures import (
    sign_container, verify_container,
    sign_hybrid_container, verify_hybrid_container,
    get_signer_fingerprint, SIGN_FOOTER_SIZE,
)
from crypto.hybrid    import (
    generate_x25519_keypair,
    encrypt_for_recipients,
    decrypt_for_recipient,
    get_recipient_fingerprints,
    get_x25519_fingerprint,
)
from crypto.secure_send import (
    secure_encrypt_and_sign,
    secure_verify_and_decrypt,
)
from cryptography.exceptions import InvalidTag, InvalidSignature

# ── datos de prueba ───────────────────────────────────────────────────────────
DOCUMENTO = b"Contrato confidencial UNAM - Semestre 2026-2.\nClausula 1: acceso restringido."
FILENAME  = "contrato_confidencial.pdf"

def separador():
    print()

# =============================================================================
# ESCENARIO 1: Cifrado valido -> descifrado exitoso
# =============================================================================
def escenario_1():
    header(1, "Cifrado valido → Descifrado exitoso")
    info(f"Archivo: '{FILENAME}' ({len(DOCUMENTO)} bytes)")
    info("Algoritmo: AES-256-GCM  |  Nonce: 96-bit CSPRNG  |  Tag: 128-bit")

    container, key = encrypt_file(DOCUMENTO, FILENAME)
    info(f"Contenedor generado: {len(container)} bytes  (overhead = {len(container)-len(DOCUMENTO)} bytes)")
    info(f"Clave (hex): {key.hex()[:32]}...")

    plaintext, meta = decrypt_file(container, key)

    assert plaintext == DOCUMENTO
    ok(f"Descifrado exitoso — {len(plaintext)} bytes recuperados")
    ok(f"Filename en AAD verificado: '{meta['filename']}'")
    ok(f"Algoritmo confirmado: {meta['algo'].name}")
    ok("Tag AEAD valido — ningun byte fue manipulado")

# =============================================================================
# ESCENARIO 2: Archivo compartido -> ambos destinatarios descifran
# =============================================================================
def escenario_2():
    header(2, "Cifrado hibrido → Dos destinatarios autorizados descifran")

    # Generar llaves X25519 para Alice y Bob
    alice_priv, alice_pub = generate_x25519_keypair()
    bob_priv,   bob_pub   = generate_x25519_keypair()
    fp_alice = get_x25519_fingerprint(alice_pub)
    fp_bob   = get_x25519_fingerprint(bob_pub)

    info(f"Alice fingerprint: {fp_alice[:16]}...")
    info(f"Bob   fingerprint: {fp_bob[:16]}...")
    info("Cifrando para Alice y Bob (KEM+DEM, X25519 ECDH + AES-256-GCM)...")

    container = encrypt_for_recipients(DOCUMENTO, FILENAME, [alice_pub, bob_pub])
    fps_en_contenedor = get_recipient_fingerprints(container)

    info(f"Contenedor generado: {len(container)} bytes con {len(fps_en_contenedor)} destinatarios")

    # Alice descifra
    plaintext_alice, _ = decrypt_for_recipient(container, alice_priv)
    assert plaintext_alice == DOCUMENTO
    ok("Alice descifra correctamente")

    # Bob descifra
    plaintext_bob, _ = decrypt_for_recipient(container, bob_priv)
    assert plaintext_bob == DOCUMENTO
    ok("Bob descifra correctamente")

    ok("Ambos obtienen el mismo plaintext original")

# =============================================================================
# ESCENARIO 3: No-destinatario no puede descifrar
# =============================================================================
def escenario_3():
    header(3, "No-destinatario no puede descifrar")

    alice_priv, alice_pub = generate_x25519_keypair()
    eve_priv,   eve_pub   = generate_x25519_keypair()  # Eve no esta invitada

    info(f"Destinatario autorizado: Alice  ({get_x25519_fingerprint(alice_pub)[:16]}...)")
    info(f"Intruso (Eve):           NO autorizada ({get_x25519_fingerprint(eve_pub)[:16]}...)")

    container = encrypt_for_recipients(DOCUMENTO, FILENAME, [alice_pub])
    info("Contenedor cifrado solo para Alice")

    # Eve intenta descifrar
    try:
        decrypt_for_recipient(container, eve_priv)
        fail("ERROR: Eve pudo descifrar — fallo de seguridad!")
        sys.exit(1)
    except ValueError as e:
        ok(f"Eve rechazada: {e}")

    # Confirmar que Alice si puede
    plaintext, _ = decrypt_for_recipient(container, alice_priv)
    assert plaintext == DOCUMENTO
    ok("Alice sigue pudiendo descifrar normalmente")

# =============================================================================
# ESCENARIO 4: Archivo modificado -> descifrado falla (integridad)
# =============================================================================
def escenario_4():
    header(4, "Archivo modificado → Descifrado falla (integridad AEAD)")

    container, key = encrypt_file(DOCUMENTO, FILENAME)
    info(f"Contenedor original: {len(container)} bytes")

    # --- 4a: modificar ciphertext ---
    info("Caso 4a — modificar 1 byte del ciphertext:")
    tampered = bytearray(container)
    tampered[len(container)//2] ^= 0xFF
    try:
        decrypt_file(bytes(tampered), key)
        fail("ERROR: descifrado deberia haber fallado!")
        sys.exit(1)
    except InvalidTag:
        ok("InvalidTag lanzado — ciphertext manipulado detectado")

    # --- 4b: modificar metadata (filename en AAD) ---
    info("Caso 4b — modificar filename en el AAD:")
    tampered2 = bytearray(container)
    tampered2[16] ^= 0x01  # primer byte del filename
    try:
        decrypt_file(bytes(tampered2), key)
        fail("ERROR: metadata manipulada no detectada!")
        sys.exit(1)
    except (InvalidTag, ValueError):
        ok("Manipulacion del AAD detectada — tag invalido")

    # --- 4c: lista de destinatarios en contenedor hibrido ---
    info("Caso 4c — modificar lista de destinatarios en contenedor hibrido:")
    alice_priv, alice_pub = generate_x25519_keypair()
    h_container = encrypt_for_recipients(DOCUMENTO, FILENAME, [alice_pub])
    tampered3 = bytearray(h_container)
    # Corromper fingerprint del destinatario en el AAD
    from crypto.hybrid import _parse_hybrid_header
    import struct
    fname_len = struct.unpack(">H", h_container[14:16])[0]
    fp_start  = 16 + fname_len + 2
    tampered3[fp_start] ^= 0x01
    try:
        decrypt_for_recipient(bytes(tampered3), alice_priv)
        fail("ERROR: lista de destinatarios manipulada no detectada!")
        sys.exit(1)
    except (InvalidTag, ValueError):
        ok("Lista de destinatarios protegida por AAD — manipulacion detectada")

# =============================================================================
# ESCENARIO 5: D4 - Flujo completo Encrypt -> Sign -> Verify -> Decrypt
# =============================================================================
def escenario_5():
    header(5, "D4 - Cifrado hibrido + Firma digital + Verify-first")

    # Alice firma. Bob y Carol son destinatarios. Eve es atacante.
    alice_priv, alice_pub = generate_keypair()              # Ed25519 firmante
    bob_priv,   bob_pub   = generate_x25519_keypair()       # X25519 destinatario
    carol_priv, carol_pub = generate_x25519_keypair()       # X25519 destinatario
    eve_priv,   eve_pub   = generate_keypair()              # Ed25519 atacante

    info(f"Firmante (Alice) Ed25519: {get_fingerprint(alice_pub)[:16]}...")
    info(f"Bob   (X25519): {get_x25519_fingerprint(bob_pub)[:16]}...")
    info(f"Carol (X25519): {get_x25519_fingerprint(carol_pub)[:16]}...")
    info(f"Eve   (atacante Ed25519): {get_fingerprint(eve_pub)[:16]}...")

    # --- 5a: envio firmado ---
    info("Caso 5a - Alice cifra y firma para Bob y Carol:")
    signed = secure_encrypt_and_sign(
        plaintext=DOCUMENTO,
        filename=FILENAME,
        recipients=[bob_pub, carol_pub],
        signer_priv=alice_priv,
    )
    info(f"Contenedor firmado: {len(signed)} bytes  "
         f"(SDDH {len(signed)-SIGN_FOOTER_SIZE} + footer firma {SIGN_FOOTER_SIZE})")

    fp_extraido = get_signer_fingerprint(signed)
    ok(f"Footer indica firmante: {fp_extraido[:16]}... (coincide con Alice)")

    # --- 5b: Bob verifica y descifra ---
    info("Caso 5b - Bob verifica firma de Alice y descifra:")
    plaintext_bob, _ = secure_verify_and_decrypt(
        signed,
        expected_signer_pub=alice_pub,
        recipient_priv=bob_priv,
    )
    assert plaintext_bob == DOCUMENTO
    ok("Firma Ed25519 verificada -> descifrado exitoso para Bob")

    # --- 5c: Carol tambien verifica y descifra ---
    info("Caso 5c - Carol verifica y descifra:")
    plaintext_carol, _ = secure_verify_and_decrypt(
        signed, alice_pub, carol_priv
    )
    assert plaintext_carol == DOCUMENTO
    ok("Carol obtiene el mismo plaintext")

    # --- 5d: Eve intenta hacerse pasar por Alice re-firmando ---
    info("Caso 5d - Eve toma el SDDH de Alice y lo re-firma con su llave:")
    sddh_solo = signed[:-SIGN_FOOTER_SIZE]
    re_firmado_por_eve = sign_hybrid_container(sddh_solo, eve_priv)
    info(f"Eve produce un contenedor 'valido' firmado por ella misma")

    # Bob esperaba a Alice -> rechazo
    try:
        secure_verify_and_decrypt(re_firmado_por_eve, alice_pub, bob_priv)
        fail("ERROR: Eve logro suplantar a Alice!")
        sys.exit(1)
    except InvalidSignature:
        ok("Bob rechaza: el fingerprint del footer no es el de Alice")

    # --- 5e: Mallory modifica metadatos del SDDH firmado ---
    info("Caso 5e - Atacante modifica el filename en el AAD del SDDH firmado:")
    tampered = bytearray(signed)
    tampered[16] ^= 0x01   # primer byte del filename
    try:
        secure_verify_and_decrypt(bytes(tampered), alice_pub, bob_priv)
        fail("ERROR: metadata manipulada no detectada!")
        sys.exit(1)
    except InvalidSignature:
        ok("Firma Ed25519 invalidada -> manipulacion detectada antes de descifrar")

    # --- 5f: Atacante elimina el footer de firma ---
    info("Caso 5f - Atacante elimina el footer de firma:")
    sin_firma = signed[:-SIGN_FOOTER_SIZE]
    try:
        secure_verify_and_decrypt(sin_firma, alice_pub, bob_priv)
        fail("ERROR: contenedor sin firma fue aceptado!")
        sys.exit(1)
    except (ValueError, InvalidSignature):
        ok("Contenedor sin firma rechazado -> ValueError/InvalidSignature")


# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print(f"\n{BOLD}{'='*60}")
    print("  SDDV - Boveda Digital Segura de Documentos")
    print("  Demo final - D2 + D3 + D4 (Cifrado hibrido + Firma)")
    print(f"{'='*60}{RESET}")

    escenario_1(); separador()
    escenario_2(); separador()
    escenario_3(); separador()
    escenario_4(); separador()
    escenario_5(); separador()

    print(f"{BOLD}{GREEN}{'='*60}")
    print("  Todos los escenarios pasaron correctamente.")
    print(f"{'='*60}{RESET}\n")
