"""
audit_tampering.py
==================
Script de auditoria de seguridad — reproduce los 5 ataques del checklist
y muestra TODOS los procesos involucrados:
  - Generacion de llaves
  - Cifrado y construccion del contenedor (con hex dump)
  - Modificacion byte-a-byte (con resaltado visual)
  - Intento de descifrado/verificacion
  - Excepcion lanzada con traceback completo
  - Interpretacion del resultado

Uso (desde la raiz del repo, para que PYTHONPATH resuelva 'src.*'):
    PYTHONPATH=. python3 audit/audit_tampering.py             # corre todos
    PYTHONPATH=. python3 audit/audit_tampering.py --test 1    # solo test N (1..5)
"""

import hashlib
import sys
import traceback

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.aead import encrypt_file, decrypt_file
from src.hybrid import (
    encrypt_for_recipients,
    decrypt_for_recipient,
    generate_x25519_keypair,
    get_x25519_fingerprint,
)
from src.keys import generate_keypair
from src.secure_send import secure_encrypt_and_sign, secure_verify_and_decrypt
from src.signatures import sign_container, verify_container


# ───── helpers de presentacion ────────────────────────────────────────────────

WIDTH = 78

# Colores ANSI: solo si stdout es un terminal real (no pipe ni archivo)
_USE_COLOR = sys.stdout.isatty() and "--no-color" not in sys.argv
RED   = "\033[1;31m" if _USE_COLOR else ""
RESET = "\033[0m"   if _USE_COLOR else ""


def banner(text):
    print("\n" + "#" * WIDTH)
    print("#" + text.center(WIDTH - 2) + "#")
    print("#" * WIDTH)


def section(num, title):
    print("\n" + "=" * WIDTH)
    print(f"  TEST {num}: {title}")
    print("=" * WIDTH)


def phase(text):
    print(f"\n  --- {text} ---")


def kv(label, value):
    print(f"  {label:.<30} {value}")


def hex_dump(data, label="contenido", highlight_offset=None, highlight_len=1, max_bytes=128):
    """Imprime un hex dump tipo `xxd` con resaltado opcional de bytes."""
    print(f"\n  hex dump ({label}, {len(data)} bytes total):")
    data = bytes(data)
    shown = data[:max_bytes]
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        # offset
        line = f"  {i:08x}  "
        # hex bytes (con resaltado si aplica)
        for j, b in enumerate(chunk):
            abs_offset = i + j
            in_range = (
                highlight_offset is not None
                and highlight_offset <= abs_offset < highlight_offset + highlight_len
            )
            if in_range:
                line += f"{RED}{b:02x}{RESET} "
            else:
                line += f"{b:02x} "
            if j == 7:
                line += " "
        # padding
        line += "   " * (16 - len(chunk))
        if len(chunk) <= 8:
            line += " "
        # ascii
        line += " |"
        for j, b in enumerate(chunk):
            abs_offset = i + j
            ch = chr(b) if 32 <= b < 127 else "."
            in_range = (
                highlight_offset is not None
                and highlight_offset <= abs_offset < highlight_offset + highlight_len
            )
            if in_range:
                line += f"{RED}{ch}{RESET}"
            else:
                line += ch
        line += "|"
        print(line)
    if len(data) > max_bytes:
        print(f"  ... ({len(data) - max_bytes} bytes mas)")


def show_byte_change(label, offset, before, after):
    print(f"\n  >> MODIFICACION en byte[{offset}]:")
    print(f"     antes:    0x{before:02x}  ({before:08b})  '{chr(before) if 32<=before<127 else '.'}'")
    print(f"     despues:  0x{after:02x}  ({after:08b})  '{chr(after) if 32<=after<127 else '.'}'")
    print(f"     XOR:      0x{before ^ after:02x}  ({before ^ after:08b})")
    print(f"     descripcion: {label}")


def attempt_decrypt(label, fn):
    """Intenta ejecutar fn() y muestra el resultado con detalle."""
    phase("INTENTO DE DESCIFRADO / VERIFICACION")
    print(f"  llamada: {label}")
    print(f"  ejecutando...")
    try:
        result = fn()
        print(f"\n  [!! FALLO DE AUDITORIA] el sistema NO detecto la modificacion")
        print(f"  resultado inesperado: {result!r}")
        return False
    except Exception as e:
        print(f"\n  [EXCEPCION CAPTURADA]")
        kv("tipo",       f"{type(e).__module__}.{type(e).__name__}")
        kv("mensaje",    repr(str(e)) if str(e) else "<vacio>")
        print(f"\n  traceback completo:")
        for line in traceback.format_exception(type(e), e, e.__traceback__):
            for ln in line.rstrip().split("\n"):
                print(f"    {ln}")
        print(f"\n  [OK] sistema fail-closed: lanza excepcion antes de exponer plaintext")
        return True


# ───── TEST 1: METADATA (filename en AAD del SDDV) ────────────────────────────

def test_metadata():
    section(1, "Modificacion de METADATA (filename en AAD del SDDV)")

    phase("FASE 1 — GENERACION DE CONTENEDOR LIMPIO")
    plaintext = b"Documento confidencial de auditoria"
    filename  = "contrato.pdf"
    kv("plaintext",   repr(plaintext))
    kv("plaintext (hex)", plaintext.hex())
    kv("filename",    repr(filename))

    container, key = encrypt_file(plaintext, filename)
    kv("algoritmo",         "AES-256-GCM")
    kv("llave generada",    key.hex())
    kv("contenedor (bytes)", len(container))

    hex_dump(container, label="contenedor SDDV original")

    phase("FASE 2 — VERIFICACION DEL HAPPY PATH")
    print("  primero confirmamos que el contenedor LIMPIO se descifra bien:")
    plaintext_recuperado, meta = decrypt_file(container, key)
    kv("plaintext recuperado", repr(plaintext_recuperado))
    kv("metadata recuperada",  meta)
    assert plaintext_recuperado == plaintext, "el descifrado limpio fallo!"
    print("  [OK] happy path funciona correctamente")

    phase("FASE 3 — APLICAR MODIFICACION MALICIOSA")
    target_offset = 16  # primer byte del filename (justo despues del header fijo)
    tampered = bytearray(container)
    original_byte = tampered[target_offset]
    tampered[target_offset] ^= 0x01
    new_byte = tampered[target_offset]
    show_byte_change(
        f"flip de bit en filename (offset 16 = primer caracter de '{filename}')",
        target_offset, original_byte, new_byte
    )

    hex_dump(tampered, label="contenedor SDDV ADULTERADO",
             highlight_offset=target_offset, highlight_len=1)

    phase("FASE 4 — INTERPRETACION DEL ATAQUE")
    print(f"  el filename forma parte del AAD del cifrado AES-256-GCM.")
    print(f"  modificarlo cambia el AAD presentado al verificar el TAG.")
    print(f"  el TAG calculado durante encrypt cubre 'AAD original + ciphertext'.")
    print(f"  al verificar con AAD modificado, el TAG no coincide -> InvalidTag.")

    detected = attempt_decrypt(
        "decrypt_file(tampered_container, key)",
        lambda: decrypt_file(bytes(tampered), key),
    )
    return detected


# ───── TEST 2: LISTA DE DESTINATARIOS (fingerprint en AAD del SDDH) ──────────

def test_recipient_list():
    section(2, "Modificacion de LISTA DE DESTINATARIOS (fingerprint en AAD)")

    phase("FASE 1 — GENERACION DE LLAVES Y CONTENEDOR HIBRIDO")
    alice_priv, alice_pub = generate_x25519_keypair()
    bob_priv,   bob_pub   = generate_x25519_keypair()

    alice_fp = get_x25519_fingerprint(alice_pub)
    bob_fp   = get_x25519_fingerprint(bob_pub)

    kv("Alice X25519 FP", alice_fp)
    kv("Bob   X25519 FP", bob_fp)

    plaintext = b"Documento compartido entre Alice y Bob"
    filename  = "doc.pdf"
    container = encrypt_for_recipients(plaintext, filename, [alice_pub, bob_pub])

    kv("plaintext",          repr(plaintext))
    kv("filename",            repr(filename))
    kv("contenedor (bytes)",  len(container))
    kv("destinatarios",       2)

    hex_dump(container, label="contenedor SDDH original", max_bytes=160)

    phase("FASE 2 — VERIFICACION DEL HAPPY PATH (Alice y Bob descifran)")
    pt_a, _ = decrypt_for_recipient(container, alice_priv)
    pt_b, _ = decrypt_for_recipient(container, bob_priv)
    kv("Alice recupera", repr(pt_a))
    kv("Bob recupera",   repr(pt_b))
    assert pt_a == plaintext == pt_b
    print("  [OK] ambos destinatarios descifran correctamente")

    phase("FASE 3 — APLICAR MODIFICACION MALICIOSA")
    # Layout SDDH: MAGIC(4) + VER(1) + ALGO(1) + TS(8) + FNAME_LEN(2) + FNAME + RCPT_COUNT(2) + entries
    # Alice es el primer destinatario; su fingerprint empieza en:
    fingerprint_offset = 16 + len(filename) + 2
    tampered = bytearray(container)
    original_byte = tampered[fingerprint_offset]
    tampered[fingerprint_offset] ^= 0x01
    new_byte = tampered[fingerprint_offset]
    show_byte_change(
        f"flip de bit en primer byte del fingerprint de Alice (offset {fingerprint_offset})",
        fingerprint_offset, original_byte, new_byte
    )

    hex_dump(tampered, label="contenedor SDDH ADULTERADO",
             highlight_offset=fingerprint_offset, highlight_len=1, max_bytes=160)

    phase("FASE 4 — INTERPRETACION DEL ATAQUE")
    print(f"  el fingerprint de Alice ya no coincide con SHA-256(alice_pub).")
    print(f"  cuando Alice intente descifrar, decrypt_for_recipient calcula su")
    print(f"  fingerprint y lo busca en la lista. NO encuentra coincidencia.")
    print(f"  -> ValueError 'destinatario no autorizado' antes de tocar el ciphertext.")
    print(f"  ademas, la lista es parte del AAD: si forzaramos seguir, el TAG fallaria.")

    detected = attempt_decrypt(
        "decrypt_for_recipient(tampered, alice_priv)",
        lambda: decrypt_for_recipient(bytes(tampered), alice_priv),
    )
    return detected


# ───── TEST 3: NONCE (12 bytes despues del header del SDDV) ──────────────────

def test_nonce():
    section(3, "Modificacion de NONCE (DEM nonce de 96 bits)")

    phase("FASE 1 — GENERACION DE CONTENEDOR LIMPIO")
    plaintext = b"Mensaje protegido por AES-256-GCM"
    filename  = "doc.txt"
    container, key = encrypt_file(plaintext, filename)

    nonce_offset = 16 + len(filename)
    nonce_original = bytes(container[nonce_offset:nonce_offset + 12])

    kv("plaintext",        repr(plaintext))
    kv("llave",             key.hex())
    kv("contenedor bytes",  len(container))
    kv("nonce offset",      nonce_offset)
    kv("nonce original",    nonce_original.hex())

    hex_dump(container, label="contenedor SDDV original",
             highlight_offset=nonce_offset, highlight_len=12)
    print(f"  (los bytes resaltados son los 12 bytes del nonce)")

    phase("FASE 2 — APLICAR MODIFICACION AL NONCE")
    tampered = bytearray(container)
    original_byte = tampered[nonce_offset]
    tampered[nonce_offset] ^= 0xFF   # flip total del primer byte
    new_byte = tampered[nonce_offset]
    show_byte_change(
        "flip total (XOR 0xFF) del primer byte del nonce",
        nonce_offset, original_byte, new_byte
    )
    nonce_modificado = bytes(tampered[nonce_offset:nonce_offset + 12])
    kv("nonce modificado", nonce_modificado.hex())

    hex_dump(tampered, label="contenedor SDDV ADULTERADO",
             highlight_offset=nonce_offset, highlight_len=12)

    phase("FASE 3 — INTERPRETACION DEL ATAQUE")
    print(f"  AES-GCM usa el nonce para derivar el counter J0 = nonce || 0x00000001.")
    print(f"  el keystream es AES-CTR(K, J0+1, J0+2, ...) y el TAG = GHASH(H, AAD,")
    print(f"  ciphertext) XOR AES_K(J0). modificar el nonce cambia ambos: keystream")
    print(f"  Y tag. el descifrado no recupera plaintext y la verificacion falla.")

    detected = attempt_decrypt(
        "decrypt_file(tampered_container, key)",
        lambda: decrypt_file(bytes(tampered), key),
    )
    return detected


# ───── TEST 4: FIRMA DIGITAL (Ed25519, ultimos 64 bytes) ─────────────────────

def test_signature():
    section(4, "Modificacion de FIRMA DIGITAL (Ed25519)")

    phase("FASE 1 — GENERACION DE LLAVES Y CONTENEDOR FIRMADO")
    alice_sign_priv, alice_sign_pub = generate_keypair()
    pubkey_raw = alice_sign_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    fingerprint = hashlib.sha256(pubkey_raw).digest()
    kv("Alice Ed25519 pub",  pubkey_raw.hex())
    kv("Alice fingerprint",  fingerprint.hex())

    plaintext = b"Documento firmado por Alice"
    filename  = "doc.pdf"
    container, key = encrypt_file(plaintext, filename)
    signed = sign_container(container, alice_sign_priv)

    kv("contenedor SDDV",     f"{len(container)} bytes")
    kv("contenedor firmado",  f"{len(signed)} bytes (= SDDV + 100 bytes footer)")
    kv("layout footer",       "SIGS(4) + FINGERPRINT(32) + SIGNATURE(64)")

    sig_offset = len(signed) - 64
    signature_bytes = bytes(signed[sig_offset:])
    kv("firma Ed25519 (hex)", signature_bytes.hex())

    hex_dump(signed, label="contenedor firmado completo",
             highlight_offset=sig_offset, highlight_len=64, max_bytes=300)
    print(f"  (los 64 bytes resaltados son la firma Ed25519)")

    phase("FASE 2 — VERIFICACION DEL HAPPY PATH")
    container_recuperado = verify_container(signed, alice_sign_pub)
    print(f"  verify_container retorno {len(container_recuperado)} bytes (= SDDV original)")
    pt, _ = decrypt_file(container_recuperado, key)
    kv("plaintext recuperado", repr(pt))
    print("  [OK] firma valida + descifrado correcto")

    phase("FASE 3 — APLICAR MODIFICACION A LA FIRMA")
    target = sig_offset + 54   # byte arbitrario dentro de la firma
    tampered = bytearray(signed)
    original_byte = tampered[target]
    tampered[target] ^= 0x01
    new_byte = tampered[target]
    show_byte_change(
        f"flip de bit dentro de la firma Ed25519 (offset {target})",
        target, original_byte, new_byte
    )

    hex_dump(tampered, label="contenedor firmado ADULTERADO",
             highlight_offset=target, highlight_len=1, max_bytes=300)

    phase("FASE 4 — INTERPRETACION DEL ATAQUE")
    print(f"  Ed25519 calcula la firma como (R, S) donde S = hash(R, A, M) * a + r.")
    print(f"  cualquier flip de bit produce una (R, S) que no satisface la ecuacion")
    print(f"  de verificacion: [S]B == R + [hash(R, A, M)]A. la libreria detecta esto")
    print(f"  y lanza InvalidSignature. Ed25519 es EUF-CMA seguro -> imposible forjar.")

    detected = attempt_decrypt(
        "verify_container(tampered_signed, alice_sign_pub)",
        lambda: verify_container(bytes(tampered), alice_sign_pub),
    )
    return detected


# ───── TEST 5: KEY IDENTIFIER (fingerprint del firmante en footer SIGS) ──────

def test_key_identifier():
    section(5, "Modificacion de KEY IDENTIFIER (signer fingerprint en footer)")

    phase("FASE 1 — GENERACION DE LLAVES Y CONTENEDOR D5 FIRMADO")
    bob_priv,        bob_pub        = generate_x25519_keypair()
    alice_sign_priv, alice_sign_pub = generate_keypair()
    eve_sign_priv,   eve_sign_pub   = generate_keypair()

    alice_pub_raw = alice_sign_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    eve_pub_raw   = eve_sign_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    alice_fp = hashlib.sha256(alice_pub_raw).digest()
    eve_fp   = hashlib.sha256(eve_pub_raw).digest()

    kv("Alice fingerprint", alice_fp.hex())
    kv("Eve   fingerprint", eve_fp.hex())

    plaintext = b"Mensaje secreto firmado por Alice"
    signed = secure_encrypt_and_sign(
        plaintext=plaintext,
        filename="confidencial.pdf",
        recipients=[bob_pub],
        signer_priv=alice_sign_priv,
    )

    kv("contenedor D5",       f"{len(signed)} bytes")
    kv("layout final",         "SDDH(...) || SIGS(4) || SIGNER_FP(32) || SIG(64)")

    fp_start = len(signed) - 96     # despues de SIGS
    fp_end   = fp_start + 32
    embedded_fp = bytes(signed[fp_start:fp_end])
    kv("SIGNER_FP en footer",  embedded_fp.hex())
    kv("coincide con Alice?",  embedded_fp == alice_fp)

    hex_dump(signed, label="contenedor D5 original",
             highlight_offset=fp_start, highlight_len=32, max_bytes=320)
    print(f"  (los 32 bytes resaltados son el SIGNER_FP)")

    phase("FASE 2 — VERIFICACION DEL HAPPY PATH")
    pt, meta = secure_verify_and_decrypt(signed, alice_sign_pub, bob_priv)
    kv("plaintext recuperado", repr(pt))
    print("  [OK] firma valida + Bob descifra")

    phase("FASE 3 — APLICAR MODIFICACION: sustituir SIGNER_FP de Alice por el de Eve")
    tampered = bytearray(signed)
    print(f"  bytes[{fp_start}:{fp_end}] = SIGNER_FP")
    print(f"     antes:   {alice_fp.hex()}")
    print(f"     despues: {eve_fp.hex()}")
    tampered[fp_start:fp_end] = eve_fp

    hex_dump(tampered, label="contenedor D5 ADULTERADO",
             highlight_offset=fp_start, highlight_len=32, max_bytes=320)

    phase("FASE 4 — INTERPRETACION DEL ATAQUE")
    print(f"  el atacante intenta hacerse pasar por Eve manteniendo la firma de Alice.")
    print(f"  pero verify_container compara fingerprint con SHA-256(expected_pub).")
    print(f"  con expected=alice_sign_pub: el FP del footer (Eve) != SHA256(Alice).")
    print(f"  -> InvalidSignature antes de verificar la firma Ed25519 misma.")
    print(f"  ademas, la firma fue calculada sobre 'SDDH || SIGS || alice_fp', asi")
    print(f"  que aunque pasara ese chequeo, Ed25519.verify(sig, ... eve_fp) fallaria.")

    detected = attempt_decrypt(
        "secure_verify_and_decrypt(tampered, alice_sign_pub, bob_priv)",
        lambda: secure_verify_and_decrypt(bytes(tampered), alice_sign_pub, bob_priv),
    )
    return detected


# ───── main ───────────────────────────────────────────────────────────────────

TESTS = [
    ("Metadata",            test_metadata),
    ("Lista destinatarios", test_recipient_list),
    ("Nonce",               test_nonce),
    ("Firma Ed25519",       test_signature),
    ("Key identifier",      test_key_identifier),
]


def main():
    args = sys.argv[1:]
    if "--test" in args:
        idx = int(args[args.index("--test") + 1]) - 1
        banner(f"AUDITORIA — TEST {idx + 1}: {TESTS[idx][0]}")
        TESTS[idx][1]()
        return

    banner("AUDITORIA DE SEGURIDAD DEL SDDV — 5 VECTORES DE MODIFICACION")
    print(f"\n  El SDDV (Secure Digital Document Vault) implementa cifrado AEAD,")
    print(f"  cifrado hibrido multi-destinatario y firma Ed25519 sobre el contenedor")
    print(f"  completo. Esta auditoria modifica byte-a-byte cada componente critico")
    print(f"  y verifica que el sistema lo detecta antes de exponer plaintext.")

    results = []
    for name, fn in TESTS:
        results.append((name, fn()))

    banner("RESUMEN DE RESULTADOS")
    print()
    print(f"  {'TEST':<24} {'DETECTADO?':<12} {'PROPIEDAD':<28}")
    print(f"  {'-'*24} {'-'*12} {'-'*28}")
    properties = {
        "Metadata":            "Integridad",
        "Lista destinatarios": "Integridad/Acceso",
        "Nonce":               "Conf./Integridad",
        "Firma Ed25519":       "Autenticidad",
        "Key identifier":      "Autenticidad/Identidad",
    }
    for name, ok in results:
        icon = "[OK] SI" if ok else "[!!] NO"
        print(f"  {name:<24} {icon:<12} {properties[name]:<28}")

    todos_detectados = all(ok for _, ok in results)
    print()
    if todos_detectados:
        print("  CONCLUSION: el sistema detecta los 5 vectores de modificacion.")
        print("              fail-closed en todos los casos. Ningun byte de plaintext")
        print("              es expuesto cuando el contenedor fue manipulado.")
    else:
        print("  CONCLUSION: AUDITORIA FALLIDA — uno o mas vectores no fueron detectados.")
    print()


if __name__ == "__main__":
    main()
