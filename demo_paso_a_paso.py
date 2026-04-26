"""
demo_paso_a_paso.py
===================
Demo interactiva que muestra cada paso del cifrado AEAD y del
cifrado hibrido KEM+DEM paso a paso.

Ejecutar:
    python3 demo_paso_a_paso.py
"""

import os, sys, struct, time
sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ── colores ──────────────────────────────────────────────────────────────────
G  = "\033[92m"   # verde
R  = "\033[91m"   # rojo
C  = "\033[96m"   # cyan
Y  = "\033[93m"   # amarillo
B  = "\033[94m"   # azul
DIM= "\033[2m"    # dim
BO = "\033[1m"    # bold
RS = "\033[0m"    # reset

def paso(n, titulo):
    print(f"\n{BO}{Y}▶  PASO {n} — {titulo}{RS}")
    print(f"{DIM}{'─'*58}{RS}")

def muestra(etiqueta, valor, color=C):
    print(f"  {DIM}{etiqueta:<22}{RS}{color}{valor}{RS}")

def ok(msg):   print(f"  {G}✔  {msg}{RS}")
def err(msg):  print(f"  {R}✖  {msg}{RS}")
def espera():
    input(f"\n  {DIM}[ Presiona Enter para continuar... ]{RS}")

# =============================================================================
# PARTE 1 — CIFRADO SIMÉTRICO AEAD (AES-256-GCM)
# =============================================================================

def parte_aead():
    print(f"\n{BO}{'═'*58}")
    print(f"  PARTE 1 · Cifrado AEAD — AES-256-GCM")
    print(f"{'═'*58}{RS}")

    PLAINTEXT = "Contrato UNAM 2026 - Clausula 1: acceso restringido.".encode()
    FILENAME  = "contrato.pdf"

    # ── PASO 1 ────────────────────────────────────────────────────────────────
    paso(1, "Datos de entrada")
    muestra("Archivo:",     FILENAME)
    muestra("Contenido:",   PLAINTEXT.decode())
    muestra("Tamaño:",      f"{len(PLAINTEXT)} bytes")
    espera()

    # ── PASO 2 ────────────────────────────────────────────────────────────────
    paso(2, "Generar clave de 256 bits (CSPRNG)")
    key = os.urandom(32)
    muestra("Clave (hex):", key.hex())
    muestra("Bits:",        f"{len(key)*8}  ←  2^256 posibilidades")
    print(f"\n  {DIM}os.urandom() usa el CSPRNG del SO (getrandom en Linux,{RS}")
    print(f"  {DIM}CryptGenRandom en Windows). Nunca predecible.{RS}")
    espera()

    # ── PASO 3 ────────────────────────────────────────────────────────────────
    paso(3, "Generar nonce de 96 bits (CSPRNG)")
    nonce = os.urandom(12)
    muestra("Nonce (hex):", nonce.hex())
    muestra("Bits:",        "96  ←  único por operación de cifrado")
    print(f"\n  {DIM}Reutilizar nonce con la misma clave rompe GCM.{RS}")
    print(f"  {DIM}Con 96 bits aleatorios la colisión es prácticamente imposible.{RS}")
    espera()

    # ── PASO 4 ────────────────────────────────────────────────────────────────
    paso(4, "Construir AAD (Associated Authenticated Data)")
    timestamp = int(time.time())
    fname_b   = FILENAME.encode()
    aad = b"SDDV" + bytes([1, 1]) + struct.pack(">Q", timestamp) + struct.pack(">H", len(fname_b)) + fname_b
    muestra("MAGIC:",     "53 44 44 56  →  'SDDV'")
    muestra("VERSION:",   "01")
    muestra("ALGO_ID:",   "01  →  AES-256-GCM")
    muestra("TIMESTAMP:", f"{timestamp}  →  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}")
    muestra("FILENAME:",  FILENAME)
    muestra("AAD total:", f"{len(aad)} bytes  (no cifrado, sí autenticado)")
    print(f"\n  {DIM}El AAD nunca se cifra, pero el TAG lo protege.{RS}")
    print(f"  {DIM}Cambiar filename o timestamp → TAG inválido.{RS}")
    espera()

    # ── PASO 5 ────────────────────────────────────────────────────────────────
    paso(5, "Cifrar con AES-256-GCM")
    cipher      = AESGCM(key)
    ct_with_tag = cipher.encrypt(nonce, PLAINTEXT, aad)
    ciphertext  = ct_with_tag[:-16]
    tag         = ct_with_tag[-16:]

    print(f"\n  {DIM}AES-256-GCM( key, nonce, plaintext, AAD )  →  ciphertext + TAG{RS}\n")
    muestra("Ciphertext (hex):", ciphertext.hex())
    muestra("TAG (hex):",        tag.hex())
    muestra("TAG bits:",         "128  ←  autenticación del ciphertext Y el AAD")
    print(f"\n  {DIM}El TAG es la 'firma' de que nada fue modificado.{RS}")
    espera()

    # ── PASO 6 ────────────────────────────────────────────────────────────────
    paso(6, "Construir contenedor SDDV final")
    ct_len    = struct.pack(">I", len(ciphertext))
    container = aad + nonce + ct_len + ciphertext + tag
    print(f"\n  {DIM}[ AAD | NONCE | CT_LEN | CIPHERTEXT | TAG ]{RS}\n")
    muestra("Tamaño total:",  f"{len(container)} bytes")
    muestra("Overhead:",      f"{len(container)-len(PLAINTEXT)} bytes  (nonce 12 + tag 16 + header)")
    muestra("Primeros bytes:","53 44 44 56  →  magic 'SDDV'")
    espera()

    # ── PASO 7 ────────────────────────────────────────────────────────────────
    paso(7, "Descifrar y verificar TAG")
    plaintext_dec = cipher.decrypt(nonce, ciphertext + tag, aad)
    ok(f"TAG verificado — ningún byte fue manipulado")
    ok(f"Plaintext recuperado: {plaintext_dec.decode()}")
    espera()

    # ── PASO 8 ────────────────────────────────────────────────────────────────
    paso(8, "Intento de tamper — modificar 1 byte del ciphertext")
    from cryptography.exceptions import InvalidTag
    tampered = bytearray(container)
    tampered[len(aad) + 12 + 4] ^= 0xFF   # flip un bit del ciphertext
    try:
        cipher.decrypt(nonce, bytes(tampered[len(aad)+12+4 : -16]) + tag, aad)
    except InvalidTag:
        err("InvalidTag — manipulación detectada")
        ok("El sistema no devolvió ni un byte del plaintext")

# =============================================================================
# PARTE 2 — CIFRADO HÍBRIDO KEM+DEM (X25519 + AES-256-GCM)
# =============================================================================

def parte_hibrido():
    print(f"\n{BO}{'═'*58}")
    print(f"  PARTE 2 · Cifrado Híbrido KEM+DEM — X25519 + AES-GCM")
    print(f"{'═'*58}{RS}")

    PLAINTEXT = "Contrato UNAM 2026 - Clausula 1: acceso restringido.".encode()
    FILENAME  = "contrato.pdf"

    # ── PASO 1 ────────────────────────────────────────────────────────────────
    paso(1, "Generar llaves permanentes X25519 de Alice y Bob")
    alice_priv = X25519PrivateKey.generate()
    bob_priv   = X25519PrivateKey.generate()
    alice_pub  = alice_priv.public_key()
    bob_pub    = bob_priv.public_key()
    alice_pub_bytes = alice_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    bob_pub_bytes   = bob_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    fp_alice = __import__('hashlib').sha256(alice_pub_bytes).hexdigest()
    fp_bob   = __import__('hashlib').sha256(bob_pub_bytes).hexdigest()

    muestra("Alice pub key:", alice_pub_bytes.hex()[:32] + "...")
    muestra("Bob   pub key:", bob_pub_bytes.hex()[:32] + "...")
    muestra("Alice FP:",      fp_alice[:16] + "...")
    muestra("Bob   FP:",      fp_bob[:16] + "...")
    print(f"\n  {DIM}Fingerprint = SHA-256(pub_key)  →  64 hex chars{RS}")
    print(f"  {DIM}Permite a cada receptor encontrar su slot sin leer todos.{RS}")
    espera()

    # ── PASO 2 ────────────────────────────────────────────────────────────────
    paso(2, "DEM — Generar file_key aleatoria de 256 bits")
    file_key = os.urandom(32)
    muestra("file_key (hex):", file_key.hex())
    muestra("Bits:", "256  ←  cifra el archivo completo con AES-GCM")
    print(f"\n  {DIM}Una sola clave cifra el archivo. KEM la encapsula{RS}")
    print(f"  {DIM}individualmente para cada destinatario.{RS}")
    espera()

    # ── PASO 3 ────────────────────────────────────────────────────────────────
    paso(3, "KEM — Encapsular file_key para Alice (ECDH efímero)")
    eph_priv_a = X25519PrivateKey.generate()
    eph_pub_a  = eph_priv_a.public_key()
    eph_pub_a_bytes = eph_pub_a.public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared_a = eph_priv_a.exchange(alice_pub)
    salt_a   = eph_pub_a_bytes + alice_pub_bytes
    wrapping_key_a = HKDF(SHA256(), 32, salt_a, b"SDDV-KEM-v1").derive(shared_a)
    nonce_a   = os.urandom(12)
    wrapped_a = AESGCM(wrapping_key_a).encrypt(nonce_a, file_key, None)

    muestra("Eph priv (Alice):", eph_pub_a_bytes.hex()[:24] + "...  (nunca se guarda)")
    muestra("ECDH shared:",      shared_a.hex()[:24] + "...")
    muestra("HKDF →wrapping_key:",wrapping_key_a.hex()[:24] + "...")
    muestra("Wrapped file_key:", wrapped_a.hex()[:24] + "...")
    print(f"\n  {DIM}Llave efímera descartada → Forward Secrecy garantizado.{RS}")
    espera()

    # ── PASO 4 ────────────────────────────────────────────────────────────────
    paso(4, "KEM — Encapsular file_key para Bob (ECDH efímero diferente)")
    eph_priv_b = X25519PrivateKey.generate()
    eph_pub_b  = eph_priv_b.public_key()
    eph_pub_b_bytes = eph_pub_b.public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared_b = eph_priv_b.exchange(bob_pub)
    salt_b   = eph_pub_b_bytes + bob_pub_bytes
    wrapping_key_b = HKDF(SHA256(), 32, salt_b, b"SDDV-KEM-v1").derive(shared_b)
    nonce_b   = os.urandom(12)
    wrapped_b = AESGCM(wrapping_key_b).encrypt(nonce_b, file_key, None)

    muestra("Eph priv (Bob):",   eph_pub_b_bytes.hex()[:24] + "...  (diferente a Alice)")
    muestra("Wrapped file_key:", wrapped_b.hex()[:24] + "...")
    print(f"\n  {DIM}Cada destinatario tiene su propio ECDH efímero.{RS}")
    espera()

    # ── PASO 5 ────────────────────────────────────────────────────────────────
    paso(5, "DEM — Cifrar el archivo con la file_key")
    nonce_file = os.urandom(12)
    ciphertext_file = AESGCM(file_key).encrypt(nonce_file, PLAINTEXT, None)
    muestra("file_key usada:",   file_key.hex()[:24] + "...")
    muestra("Ciphertext:",       ciphertext_file.hex()[:24] + "...")
    muestra("Tamaño:",           f"{len(PLAINTEXT)} bytes → {len(ciphertext_file)} bytes")
    print(f"\n  {DIM}El archivo se cifra UNA sola vez sin importar{RS}")
    print(f"  {DIM}cuántos destinatarios haya.{RS}")
    espera()

    # ── PASO 6 ────────────────────────────────────────────────────────────────
    paso(6, "Alice descifra — busca su fingerprint, recupera file_key")
    shared_dec_a   = alice_priv.exchange(eph_pub_a)
    wk_dec_a       = HKDF(SHA256(), 32, eph_pub_a_bytes + alice_pub_bytes, b"SDDV-KEM-v1").derive(shared_dec_a)
    file_key_dec_a = AESGCM(wk_dec_a).decrypt(nonce_a, wrapped_a, None)
    plaintext_a    = AESGCM(file_key_dec_a).decrypt(nonce_file, ciphertext_file, None)

    ok(f"Alice recupera file_key: {file_key_dec_a.hex()[:16]}...")
    ok(f"Alice descifra: {plaintext_a.decode()}")
    espera()

    # ── PASO 7 ────────────────────────────────────────────────────────────────
    paso(7, "Eve intenta descifrar sin ser destinataria")
    eve_priv = X25519PrivateKey.generate()
    shared_eve = eve_priv.exchange(eph_pub_a)   # ECDH con la llave de Alice
    wk_eve     = HKDF(SHA256(), 32, eph_pub_a_bytes + alice_pub_bytes, b"SDDV-KEM-v1").derive(shared_eve)
    try:
        AESGCM(wk_eve).decrypt(nonce_a, wrapped_a, None)
    except Exception:
        from cryptography.exceptions import InvalidTag
        err("InvalidTag — Eve no puede recuperar la file_key")
        ok("Sin file_key, el ciphertext del archivo es inaccesible")

# =============================================================================
# MAIN
# =============================================================================
if __name__ == "__main__":
    print(f"\n{BO}{'═'*58}")
    print("  SDDV · Demo Paso a Paso")
    print("  Bóveda Digital Segura de Documentos")
    print(f"{'═'*58}{RS}")
    print(f"\n  {DIM}Presiona Enter para avanzar entre pasos.{RS}")

    parte_aead()

    print(f"\n{BO}{Y}{'─'*58}")
    print(f"  Parte 1 completa. Continuamos con cifrado híbrido.")
    print(f"{'─'*58}{RS}")
    espera()

    parte_hibrido()

    print(f"\n{BO}{G}{'═'*58}")
    print("  Demo completada.")
    print(f"{'═'*58}{RS}\n")
