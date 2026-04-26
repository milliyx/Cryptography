# Bóveda Digital Segura de Documentos (SDDV)

**Equipo:** Barrios Aguilar Dulce Michelle · Contreras Colmenero Emilio Sebastian · Martínez López Evan Emiliano · Caballero Martínez Sergio Jair  
**Materia:** Criptografía — Dra. Rocío Aldeco Pérez · UNAM 2026-2  
**Repositorio:** `feature/d3-hybrid`

---

## Descripción

El SDDV es un sistema de cifrado de documentos que garantiza:

- **Confidencialidad** — AES-256-GCM / ChaCha20-Poly1305 (AEAD) — *D2*
- **Integridad** — tag de 128 bits cubre ciphertext y metadatos — *D2*
- **Compartición segura** — cifrado híbrido multi-destinatario (X25519 ECDH + KEM+DEM) — *D3*
- **Autenticación de origen** — firmas Ed25519 sobre contenedores híbridos completos, patrón verify-first — *D4*
- **Detección de re-empaquetado** — binding del fingerprint del firmante a los datos firmados — *D4*

---

## Estructura del proyecto

```
Proyecto/
├── crypto/
│   ├── aead.py          # D2 — Cifrado AEAD (AES-256-GCM, ChaCha20-Poly1305)
│   ├── keys.py          # Gestión de llaves Ed25519 (PKCS8 PEM)
│   ├── signatures.py    # Firmas Ed25519 + wrappers para SDDH (D4)
│   ├── hybrid.py        # D3 — Cifrado híbrido multi-destinatario (X25519)
│   └── secure_send.py   # D4 — API combinada Encrypt+Sign / Verify+Decrypt
├── tests/
│   ├── test_aead.py             # 27 tests — módulo AEAD
│   ├── test_keys.py             # 19 tests — gestión de llaves
│   ├── test_signatures.py       # 17 tests — firmas digitales (SDDV)
│   ├── test_hybrid.py           # 31 tests — cifrado híbrido
│   └── test_d4_hybrid_signed.py # 28 tests — D4 firma sobre SDDH
├── docs/
│   ├── architecture.svg         # Diagrama de arquitectura
│   ├── D2_Encryption_Design.md  # Documentación D2
│   └── D4_Signature_Design.md   # Documentación D4
├── demo.py              # Script de demo en vivo (D2 + D3 + D4)
└── README.md
```

---

## Instalación

```bash
# Clonar el repositorio
git clone git@github.com:milliyx/Cryptography.git
cd Cryptography
git checkout feature/d3-hybrid

# Instalar dependencias
pip install cryptography
```

---

## Ejecutar tests

```bash
# Todos los tests (122 en total: 94 D2/D3 + 28 D4)
pytest tests/ -v

# Por módulo
pytest tests/test_aead.py -v
pytest tests/test_keys.py -v
pytest tests/test_signatures.py -v
pytest tests/test_hybrid.py -v
pytest tests/test_d4_hybrid_signed.py -v
```

---

## Demo en vivo

```bash
python demo.py
```

El script ejecuta los 5 escenarios automáticamente:

| # | Escenario | Resultado esperado |
|---|-----------|-------------------|
| 1 | Cifrado válido → descifrado | ✔ Plaintext recuperado idéntico |
| 2 | Compartido → ambos destinatarios descifran | ✔ Alice y Bob obtienen el mismo documento |
| 3 | No-destinatario intenta descifrar | ✔ `ValueError: no está autorizado` |
| 4 | Archivo modificado → descifrado falla | ✔ `InvalidTag` en 3 variantes de ataque |
| 5 | **D4 — Firmar + cifrar + verify-first + descifrar** | ✔ Bob/Carol descifran tras verificar; rechazo de re-firmado, metadata modificada y firma eliminada |

---

## Uso de la API

### D2 — Cifrado simétrico (archivo individual)

```python
from crypto.aead import encrypt_file, decrypt_file, Algorithm

# Cifrar
with open("documento.pdf", "rb") as f:
    plaintext = f.read()

container, key = encrypt_file(plaintext, "documento.pdf", algo=Algorithm.AES_256_GCM)

with open("documento.pdf.sddv", "wb") as f:
    f.write(container)

# Descifrar
with open("documento.pdf.sddv", "rb") as f:
    container = f.read()

plaintext, metadata = decrypt_file(container, key)
print(f"Archivo: {metadata['filename']}")
```

### D3 — Cifrado híbrido multi-destinatario

```python
from crypto.hybrid import (
    generate_x25519_keypair,
    encrypt_for_recipients,
    decrypt_for_recipient,
    get_recipient_fingerprints,
)

# Generar llaves para Alice y Bob
alice_priv, alice_pub = generate_x25519_keypair()
bob_priv,   bob_pub   = generate_x25519_keypair()

# Cifrar para ambos
container = encrypt_for_recipients(plaintext, "documento.pdf", [alice_pub, bob_pub])

# Cualquiera de los dos puede descifrar
plaintext_alice, meta = decrypt_for_recipient(container, alice_priv)
plaintext_bob,   meta = decrypt_for_recipient(container, bob_priv)

# Ver destinatarios autorizados (sin necesidad de llave)
fps = get_recipient_fingerprints(container)
print(f"Destinatarios: {fps}")
```

### Firmas digitales sobre contenedores SDDV (Encrypt-then-Sign)

```python
from crypto.keys import generate_keypair
from crypto.signatures import sign_container, verify_container
from crypto.aead import encrypt_file, decrypt_file

priv, pub = generate_keypair()

# 1. Cifrar
container, key = encrypt_file(plaintext, "doc.pdf")

# 2. Firmar el contenedor cifrado
signed = sign_container(container, priv)

# 3. Verificar ANTES de descifrar
container_verificado = verify_container(signed, pub)

# 4. Descifrar solo si la firma es válida
plaintext, meta = decrypt_file(container_verificado, key)
```

### D4 — Cifrado híbrido + firma (API combinada, recomendado)

```python
from crypto.secure_send import secure_encrypt_and_sign, secure_verify_and_decrypt
from crypto.keys import generate_keypair                  # Ed25519 firmante
from crypto.hybrid import generate_x25519_keypair         # X25519 destinatarios

# Llaves
alice_sign_priv, alice_sign_pub = generate_keypair()
bob_priv, bob_pub               = generate_x25519_keypair()
carol_priv, carol_pub           = generate_x25519_keypair()

# Envío: Alice cifra para Bob y Carol, firma con su llave Ed25519
signed_container = secure_encrypt_and_sign(
    plaintext=b"Documento confidencial...",
    filename="contrato.pdf",
    recipients=[bob_pub, carol_pub],
    signer_priv=alice_sign_priv,
)

# Recepción: Bob verifica que sea de Alice y descifra. Si no es de Alice
# o el contenedor fue modificado, lanza InvalidSignature ANTES de descifrar.
plaintext, metadata = secure_verify_and_decrypt(
    signed_container,
    expected_signer_pub=alice_sign_pub,
    recipient_priv=bob_priv,
)
```

La función combinada hace que sea **imposible saltarse la verificación**: si la firma falla, no se llega a la fase de descifrado. Es el patrón "misuse-resistant API" recomendado por NaCl/libsodium.

---

## Formato de contenedores

### SDDV (D2 — cifrado simétrico)
```
MAGIC(4)      b"SDDV"
VERSION(1)    = 1
ALGO_ID(1)    0x01=AES-256-GCM  0x02=ChaCha20-Poly1305
TIMESTAMP(8)  Unix time (big-endian uint64)
FNAME_LEN(2)  longitud del nombre (big-endian uint16)
FILENAME      variable, UTF-8         ← todo lo anterior es el AAD
NONCE(12)     aleatorio CSPRNG
CT_LEN(4)     longitud del ciphertext
CIPHERTEXT    variable
TAG(16)       tag de autenticación AEAD
```

### SDDH (D3 — cifrado híbrido)
```
MAGIC(4)          b"SDDH"
VERSION(1)        = 1
ALGO_ID(1)
TIMESTAMP(8)
FNAME_LEN(2) + FILENAME
RCPT_COUNT(2)     número de destinatarios
Por cada destinatario (124 bytes fijos):
  FINGERPRINT(32)   SHA-256 de la X25519 pub key del destinatario
  EPH_PUB(32)       X25519 ephemeral public key
  WRAP_NONCE(12)    nonce para el AES-GCM de envolvimiento
  WRAPPED_KEY(48)   file_key cifrada: ct(32) + tag(16)   ← todo lo anterior es el AAD
NONCE(12)
CT_LEN(4) + CIPHERTEXT
TAG(16)
```

### SDDH firmado (D4 — autenticación de origen)
```
[ contenedor SDDH completo, tal como D3 ]    ← cubierto por la firma
SIGN_MAGIC(4)     b"SIGS"                    ← cubierto por la firma
SIGNER_FP(32)     SHA-256(raw Ed25519 pub)   ← cubierto por la firma
SIGNATURE(64)     Ed25519 sobre TODO lo anterior
```

**Garantías del footer de firma:**
- Cubre el SDDH **completo** (metadatos, lista de destinatarios, ciphertext, tag AEAD).
- El `SIGNER_FP` está **incluido** en lo firmado, por lo que un atacante no puede sustituir la identidad del firmante manteniendo la firma válida.
- Verificación con `Ed25519PublicKey.verify(sig, SDDH || b"SIGS" || fp)`. Si falla → `InvalidSignature`.

---

## Decisiones de diseño criptográfico

| Decisión | Elección | Justificación |
|----------|----------|---------------|
| Cifrado simétrico | AES-256-GCM | AEAD nativo, hardware-accelerated, estándar NIST |
| Alternativa | ChaCha20-Poly1305 | Resistente a timing attacks, sin instrucciones AES |
| Nonce | 96-bit CSPRNG | Probabilidad de colisión ≈ 2⁻³² tras 2³² mensajes |
| AAD | Cabecera completa | Cualquier modificación a metadatos invalida el TAG |
| Firma | Ed25519 | 128-bit seguridad, 64-byte sig, determinista (RFC 8032) |
| Patrón | Encrypt-then-Sign | Verificación antes de descifrar — no expone plaintext |
| Datos firmados | SDDH completo + magic + fingerprint | Cubre metadata, recipients, ciphertext, tag; binding de identidad |
| Identificación firmante | SHA-256(raw pubkey Ed25519) | 32 bytes, coherente con D3, sin PKI |
| Encoding firma | 64 bytes raw (RFC 8032) | Sin base64; el contenedor ya es binario |
| KEM | X25519 ECDH + HKDF | Ephemeral keys por destinatario → forward secrecy |
| KDF de wrapping | HKDF-SHA256 | Salt = fingerprint del destinatario, info = "SDDV-D3-wrap" |
| Protección llave priv | PKCS8 PEM (AES-256-CBC) | Estándar compatible con OpenSSL |

---

## Modelo de amenazas

**Adversario:** atacante con acceso de lectura/escritura al disco.

**Protegemos contra:**
- Lectura del contenido sin la clave → ciphertext ilegible
- Modificación del contenido o metadatos → `InvalidTag` (D2/D3) + `InvalidSignature` (D4)
- Acceso de usuario no autorizado → `ValueError` en KEM lookup (D3)
- Suplantación del remitente → `InvalidSignature` en verificación (D4)
- Re-empaquetado por terceros → fingerprint del firmante incluido en lo firmado (D4)
- Context manipulation (cambio de filename, recipients, algo) → cubierto por la firma sobre la cabecera completa (D4)

**Fuera de scope:**
- Compromiso de la memoria del proceso en ejecución
- Canal de distribución de llaves públicas (se asume auténtico — no hay PKI)
- Revocación de llaves comprometidas
- Replay attacks (no hay nonce de sesión ni timestamp autoritativo)
- Ataques de denegación de servicio
