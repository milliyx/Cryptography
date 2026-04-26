# D4 — Diseño del Módulo de Firma Digital

**Bóveda Digital Segura de Documentos (SDDV)**

| | |
|---|---|
| **Equipo** | Barrios Aguilar Dulce Michelle · Contreras Colmenero Emilio Sebastian · Martínez López Evan Emiliano · Caballero Martínez Sergio Jair |
| **Curso** | Criptografía — Semestre 2026-2 — Dra. Rocío Aldeco Pérez |
| **Fecha** | Abril 2026 |

---

## Objetivo del módulo

Hasta D3 el sistema garantiza **confidencialidad** (cifrado AEAD) y **control de acceso** (KEM+DEM multi-destinatario), pero **no garantiza quién creó el archivo**. Cualquiera con la llave pública del destinatario puede generar un contenedor SDDH legítimo y hacerlo pasar por enviado por otra persona.

D4 cierra ese hueco con **firma digital**: el receptor podrá verificar que un archivo fue creado por un usuario específico y no ha sido modificado desde que se firmó. Las garantías que D4 añade son:

1. **Autenticación de origen** — el receptor sabe quién firmó.
2. **Integridad cross-layer** — cualquier modificación al ciphertext, los metadatos, o la lista de destinatarios se detecta.
3. **Rechazo de contenedores forjados o manipulados** — antes de descifrar.

---

## 1. Algoritmo elegido: Ed25519

Implementamos firma con **Ed25519** (RFC 8032, Edwards-curve Digital Signature Algorithm sobre Curve25519).

### Por qué Ed25519

| Propiedad | Justificación |
|---|---|
| **128-bit de seguridad** | Curve25519 ofrece ~126 bits efectivos contra ataques de logaritmo discreto en curva elíptica, equivalente a RSA-3072 pero con llaves de 32 bytes. Cumple requisito RS-1 del D1. |
| **Firmas deterministas** | Misma llave + mismo mensaje = misma firma. Elimina la dependencia de un nonce/k aleatorio por firma. |
| **Sin riesgo de "PS3 bug"** | ECDSA y DSA se rompen si el `k` aleatorio se repite o se filtra (Sony PS3 fue hackeada exactamente así en 2010). Ed25519 lo previene por construcción: deriva un nonce determinista a partir de la llave privada y el mensaje vía SHA-512. |
| **Resistencia a timing** | Diseñado por Bernstein con operaciones de tiempo constante. |
| **Tamaños fijos pequeños** | Llave privada 32 bytes, llave pública 32 bytes, firma 64 bytes. La verificación es rápida (~70 µs en hardware moderno). |
| **Estandarizado** | RFC 8032 (IRTF, 2017). Implementado en TLS 1.3, SSH, GnuPG, libsodium. |

### Por qué no ECDSA o RSA-PSS

- **ECDSA** fue una opción válida (NIST P-256 con SHA-256, RFC 6979 para nonces deterministas). Lo descartamos porque Ed25519 tiene determinismo desde la especificación, no como añadido posterior, y porque el ecosistema moderno (`age`, Saltpack, minisign, Signal) está estandarizando alrededor de Ed25519.
- **RSA-PSS** es seguro y bien analizado, pero las llaves de 3072 bits (necesarias para 128-bit security) ocupan 384 bytes y la verificación es ~10× más lenta. No hay razón técnica para preferirlo en un sistema nuevo.

---

## 2. Qué se firma exactamente

La firma cubre el **contenedor SDDH completo** producido por D3 más un binding de la identidad del firmante:

```
data_a_firmar = SDDH_completo  ||  SIGN_MAGIC(b"SIGS")  ||  signer_fingerprint(32)
```

Es decir, todo lo siguiente queda bajo la firma:

```
┌─────────────────────────────────────────────────────────┐
│  CABECERA SDDH (= AAD del DEM)                          │
├─────────────────────────────────────────────────────────┤
│  MAGIC b"SDDH"                                          │
│  VERSION                                                │
│  ALGO_ID                                                │
│  TIMESTAMP                                              │
│  FILENAME_LEN + FILENAME                                │
│  RECIPIENT_COUNT                                        │
│  Por cada destinatario (124 bytes):                     │
│    FINGERPRINT  + EPH_PUB  + WRAP_NONCE  + WRAPPED_KEY  │
├─────────────────────────────────────────────────────────┤
│  NONCE_DEM                                              │
│  CT_LEN  +  CIPHERTEXT  +  TAG_AEAD                     │
├─────────────────────────────────────────────────────────┤
│  SIGN_MAGIC b"SIGS"     ← incluido en lo firmado        │
│  SIGNER_FINGERPRINT     ← incluido en lo firmado        │
└─────────────────────────────────────────────────────────┘
        SIGNATURE Ed25519 (64 bytes)   ← solo la firma queda fuera
```

### Por qué incluir el `signer_fingerprint` en los datos firmados

Si solo firmáramos el SDDH, un atacante podría tomar `signed = SDDH || SIGS || fp_alice || sig_alice` y reescribir el footer como `SDDH || SIGS || fp_eve || sig_alice` — la firma `sig_alice` es matemáticamente válida sobre `SDDH`, pero el footer ahora **anuncia** que es de Eve. Un verificador descuidado podría confundirse.

Al hacer que la firma cubra `SDDH || SIGS || fingerprint`, vinculamos la identidad del firmante al cómputo de la firma. Cualquier sustitución del fingerprint invalida la firma.

### Mapeo al rubric del entregable

El rubric exige que el contenedor incluya:

| Campo del rubric | Dónde está en SDDV |
|---|---|
| `metadata` | Cabecera SDDH (MAGIC, VERSION, ALGO_ID, TIMESTAMP, FILENAME) |
| `recipients` | Lista de entradas de destinatarios en la cabecera SDDH |
| `ciphertext` | Sección cifrada del SDDH |
| `tag` | Tag AEAD del DEM (16 bytes) |
| `signature` | 64 bytes Ed25519 al final del footer |
| `signer_id` | Fingerprint SHA-256 de la pubkey Ed25519 (32 bytes en el footer) |

---

## 3. Por qué el hash es necesario antes de firmar

Conceptualmente, la operación es **Hash → Sign → Verify**. En la implementación, el hash es **interno a Ed25519** y queda transparente para el código cliente: cuando llamas `private_key.sign(data)`, la primitiva hace internamente `SHA-512(prefix || A || data)` y firma sobre ese hash. No tenemos que invocar SHA-512 manualmente.

Aun así, el rubric pide explicar **por qué** el hash es necesario, no solo dónde está:

### 1. Tamaño constante del input para la primitiva matemática

La operación de firma EdDSA (o ECDSA, RSA-PSS) requiere un input de tamaño fijo determinado por el campo finito subyacente. SHA-512 reduce un mensaje de longitud arbitraria (1 byte o 1 GB) a 64 bytes deterministas. Sin el hash, tendríamos que firmar mensajes muy largos por bloques o limitar el tamaño del input — ambas alternativas son frágiles e introducen bugs.

### 2. Resistencia a colisiones

Si el algoritmo de hash es resistente a colisiones (SHA-512 lo es bajo el modelo estándar), encontrar dos mensajes distintos $M_1 \neq M_2$ con `H(M_1) = H(M_2)` es computacionalmente inviable. Esto significa que una firma sobre `H(M_1)` es válida solo para `M_1`, no para `M_2`. Sin un hash resistente a colisiones, un atacante podría generar dos contratos `M_1` y `M_2` con el mismo hash, hacerte firmar `M_1`, y exhibir tu firma como prueba de que firmaste `M_2`.

### 3. Defensa contra ataques de length-extension y manipulación

Algunos esquemas de firma legacy (RSA con padding ingenuo) son vulnerables a manipulación del mensaje si no se hashea primero. Hashear el mensaje antes de aplicar la primitiva matemática elimina esa clase de ataques por construcción.

### 4. Decisión específica de Ed25519: PureEdDSA con SHA-512

Ed25519 (RFC 8032 §5.1) usa **PureEdDSA**: hashea internamente con SHA-512 y firma. Esto significa:
- El cliente pasa el mensaje completo a `sign()`, no el hash.
- El hash es parte del estándar, no una decisión del implementador → no podemos equivocarnos.
- A diferencia de "HashEdDSA" (Ed25519ph), no hay que decidir qué hash usar antes; la primitiva lo fija.

---

## 4. Decisiones de seguridad

### 4.1 ¿Por qué firmar el ciphertext y no el plaintext?

Optamos por **Encrypt-then-Sign**: primero D3 cifra produciendo el SDDH, luego D4 firma sobre el SDDH completo.

**Razones:**

1. **Verificación antes de descifrar.** El receptor verifica la firma con la pubkey del firmante esperado. Si falla, descarta el contenedor sin gastar un solo ciclo de CPU descifrando. Si firmáramos el plaintext, el receptor tendría que descifrar primero para tener algo que verificar.

2. **No exponer plaintext de origen incierto.** Descifrar antes de verificar implica que en el momento de chequear la firma, el plaintext ya está en memoria. Si la firma falla, ese plaintext es de origen no autenticado y nunca debió tocarse — pero ya lo tocó la rutina de descifrado. En sistemas reales con efectos secundarios (logging, parsing, renderizado), eso puede ser explotable.

3. **No habilitar oráculos de descifrado.** Si la app distingue entre "ciphertext válido pero firma inválida" y "ciphertext inválido", el atacante puede usar la app como oráculo: enviar bytes manipulados y aprender qué los hace pasar la verificación AEAD pero no la de firma. Verificar la firma primero hace que toda firma falsa tarde lo mismo.

4. **Composición segura.** Krawczyk (2001, "The Order of Encryption and Authentication for Protecting Communications") demostró formalmente que Encrypt-then-Authenticate es la composición universalmente segura. Sign-then-Encrypt y Encrypt-and-Sign tienen patologías sutiles según el esquema de cifrado.

### 4.2 ¿Qué pasa si la firma no se verifica primero?

Cuatro escenarios concretos donde el orden importa:

- **Pérdida de CPU**: descifrar 1 GB de un contenedor falso para luego rechazarlo en la verificación final. El atacante puede DoS al receptor con contenedores grandes y firma inválida.

- **Filtrado por timing**: la app procesa diferente "decrypt OK + verify FAIL" vs "decrypt FAIL"; el atacante mide tiempos para distinguir y refinar el ataque.

- **Efectos secundarios irreversibles**: la app de ejemplo procesa el plaintext (lo loguea, lo envía a otra cola, lanza un parser PDF que llama un servicio externo) antes de verificar la firma. Si esos efectos persisten, ya no se pueden deshacer aunque la firma falle.

- **Falsa sensación de seguridad**: si el código verifica la firma "después" pero la app se acostumbra a usar el plaintext intermedio, habrá ocasiones donde se "olviden" de verificar — y el sistema entero es tan fuerte como su llamada más débil.

La función `secure_verify_and_decrypt` en `crypto/secure_send.py` previene los cuatro casos por construcción: si la firma falla, lanza `InvalidSignature` antes de invocar `decrypt_for_recipient`.

### 4.3 ¿Qué pasa si los metadatos se excluyen de la firma?

Si la firma cubriera solo el ciphertext y no los metadatos, el atacante puede ejecutar **context-binding attacks** sin invalidar la firma:

- **Renombrar archivos**: cambiar `FILENAME` del SDDH de `bono_alice.pdf` a `bono_eve.pdf`. La firma es válida, el AEAD detecta la modificación del AAD — pero un sistema que use `verify_then_decrypt` correctamente queda protegido. Si firma y AEAD no estuvieran sincronizados, el atacante podría cambiar metadatos sin que ni la firma ni el AEAD lo detecten.

- **Recipient stripping**: cambiar `RECIPIENT_COUNT` de 3 a 1, eliminando lógicamente a Bob y Carol. El SDDH ya tiene esto cubierto por el AAD del DEM, pero al firmar el SDDH **completo** (incluyendo la lista de destinatarios) añadimos una segunda capa: la firma certifica que Alice envió este archivo a estos N destinatarios exactos.

- **Algorithm downgrade**: cambiar `ALGO_ID` de AES-GCM a ChaCha20. Sin firma sobre la cabecera, el atacante podría hacer que el receptor intente descifrar con el algoritmo equivocado — el AEAD detectaría la inconsistencia, pero solo después de gastar CPU.

- **Re-targeting**: tomar un SDDH legítimo enviado a Bob y modificar el fingerprint del destinatario. Cambia "esto era para Bob" a "esto era para Eve". El AEAD y la firma juntas (porque la lista entera está en lo firmado) hacen este ataque imposible.

Por estas razones, **toda la cabecera SDDH (incluida la lista de destinatarios) está cubierta por la firma**, no solo el ciphertext. Es el principio fundamental de AEAD aplicado una capa más arriba.

---

## 5. Identificación del firmante

El firmante se identifica con su **fingerprint SHA-256 de 32 bytes**:

```
signer_fingerprint = SHA-256( raw_ed25519_public_key_32_bytes )
```

### Por qué fingerprint en lugar de la llave pública directa

- **Tamaño consistente**: 32 bytes siempre, independiente del esquema de firma.
- **Compatibilidad con D3**: D3 ya usa fingerprints SHA-256 para identificar destinatarios X25519. D4 usa la misma estructura para Ed25519, manteniendo coherencia.
- **Ofuscación trivial**: el fingerprint no revela la llave pública (aunque la pubkey Ed25519 generalmente no es secreta, este pequeño paso facilita una eventual rotación a esquemas que requieran ocultar pubkeys).
- **No requiere PKI**: el destinatario conoce a priori el fingerprint del firmante esperado (ej. publicado en un sitio web o intercambiado por canal seguro). No hay autoridades certificadoras.

### Encoding

| Forma | Tamaño | Uso |
|---|---|---|
| Bytes raw | 32 bytes | En el footer del contenedor (campo `FINGERPRINT`) |
| Hex lowercase | 64 chars | En la API Python (`get_signer_fingerprint()` retorna `str`) |

La firma Ed25519 se almacena como **64 bytes raw** según RFC 8032 §3.4 — sin base64, sin DER. El contenedor es binario; cualquier codificación adicional sería overhead.

---

## 6. Workflow de envío y recepción

### Envío (`secure_encrypt_and_sign`)

```
1. Generar file_key aleatorio (32 bytes CSPRNG).
2. KEM: para cada destinatario X25519:
     a. Generar par efímero X25519.
     b. shared = ECDH(eph_priv, recipient_pub).
     c. wrapping_key = HKDF-SHA256(shared, salt=fp_dest, info=b"SDDV-D3-wrap").
     d. wrapped = AES-GCM(wrapping_key).encrypt(file_key).
3. Construir cabecera SDDH (incluye lista completa de destinatarios).
4. DEM: AES-GCM(file_key).encrypt(plaintext, AAD=cabecera_completa) → SDDH.
5. Firmar: signature = Ed25519(signer_priv).sign(SDDH || b"SIGS" || fp_signer).
6. Concatenar: signed = SDDH || b"SIGS" || fp_signer || signature.
```

### Recepción (`secure_verify_and_decrypt`)

```
1. Leer contenedor firmado.
2. Separar footer: container = signed[:-100], footer = signed[-100:].
3. Extraer fp y firma del footer.
4. VERIFICAR:
     a. Comprobar que fp coincide con SHA-256(expected_signer_pubkey).
        Si no coincide → InvalidSignature (no es del firmante esperado).
     b. Verificar la firma Ed25519 sobre (container || b"SIGS" || fp).
        Si falla → InvalidSignature.
5. Si verify pasó, descifrar:
     a. Buscar mi fingerprint X25519 en la lista de destinatarios del SDDH.
        Si no estoy → ValueError ("no autorizado").
     b. Reconstruir wrapping_key con mi privada X25519 y eph_pub del SDDH.
     c. Desenvolver file_key.
     d. AES-GCM(file_key).decrypt(ciphertext, AAD=cabecera) → plaintext.
6. Retornar (plaintext, metadata).
```

El paso 4 **siempre** ocurre antes del paso 5. Esa es la garantía de seguridad de D4.

---

## 7. Modelo de amenazas de D4

### Adversarios considerados

| Nombre | Capacidad | D4 protege? |
|---|---|---|
| **ADV-1** lectura del medio | Lee el contenedor en disco/red | ✅ Confidencialidad por D3, integridad por D2/D3, autenticidad por D4 |
| **ADV-2** escritura del medio | Modifica el contenedor en tránsito | ✅ Cualquier byte modificado invalida la firma |
| **ADV-3** suplantación del remitente | Genera contenedores falsos pretendiendo ser Alice | ✅ Sin la priv de Alice no puede producir firma válida sobre `SDDH || SIGS || fp_alice` |
| **ADV-4** re-empaquetado | Toma SDDH legítimo de Alice y lo re-firma como Eve | ✅ El fingerprint del footer cambia → el verificador que espera a Alice rechaza |
| **ADV-5** context manipulation | Cambia metadatos (filename, recipients, algo) | ✅ La firma cubre la cabecera completa del SDDH |

### Garantías formales

- **Existential Unforgeability under Chosen Message Attack (EUF-CMA)**: bajo el modelo estándar, Ed25519 es EUF-CMA seguro. Sin la llave privada del firmante, generar una firma válida sobre cualquier mensaje (incluso uno que el firmante haya firmado mil veces antes con variaciones) requiere $\geq 2^{128}$ operaciones.
- **Strong Unforgeability**: Ed25519 es además SUF-CMA seguro: el atacante no puede ni siquiera producir una **firma diferente** sobre un mensaje ya firmado. Esto es relevante porque significa que las firmas no se pueden "manipular" sin invalidarlas.

### Fuera del scope de D4

| Amenaza | Por qué no la cubrimos |
|---|---|
| **Replay** del contenedor | No hay nonce de sesión ni marca de frescura. Para documentos at-rest es razonable; para mensajería en tiempo real requeriría capas adicionales. |
| **Revocación de llaves** | No hay PKI ni CRL. Si la llave privada de Alice se compromete, todas las firmas previas y futuras quedan en duda hasta que se distribuye una nueva pubkey por canal seguro. |
| **Confidencialidad del firmante** | El fingerprint del firmante está en el footer en claro. Cualquiera con acceso al contenedor puede ver "esto fue firmado por X" sin tener la pubkey. Si se requiere ocultar la identidad del remitente (anonymous signing, group signatures), está fuera del alcance del proyecto. |
| **No-repudio jurídico** | Criptográficamente, una firma Ed25519 válida prueba que alguien con la llave privada firmó. Si la llave es exclusiva del firmante (no compartida, no robada), eso es no-repudio. La parte legal/operacional (custodia de llaves, timestamping autoritativo) es responsabilidad del despliegue. |
| **Compromiso de memoria del proceso** | Si el atacante lee la RAM del proceso de Alice mientras firma, obtiene la llave privada. Es ADV-6 fuera del threat model. |

---

## 8. Tests

`tests/test_d4_hybrid_signed.py` cubre los 7 escenarios obligatorios del rubric más 21 tests adicionales de defensa en profundidad, totalizando **28 tests**:

| # | Escenario | Resultado esperado |
|---|---|---|
| 1 | Firma válida → archivo aceptado | `secure_verify_and_decrypt` retorna plaintext idéntico |
| 2 | Ciphertext modificado → rechazado | `InvalidSignature` |
| 3a | Filename modificado | `InvalidSignature` |
| 3b | Timestamp modificado | `InvalidSignature` |
| 3c | Algo_id modificado | `InvalidSignature` |
| 4a | Lista destinatarios modificada (fingerprint) | `InvalidSignature` |
| 4b | RECIPIENT_COUNT modificado | `InvalidSignature` |
| 4c | EPH_PUB de un destinatario modificado | `InvalidSignature` |
| 5 | Llave pública incorrecta | `InvalidSignature` |
| 6 | Firma eliminada (footer truncado) | `ValueError` |
| 7 | Re-firmado por Eve haciendo pasar por Alice | `InvalidSignature` (fingerprint distinto) |

Adicionales (defensa en profundidad):
- ChaCha20-Poly1305 con firma → roundtrip OK
- Archivo de 1 MB con firma → roundtrip OK
- Determinismo de firmas Ed25519 verificado
- Overhead exacto de 100 bytes confirmado
- Separación capa firma / capa autorización (no-destinatario con firma válida)
- Orden correcto verify-first verificado por test
- Múltiples destinatarios — Carol y Bob descifran independientemente

Ejecutar:
```bash
pytest tests/test_d4_hybrid_signed.py -v
```

---

## 9. Resumen de garantías de SDDV completo (D2 + D3 + D4)

| Garantía | D2 | D3 | D4 |
|---|---|---|---|
| Confidencialidad | ✅ AES-256-GCM / ChaCha20-Poly1305 | ✅ con file_key envuelta por destinatario | — |
| Integridad del ciphertext | ✅ tag AEAD 128-bit | ✅ tag AEAD 128-bit | ✅ + firma Ed25519 |
| Integridad de los metadatos | ✅ vía AAD | ✅ vía AAD (incluye recipients) | ✅ + firma cubre todo |
| Compartición multi-destinatario | — | ✅ X25519 ECDH + HKDF | ✅ + autenticidad del firmante |
| Autenticación de origen | — | — | ✅ Ed25519 |
| Detección de re-empaquetado | — | — | ✅ por binding de fingerprint |
| No-repudio criptográfico | — | — | ✅ EUF-CMA |

Después de D4, un destinatario que recibe un archivo SDDV puede afirmar:
> *"Este archivo fue firmado por la persona cuya llave pública Ed25519 produce el fingerprint X, y no ha sido modificado en ningún byte desde que se firmó."*
