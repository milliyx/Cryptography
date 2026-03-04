# D2 — Diseño del Módulo de Cifrado

**Bóveda Digital Segura de Documentos (SDDV)**

| | |
|---|---|
| **Equipo** | Barrios Aguilar Dulce Michelle · Contreras Colmenero Emilio Sebastian · Martínez López Evan Emiliano · Pulido Vázquez Rodrigo |
| **Curso** | Criptografía — Semestre 2026-2 — Dra. Rocío Aldeco Pérez |
| **Fecha** | Marzo 2026 |

---

## Objetivo del módulo

Este módulo implementa la capa de cifrado del núcleo criptográfico del SDDV para el caso de uso de **un solo dueño** (sin compartir todavía). La meta de seguridad es directa: un atacante que obtenga el archivo cifrado no debe poder leer ni modificar su contenido sin que eso se detecte.

---

## 1. Algoritmo AEAD seleccionado

El módulo usa **AES-256-GCM** como algoritmo principal, con **ChaCha20-Poly1305** como alternativa. Ambos son esquemas **AEAD** (*Authenticated Encryption with Associated Data*): en una sola operación protegen la confidencialidad del contenido *y* autentican tanto el ciphertext como los metadatos asociados (el AAD).

### Por qué AES-256-GCM

AES-GCM es el modo autenticado más adoptado en la industria (TLS 1.3, SSH, IPsec, FileVault, BitLocker). Su seguridad está analizada exhaustivamente por NIST en SP 800-38D. La clave de 256 bits da un nivel de seguridad de 128 bits contra búsqueda exhaustiva, que es el mínimo que nos impusimos en el D1 (requisito RS-1). Además, los procesadores modernos tienen la instrucción **AES-NI** que lo hace extremadamente rápido en hardware.

Implementamos usando la librería `cryptography` de pyca, que delega a OpenSSL internamente. No tocamos las primitivas de bajo nivel directamente; eso reduce la superficie de error humano.

### Por qué también ChaCha20-Poly1305

Está incluido para dispositivos sin AES-NI (algunos ARM, microcontroladores). ChaCha20-Poly1305 no depende de hardware especial y es el algoritmo preferido en WireGuard y Signal. La clave siempre es de 256 bits. Para el SDDV, ambos son intercambiables en seguridad; la elección es de rendimiento y plataforma.

---

## 2. Tamaño de clave

Usamos **256 bits (32 bytes)** para los dos algoritmos.

- **AES-256-GCM**: 256 bits de clave. AES tiene variantes de 128 y 192, pero elegimos 256 porque los documentos protegidos por la bóveda pueden necesitar confidencialidad a largo plazo (contratos, expedientes médicos), y el costo computacional adicional de AES-256 frente a AES-128 es marginal.
- **ChaCha20-Poly1305**: La especificación RFC 8439 fija la clave en 256 bits. No hay otra opción.

La clave se genera con `os.urandom(32)`, que usa el CSPRNG del kernel:

- Linux/macOS → `/dev/urandom` (entropía del kernel)
- Windows → `BCryptGenRandom`

Está **prohibido** usar `random.random()`, `numpy.random`, o cualquier PRNG que no sea el del sistema operativo.

---

## 3. Estrategia de nonce

El nonce (IV) tiene **96 bits (12 bytes)** y se genera con `os.urandom(12)` en cada operación de cifrado, sin excepción. El nonce se almacena en texto claro dentro del contenedor; no necesita ser secreto, sólo único.

### Por qué 96 bits

NIST SP 800-38D especifica que con nonces de exactamente 96 bits, la construcción de GCM tiene el análisis de seguridad más robusto. Con nonces de longitud diferente, el modo internamente aplica GHASH sobre el nonce antes de usarlo, lo que complica el análisis y puede reducir el margen de seguridad efectivo.

### Cómo garantizamos unicidad

Usamos dos capas de defensa:

1. **Nonce aleatorio de 96 bits por cifrado**: La probabilidad de colisión en un millón de archivos cifrados es aproximadamente $2^{-52}$ (límite de cumpleaños sobre $2^{96}$ posibles nonces). Eso es despreciable en la práctica.

2. **Clave efímera distinta por archivo**: Incluso en el improbable caso de colisión de nonces en dos archivos distintos, las claves son diferentes, así que el ataque de reutilización de nonce no aplica.

### Qué pasa si se repite el nonce

La reutilización de nonce bajo la misma clave en AES-GCM es **catastrófica**. Si dos mensajes $P_1$ y $P_2$ se cifran con la misma clave $k$ y el mismo nonce $n$:

- El keystream generado es idéntico: $C_1 = P_1 \oplus KS$ y $C_2 = P_2 \oplus KS$.
- Un atacante que tenga ambos ciphertexts puede calcular $C_1 \oplus C_2 = P_1 \oplus P_2$. Si conoce parte de $P_1$ (por ejemplo, que el archivo empieza con `%PDF-1.`), puede recuperar los bytes correspondientes de $P_2$. **Confidencialidad rota.**

- La clave de autenticación de GCM es $H = \text{AES}_k(0^{128})$. Con dos pares $(C_1, T_1)$ y $(C_2, T_2)$ bajo el mismo $(k, n)$, un atacante puede resolver un sistema de ecuaciones cuadráticas sobre $GF(2^{128})$ y recuperar $H$. Con $H$ puede **forjar tags válidos** para cualquier ciphertext de su elección. **Integridad rota totalmente.**

Este ataque fue formalizado por Joux (2006) y detallado por McGrew y Viega. No es teórico; herramientas como `gcm-siv-nonce-reuse-attack` lo demuestran en la práctica.

---

## 4. Estrategia de autenticación de metadatos

Los metadatos del archivo se pasan como **AAD** a la función de cifrado. La cabecera contiene:

| Campo | Tamaño | Descripción |
|---|---|---|
| `MAGIC` | 4 bytes | `b"SDDV"` — identifica el formato |
| `VERSION` | 1 byte | Versión del formato de serialización |
| `ALGO_ID` | 1 byte | `0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305 |
| `TIMESTAMP` | 8 bytes | Tiempo de creación en segundos Unix (big-endian uint64) |
| `FILENAME_LEN` | 2 bytes | Longitud del nombre de archivo en bytes (big-endian uint16) |
| `FILENAME` | variable | Nombre del archivo en UTF-8 |

La cabecera se almacena en **texto claro** — no necesita cifrarse porque no contiene secretos. Lo que hace el AEAD es **autenticarla**: el tag de 128 bits cubre simultáneamente el ciphertext *y* la cabecera completa. Si alguien modifica cualquier byte de la cabecera (el nombre, el timestamp, la versión, el algoritmo), el tag ya no verifica y el descifrado falla antes de devolver cualquier dato.

Esto corresponde directamente al requisito RS-2 del D1: "Cualquier modificación al contenedor (texto cifrado, metadatos, tag de autenticación) debe detectarse durante el descifrado."

---

## 5. Por qué AEAD en vez de cifrado + hash separado

Una alternativa más ingenua sería cifrar el archivo con AES-CBC o AES-CTR y después calcular un HMAC-SHA256 por separado. Hay varias razones por las que eso es problemático:

### Composición manual es propensa a errores

Hay tres formas de combinar cifrado y MAC:

- **Encrypt-and-MAC**: cifrar y hacer MAC del plaintext por separado. El MAC del plaintext puede filtrar información.
- **MAC-then-Encrypt**: hacer MAC del plaintext, luego cifrar (plaintext + MAC). Vulnerable a ataques de padding oracle en CBC: el servidor distingue si el padding es válido antes de verificar el MAC, y esa distinción es un oráculo explotable (ataques BEAST, Lucky13).
- **Encrypt-then-MAC**: cifrar primero, luego MAC del ciphertext. Es la opción segura, pero **requiere que el MAC cubra también el nonce/IV y los metadatos**. Si se omite el IV del MAC, un atacante puede re-usar el ciphertext con un IV diferente. La historia tiene varios ejemplos de implementaciones que olvidaron incluir el IV en el MAC.

### AEAD resuelve todo esto por diseño

Con AES-GCM, el tag de autenticación cubre el ciphertext y el AAD en una sola operación atómica definida por la especificación. No hay decisiones manuales de composición, no hay forma de "olvidar" incluir algún campo. La verificación del tag ocurre **antes** de que se devuelva cualquier plaintext, lo que impide que el sistema sea usado como oráculo de padding. La especificación garantiza que si el tag verifica, el plaintext es auténtico e íntegro.

Usar cifrado + hash separado requiere tomar decisiones de composición delicadas que históricamente generan vulnerabilidades sutiles. AEAD encapsula esas decisiones de forma correcta y estándar.

---

## 6. Contra qué atacante nos defendemos

En D2 el sistema cifra para un solo dueño, así que el adversario principal es **ADV-1 del D1: atacante externo con acceso al almacenamiento**.

### Capacidades del atacante

- Obtuvo el contenedor cifrado del disco, la nube o en tránsito.
- Puede copiarlo, modificarlo, borrarlo o reenviarlo a donde quiera.
- Conoce el formato del contenedor en detalle (principio de Kerckhoffs).
- Puede hacer fuerza bruta sobre la clave.
- **No tiene la clave simétrica.**

### Qué garantiza este módulo

- **Confidencialidad**: Sin la clave, el ciphertext no revela nada del plaintext salvo su longitud aproximada. AES-256 tiene $2^{256}$ claves posibles; búsqueda exhaustiva es físicamente imposible (el límite de Landauer lo demuestra).

- **Integridad del contenido**: Cualquier modificación al ciphertext invalida el tag de 128 bits con probabilidad $\geq 1 - 2^{-128}$. El atacante no puede producir un ciphertext modificado con tag válido sin conocer la clave.

- **Integridad de metadatos**: El nombre de archivo, la versión del algoritmo y el timestamp van en el AAD y quedan cubiertos por el mismo tag. Un atacante no puede cambiar el nombre de un archivo cifrado y que el destinatario lo acepte como válido.

### Qué NO garantiza (fuera del scope de D2)

- No protege si el atacante tiene acceso a la clave (la gestión segura de la clave es D4, con Argon2id).
- No hay autenticación del remitente (eso es D3 con firmas digitales Ed25519/RSA-PSS).
- Los metadatos en la cabecera (nombre, timestamp) son visibles en texto claro; el módulo los autentica pero no los oculta.

---

## Estructura del contenedor

```
┌────────────────────────────────────────────────────────────┐
│            CABECERA — AAD (texto claro, autenticada)       │
├─────────────────┬──────────────────────────────────────────┤
│  MAGIC          │  4 bytes  — b"SDDV"                      │
│  VERSION        │  1 byte   — versión del formato          │
│  ALGO_ID        │  1 byte   — 0x01=AES-GCM, 0x02=CC20P    │
│  TIMESTAMP      │  8 bytes  — Unix time, big-endian uint64 │
│  FILENAME_LEN   │  2 bytes  — longitud en bytes, uint16    │
│  FILENAME       │  variable — UTF-8                        │
├─────────────────┴──────────────────────────────────────────┤
│                  SECCIÓN CIFRADA                           │
├────────────────────────────────────────────────────────────┤
│  NONCE          │ 12 bytes  — 96 bits CSPRNG (os.urandom)  │
│  CT_LEN         │  4 bytes  — longitud del ciphertext      │
│  CIPHERTEXT     │  variable — datos cifrados               │
│  TAG            │ 16 bytes  — tag de autenticación 128-bit │
└────────────────────────────────────────────────────────────┘
```

El TAG cubre: CIPHERTEXT completo + CABECERA (AAD) completa.
Modificar cualquier byte de cualquier sección invalida el TAG.

---

## Cómo ejecutar los tests

```bash
# Instalar dependencias
pip install cryptography pytest

# Desde la raíz del repositorio
pytest tests/test_aead.py -v
```

Salida esperada: todos los tests en verde. Los tests cubren:

- Cifrar → descifrar devuelve el archivo idéntico (varios tamaños y algoritmos)
- Clave incorrecta falla (incluyendo variaciones de un solo bit)
- Ciphertext modificado falla (primer byte, último byte, tag)
- Metadatos modificados falla (versión, algo, timestamp, filename, magic bytes)
- Múltiples cifrados producen ciphertexts diferentes (mismo plaintext, misma clave)
- Unicidad de nonces en 100 cifrados consecutivos
