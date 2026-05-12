# D6 — Key Management Design

Documento principal de la entrega D6 del SDDV. Cubre el diseño, el
formato del keystore en disco, el ciclo de vida de las identidades,
backup y recuperación, y la alineación con el modelo de amenazas D1.

---

## 1. Objetivos y alcance

El módulo D6 amplia el SDDV para que las llaves privadas necesarias
en D3 (X25519 — cifrado híbrido) y D5 (Ed25519 — firma digital):

1. **Nunca se almacenen en texto plano**: viven solo en memoria
   durante la operación que las usa, y en disco quedan cifradas con
   una clave derivada del password del usuario.
2. **Se accedan solo con el password correcto** (no se cachean entre
   llamadas; cada uso vuelve a derivar la clave con scrypt).
3. **Tengan un formato estructurado y documentado**: campos visibles
   `encrypted_private_key`, `salt`, `kdf_parameters`, `metadata`.
4. **Soporten todo el ciclo de vida**: creación, uso, cambio de
   password, rotación, revocación, expiración opcional y borrado.
5. **Puedan respaldarse y restaurarse** con un password independiente
   del operativo.
6. **Estén alineadas con el modelo de amenazas D1**: para cada
   adversario, qué protege D6 y qué no.

Fuera del alcance (asunciones explícitas, ver sección 7):

- Distribución / publicación de llaves públicas (no hay PKI).
- Protección frente a malware en ejecución (keylogger, RAM dump).
- Recuperación si se olvida el password operativo Y se pierde el
  backup (criptografía no permite "reset"; ver §5).

---

## 2. Diseño criptográfico

### 2.1 KDF — scrypt (RFC 7914)

La clave que protege el bundle privado se deriva del password con
`hashlib.scrypt` (built-in en Python). Parámetros por defecto:

| Parámetro | Valor | Notas |
|---|---|---|
| `n` | `2**15` = 32 768 | Factor de costo (tiempo / memoria) |
| `r` | `8`              | Tamaño de bloque |
| `p` | `1`              | Paralelismo |
| `dklen` | `32`         | 256 bits para AES-256-GCM |
| `salt` | 16 bytes CSPRNG | Fresco por identidad y por cambio de password |

Coste por intento ≈ 80 MiB de RAM y ~150 ms en una laptop. Esto
destruye la economía de un ataque offline con GPU/ASIC: el atacante
paga memoria, no solo CPU.

**Por qué scrypt y no PBKDF2:** PBKDF2 gasta solo CPU y se paraleliza
trivialmente. scrypt agrega un costo de memoria que penaliza el
hardware dedicado.

**Por qué scrypt y no Argon2:** Argon2id es mejor en lo abstracto, pero
exige una dependencia externa (`argon2-cffi`). Para este proyecto
académico priorizamos no agregar dependencias. La migración a Argon2id
es un upgrade documentado para una v2 del formato (sección 8).

### 2.2 Cifrado del envelope — AES-256-GCM

El bundle de llaves privadas se cifra con AES-256-GCM:

- Clave: los 32 bytes que scrypt deriva.
- Nonce: 12 bytes fresco por cada cifrado.
- Tag: 16 bytes (autenticación).
- AAD: no se usa (no hace falta: una manipulación de los campos
  públicos del JSON cambia el salt, los parámetros o el nonce, y
  cualquiera de esos cambios produce `InvalidTag` al descifrar).

### 2.3 Material clave por identidad

Cada identidad guarda **dos pares**:

- **Ed25519** — para firma digital (D5).
- **X25519**  — para cifrado híbrido (D3).

Esto cierra un gap del estado previo del proyecto: antes de D6 la
X25519 del destinatario vivía solo en memoria durante el demo. Ahora
cada destinatario tiene su X25519 persistida y protegida con el
mismo password que su Ed25519.

---

## 3. Formato del keystore en disco

Cada identidad es un archivo JSON: `keystore/<name>.json`.

```jsonc
{
  "version": 1,
  "name": "alice",
  "created_at": "2026-05-12T18:00:00Z",
  "status": "active",                  // active | rotated | revoked

  "kdf": {
    "algorithm": "scrypt",
    "salt_b64":  "<16 bytes base64>",
    "n": 32768, "r": 8, "p": 1, "dklen": 32
  },

  "encryption": {
    "algorithm": "AES-256-GCM",
    "nonce_b64": "<12 bytes base64>",
    "tag_b64":   "<16 bytes base64>"
  },

  "encrypted_private_key": "<base64>",   // bundle{ed25519+x25519} cifrado

  "public_keys": {
    "ed25519_pub_b64": "<32 bytes base64>",
    "x25519_pub_b64":  "<32 bytes base64>"
  },

  "fingerprints": {
    "ed25519": "<sha256 hex 64>",
    "x25519":  "<sha256 hex 64>"
  },

  "metadata": {
    "comment":      "alice@unam.mx",
    "expires_at":   null,                // ISO8601 UTC o null
    "rotated_from": null                 // fingerprint Ed25519 anterior
  }
}
```

Mapeo a la rúbrica D6:

| Requisito rúbrica | Campo JSON |
|---|---|
| `encrypted_private_key` | `encrypted_private_key` |
| `salt` | `kdf.salt_b64` |
| `kdf_parameters` | `kdf.{algorithm,n,r,p,dklen}` |
| `metadata` | bloque `metadata` + `created_at` + `fingerprints` |

Archivos auxiliares en el mismo directorio:

- `<name>.rotated-<timestamp>.json` — versiones archivadas tras `rotate_keys`.
- `<name>.json.tmp` — temporal de escritura atómica (`tmp → rename`).

Los archivos `.rotated-*` se mantienen para auditoría (verificar
firmas históricas) pero no aparecen en `list_identities`.

---

## 4. Ciclo de vida

| Operación | Método | Efecto |
|---|---|---|
| Generación | `KeyStore.init_identity(name, password)` | Crea `<name>.json` |
| Uso (firma) | `KeyStore.unlock_signing_key(name, password)` | Devuelve `Ed25519PrivateKey` recién descifrada (sin cache) |
| Uso (cifrado) | `KeyStore.unlock_encryption_key(name, password)` | Devuelve `X25519PrivateKey` recién descifrada |
| Cambio de password | `KeyStore.change_password(name, old, new)` | Re-cifra con nuevo salt+nonce; mismas llaves |
| Rotación | `KeyStore.rotate_keys(name, password)` | Genera nuevas; archiva la anterior; encadena `rotated_from` |
| Revocación | `KeyStore.revoke(name, reason)` | `status='revoked'`; bloquea `unlock_*`; `get_public_keys` sigue accesible |
| Expiración | `metadata.expires_at` (ISO8601) | `unlock_*` lanza `IdentityExpiredError` tras la fecha |
| Borrado | `KeyStore.delete(name, password)` | Exige password como prueba de autoría |

### 4.1 Política de "no caching"

`unlock_signing_key` y `unlock_encryption_key` **no mantienen estado**:
cada llamada vuelve a leer el JSON, vuelve a derivar la clave con
scrypt y vuelve a descifrar. Los objetos retornados viven en el
frame del llamador; cuando la función retorna, las referencias se
sueltan y el GC eventualmente recolecta los bytes.

Esto tiene un coste deliberado (~150 ms por llamada) que actúa como
desincentivo para que el código cliente acumule operaciones bajo
una sola lectura. Si una app necesita firmar muchas cosas, debe
guardar la `Ed25519PrivateKey` en una variable local y reutilizarla
mientras dure su scope — pero nunca en memoria global ni en disco.

### 4.2 Respuesta a compromiso de clave

Si una llave privada se filtra:

1. `KeyStore.revoke(name, reason="key compromise")` — marca el JSON
   como revocado para que `unlock_*` se niegue.
2. `KeyStore.rotate_keys(name, password)` — genera un par nuevo y
   archiva el viejo en `<name>.rotated-<ts>.json`. La pública nueva
   debe redistribuirse a los contrapartes por canal seguro.
3. Documentar el evento en `metadata.comment` (incluido automática-
   mente por `revoke(..., reason=...)`).

Limitación: si un atacante ya tiene la pública vieja en otro
contexto, las firmas pre-rotación siguen verificándose contra ella.
SDDV no implementa CRL/OCSP; la revocación es local al keystore. Para
revocación distribuida se necesitaría una capa adicional (p.ej.
publicar la nueva pub con timestamp y un flag de "supersede").

---

## 5. Backup y recuperación

### 5.1 Diseño

Un archivo `.sddv_backup` es un JSON con el mismo esquema del keystore
más dos campos: `backup_of` y `backup_at`. La diferencia clave es que
se **re-cifra con un password de backup INDEPENDIENTE del operativo**.

```text
keystore activo  --- export_backup(active_pwd, backup_pwd) --->  .sddv_backup
.sddv_backup    --- import_backup(backup_pwd, new_pwd)     --->  keystore activo
```

### 5.2 Por qué re-cifrar y no solo copiar el JSON

Si simplemente copiáramos `alice.json` a `alice.sddv_backup`, un
atacante con acceso al backup podría correr fuerza bruta offline con
el **mismo** password operativo. Re-cifrar separa los secretos:

- Para descifrar el activo se necesita el password operativo.
- Para descifrar el backup se necesita el password de backup.
- Romper uno NO da pistas sobre el otro (scrypt con salt fresco).

### 5.3 Flujo de import_backup

1. Lee el JSON, valida que tenga `backup_of`.
2. Descifra el bundle con `backup_password` (`unlock_keystore_dict`).
3. Genera salt y nonce frescos.
4. Deriva clave con `new_active_password`.
5. Re-cifra el bundle con esa clave.
6. Persiste como `<name>.json`.

El `name` puede sobreescribirse al restaurar (parámetro `--name` de la
CLI), útil para tener "alice" activa y "alice_backup" coexistiendo.

### 5.4 Limitaciones

- Si se olvida el password de backup Y el operativo, la identidad
  queda inutilizable. SDDV no implementa "reset por email" porque
  rompería el modelo de amenazas (cualquier mecanismo de recuperación
  sin password es un mecanismo de bypass para un atacante).
- El backup hereda los parámetros KDF del keystore que lo originó. Si
  el operativo usaba scrypt rápido (tests), el backup también; si
  usaba defaults de producción, también.

---

## 6. Alineación con el modelo de amenazas (D1)

Ver `docs/D1_Threat_Model.md` §6 para el detalle. Resumen:

### 6.1 ADV-1 / ADV-4 — Robo del keystore

**Capacidad del atacante:** copia `keystore/alice.json` completo.

**Qué pasa:** el atacante obtiene los campos `salt`, `n,r,p,dklen`,
`nonce`, `tag` y el `encrypted_private_key`. Para recuperar la
privada debe encontrar el password que, al pasarlo por scrypt con
ese salt, produce una clave de 32 bytes que descifra el envelope
sin que AES-GCM detecte manipulación.

**Coste del ataque:** scrypt con (n=2¹⁵, r=8) cuesta ≈ 80 MiB de RAM
y ~150 ms por intento. Con un password de 64 bits de entropía
(passphrase de 5 palabras de un diccionario de 8192 = log2(8192⁵) ≈
65 bits), un atacante con 1000 GPUs equivalentes a una laptop
necesita en promedio:
- 2⁶⁴ / 2 = 2⁶³ intentos
- 2⁶³ × 150 ms / 1000 = ~1.4 × 10¹⁹ s (mucho más que la edad del universo).

**Conclusión:** robar el keystore no rompe la confidencialidad
**siempre que el password sea fuerte** (>= 12 chars, no diccionario).

### 6.2 Password débil

**Capacidad del atacante:** sabe que el usuario eligió un password
del top-100k de RockYou o variantes triviales.

**Qué pasa:** 100 000 candidatos × 150 ms = 4 horas en una laptop.
Si tiene 100 GPUs, son ~2 minutos. La protección del scrypt no
compensa un password trivial.

**Mitigación implementada:**
- `validate_password_strength` rechaza < 12 caracteres y un solo
  carácter repetido (`MIN_PASSWORD_LENGTH = 12`).
- La documentación recomienda passphrases de 4+ palabras (Diceware).

**Mitigación NO implementada:** chequeo contra diccionarios de
passwords filtrados (HaveIBeenPwned API). Es una decisión: agregar
una API externa cambia el modelo de privacidad.

### 6.3 ADV-6 — Dispositivo comprometido

**Capacidad del atacante:** corre código con los mismos privilegios
que el usuario (malware, keylogger, RAM dump).

**Qué NO protege D6:**
- Un keylogger captura el password mientras se teclea.
- Un RAM dump lee las privadas en el momento del unlock.
- Un proceso con `ptrace`/Debug Privilege lee el espacio de memoria
  del proceso SDDV.

**Conclusión explícita:** D6 NO defiende contra ADV-6. Esto está
declarado en `D1_Threat_Model.md` §3 y se documenta como asunción.
Mitigaciones que harían falta (fuera de scope):
- Hardware security modules (HSM) o YubiKey para almacenar las
  privadas en hardware tamper-resistant.
- Zeroización de memoria (`memwipe`).
- Aislamiento del proceso (sandboxing, SELinux, AppArmor).

### 6.4 Pérdida del password

**Escenario:** el usuario olvida el password operativo.

**Mitigación implementada:** backup con password independiente. Si
el usuario tiene el backup y recuerda el password del backup, puede
restaurar (ver §5).

**Si pierde ambos:** la identidad es irrecuperable. Esto es una
propiedad criptográfica, no un bug.

---

## 7. Supuestos y limitaciones explícitas

D6 asume:

1. **El usuario protege su password.** No lo anota en plaintext, no
   lo reutiliza con otros servicios, no lo comparte por canales
   inseguros.
2. **El usuario protege el backup.** Idealmente almacenado en un
   medio distinto (USB físico, gestor de contraseñas, papel en
   caja fuerte) — no junto al keystore operativo.
3. **El sistema operativo provee un CSPRNG seguro** (`os.urandom` →
   `/dev/urandom` en Linux/macOS, `BCryptGenRandom` en Windows).
4. **La librería `cryptography` es correcta** (>= 41.0.0).
5. **No hay malware ejecutándose con privilegios del usuario.**

D6 NO provee:

- Distribución autenticada de llaves públicas (no hay PKI).
- Revocación distribuida (CRL/OCSP).
- Protección contra ataques físicos (cold boot, side-channel
  por electromagnetismo).
- Recuperación si se olvidan ambos passwords (operativo y backup).
- Sincronización entre dispositivos.

---

## 8. Roadmap (no entrega actual)

- **v2 del formato JSON**: añadir `version: 2` con KDF Argon2id
  (parametrizado), manteniendo retro-compatibilidad con v1 al leer.
- **Hardware tokens**: backend alternativo `KeyStoreHSM` que delegue
  el unlock a un YubiKey OpenPGP.
- **CRL local**: archivo `revoked.json` con fingerprints revocados
  conocidos, consultado por `verify_*` antes de aceptar firmas.

---

## 9. Tests requeridos por la rúbrica

| Requisito | Archivo de test |
|---|---|
| Correct password → access granted | `tests/test_keystore_security.py::test_correct_password_grants_access` |
| Wrong password → access denied | `tests/test_keystore_security.py::test_wrong_password_denies_access` (parametrizado) |
| Modified keystore → failure | `tests/test_keystore_security.py::test_modified_keystore_*` (parametrizado por campo) |
| Backup → restore works | `tests/test_keystore_security.py::test_backup_export_y_import_roundtrip` |
| Stolen keystore alone → cannot decrypt | `tests/test_keystore_security.py::test_stolen_keystore_sin_password_no_puede_descifrar` |

Tests adicionales del módulo D6:

- `tests/test_kdf.py` (24): determinismo, salts únicos, validación
  de parámetros.
- `tests/test_keystore_format.py` (33): envelope AEAD, esquema JSON
  v1, manipulación campo-por-campo.
- `tests/test_keystore.py` (37): creación, persistencia, unlocks,
  listado.
- `tests/test_keystore_lifecycle.py` (21): change_password,
  rotate_keys, revoke, expiración, delete, integración con D5.
- `tests/test_keystore_security.py` (20): los 5 tests rúbrica +
  variaciones.

Total D6: **135 tests nuevos**.

Total suite proyecto: **300 passed**.

---

## 10. Cómo usar

### 10.1 Vía CLI

```bash
# Crear identidad (pide password con getpass, con confirmación)
python -m crypto init alice

# Listar
python -m crypto list

# Ver fingerprints
python -m crypto fingerprint alice

# Cambiar password
python -m crypto change-password alice

# Rotar llaves
python -m crypto rotate alice

# Revocar
python -m crypto revoke alice --reason "key compromise"

# Backup
python -m crypto backup alice ./backups/alice.sddv_backup

# Restore
python -m crypto restore ./backups/alice.sddv_backup --name alice_restored

# Borrar (pide password)
python -m crypto delete alice
```

Todos los subcomandos aceptan `--keystore DIR` (default: `keystore`).

### 10.2 Vía API Python

```python
from crypto.keystore import KeyStore
from crypto.secure_send import (
    encrypt_and_sign_from_keystore,
    verify_and_decrypt_from_keystore,
)

ks = KeyStore("keystore")
ks.init_identity("alice", "passwordSuperFuerte_2026!")
ks.init_identity("bob",   "otroPasswordIgualDeFuerte_2026!")

bob_pub = ks.get_public_keys("bob")["x25519_pub"]
container = encrypt_and_sign_from_keystore(
    ks, "alice", "passwordSuperFuerte_2026!",
    plaintext=b"hola Bob",
    filename="msg.txt",
    recipients_x25519=[bob_pub],
)

alice_pub = ks.get_public_keys("alice")["ed25519_pub"]
plaintext, meta = verify_and_decrypt_from_keystore(
    ks, "bob", "otroPasswordIgualDeFuerte_2026!",
    signed_container=container,
    expected_signer_pub=alice_pub,
)
```

### 10.3 Demo paso a paso

```bash
python demo_d6.py
```

Recorre el ciclo de vida completo: crear identidades, inspeccionar el
JSON, fallar con password incorrecto, firmar+cifrar+descifrar, rotar
llaves y backup→restore.
