# D6 — Key Management Design

> Documento principal de la entrega D6. El alcance, las decisiones y
> el formato del keystore se describen aqui. Las secciones marcadas
> con *(Fase N)* se completan al cierre de cada fase del plan D6.

---

## 1. Objetivos

El sistema D6 amplia el SDDV para:

1. **Proteger las llaves privadas** (Ed25519 de firma + X25519 de
   cifrado) en disco con un KDF explicito y un AEAD autenticado.
2. **Pedir el password en cada uso** (no cachear llaves
   descifradas en memoria mas alla de la operacion).
3. **Definir un formato estructurado** del keystore con campos
   visibles: `encrypted_private_key`, `salt`, `kdf_parameters`,
   `metadata`.
4. **Soportar el ciclo de vida**: generacion, uso, rotacion,
   cambio de password, revocacion, expiracion (opcional), borrado.
5. **Permitir backup y recuperacion** de identidades.
6. **Alinear con el modelo de amenazas** D1: identificar que
   protege el sistema y que NO.

---

## 2. Diseño criptografico *(Fase 1)*

### 2.1 KDF

*Decision pendiente de Fase 1.* Recomendado: **scrypt** (`hashlib.scrypt`,
built-in) con parametros OWASP 2025: `N=2**15, r=8, p=1, dklen=32`.

### 2.2 Cifrado del envelope

AES-256-GCM sobre el bundle serializado de llaves privadas. Salt y
nonce frescos por identidad y por cambio de password.

### 2.3 Material clave por identidad

Cada identidad guarda dos pares:

- **Ed25519** — firma D5.
- **X25519**  — cifrado hibrido D3.

Esto cierra el gap actual: hoy las X25519 solo viven en memoria
durante el demo. Con D6 cada destinatario tiene su X25519 persistida
y protegida con el mismo password.

---

## 3. Formato del keystore *(Fase 1)*

Un archivo JSON por identidad: `keystore/<name>.json`.

```jsonc
{
  "version": 1,
  "name": "alice",
  "created_at": "2026-05-12T18:00:00Z",
  "status": "active",                  // active | rotated | revoked
  "kdf": {
    "algorithm": "scrypt",
    "salt_b64": "...",                 // 16 bytes random
    "n": 32768, "r": 8, "p": 1,
    "dklen": 32
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "nonce_b64": "...",
    "tag_b64": "..."
  },
  "encrypted_private_key": "...",      // base64: bundle(ed25519+x25519) cifrado
  "public_keys": {
    "ed25519_pub_b64": "...",
    "x25519_pub_b64":  "..."
  },
  "fingerprints": {
    "ed25519": "sha256-hex-64-chars",
    "x25519":  "sha256-hex-64-chars"
  },
  "metadata": {
    "comment": "",
    "expires_at": null,
    "rotated_from": null
  }
}
```

Mapeo a la rubrica:

| Requisito de la rubrica | Campo del JSON |
|---|---|
| `encrypted_private_key` | `encrypted_private_key` |
| `salt` | `kdf.salt_b64` |
| `kdf_parameters` | `kdf.{algorithm,n,r,p,dklen}` |
| `metadata` | bloque `metadata` + `created_at` + `fingerprints` |

---

## 4. Ciclo de vida *(Fase 2)*

| Operacion | Metodo | Efecto |
|---|---|---|
| Generacion | `KeyStore.init_identity(name, password)` | Crea `<name>.json` |
| Uso (firma) | `KeyStore.unlock_signing_key(name, password)` | Devuelve `Ed25519PrivateKey` recien descifrada |
| Uso (cifrado) | `KeyStore.unlock_encryption_key(name, password)` | Devuelve `X25519PrivateKey` recien descifrada |
| Cambio de password | `KeyStore.change_password(name, old, new)` | Re-cifra con nuevo salt y nuevo nonce |
| Rotacion | `KeyStore.rotate_keys(name, password)` | Nueva identidad; la anterior queda en `<name>.rotated-<ts>.json` |
| Revocacion | `KeyStore.revoke(name, reason)` | `status = "revoked"`; bloquea unlocks |
| Borrado | `KeyStore.delete(name, password)` | Borra el JSON tras confirmar el password |

---

## 5. Backup y recuperacion *(Fase 3)*

Un backup es un `.sddv_backup` con el mismo esquema JSON pero
re-cifrado con un **password de backup independiente** (puede
diferir del activo). Esto permite custodiar el backup en otro
medio sin compartir el password operativo.

---

## 6. Alineacion con el modelo de amenazas (D1) *(Fase 3)*

Se ampliara con el analisis de:

- **Stolen keystore**: cuantos intentos cuesta romper el cifrado
  asumiendo un password de N bits de entropia.
- **Weak password**: por que el `MIN_PASSWORD_LENGTH=12` mas scrypt
  eleva el costo de ataque offline.
- **Compromised device**: que NO protege D6 (keylogger, RAM dump,
  malware con root).

---

## 7. Limitaciones explicitas *(Fase 3)*

A completar.

---

## 8. Tests requeridos por la rubrica *(Fase 2 / Fase 3)*

| Requisito | Test |
|---|---|
| Correct password → access granted | `test_correct_password_grants_access` |
| Wrong password → access denied | `test_wrong_password_denies_access` |
| Modified keystore → failure | `test_modified_keystore_*` (parametrizado) |
| Backup → restore works | `test_backup_export_y_import_roundtrip` |
| Stolen keystore alone → cannot decrypt | `test_stolen_keystore_sin_password_no_puede_descifrar` |

---

## 9. Como usar *(Fase 2 / Fase 3)*

Una vez completada la Fase 2:

```bash
# Crear identidad
python -m crypto init alice

# Listar
python -m crypto list

# Cambiar password
python -m crypto change-password alice

# Rotar llaves
python -m crypto rotate alice

# Backup / restore
python -m crypto backup  alice alice.sddv_backup
python -m crypto restore alice.sddv_backup
```
