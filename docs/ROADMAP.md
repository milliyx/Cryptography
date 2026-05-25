# Roadmap · Mejoras pendientes

Este documento es la lista honesta de lo que conscientemente **no se
implementó** en esta entrega del proyecto SDDV. Cada ítem incluye su
contexto, por qué quedó fuera, qué pasaría si se implementara, y el
esfuerzo estimado.

Se mantiene aquí porque parte de la madurez de un proyecto académico de
seguridad consiste en reconocer sus limitaciones explícitamente, no en
ocultarlas.

---

## Backend criptográfico

### 1. Migración a Argon2id como KDF

**Estado:** scrypt (RFC 7914) sigue siendo aceptable según OWASP 2024,
pero Argon2id es el ganador del Password Hashing Competition y la
recomendación principal hoy.

**Por qué quedó fuera:** agregar `argon2-cffi` como dependencia
externa rompe el principio "solo stdlib + cryptography" del proyecto.
La profe priorizó scrypt en `commit 4ea9182`.

**Cómo se haría:** crear `crypto/kdf.py` con `derive_argon2id()` como
opción alterna; agregar `version: 2` al keystore JSON con campo
`kdf.algorithm: "argon2id"`; el código de lectura detecta versión y
elige el KDF correspondiente.

**Esfuerzo:** 4-6 h.

### 2. Zeroización explícita de memoria

**Estado:** las llaves privadas viven en memoria del frame del caller
durante una operación; después dependen del GC de Python para ser
limpiadas.

**Por qué quedó fuera:** Python no expone `mlock`/`memset_s` de forma
nativa. Soluciones como `secret-buffer` requieren C extensions o
trucos con `ctypes`. La ganancia real frente a un atacante con RAM
dump es marginal (`ADV-6` ya está fuera de scope).

**Cómo se haría:** wrapper `SecureBytes` con `ctypes` que llene la
región con `0xFF` al destruirse. Aplicar en `unlock_*` y en el `dk`
de `kdf.py`.

**Esfuerzo:** 3-4 h + testing.

### 3. Hardware Security Module / YubiKey backend

**Estado:** `KeyStore` solo soporta backend de archivos. No hay
abstracción para HSM/YubiKey.

**Por qué quedó fuera:** complejidad alta + requiere hardware físico
para testing. Cae fuera del scope académico.

**Esfuerzo:** ~15-20 h.

### 4. Revocación distribuida (CRL local)

**Estado:** `revoke()` marca la identidad como revocada localmente,
pero las firmas hechas por esa llave antes del `revoke` siguen siendo
verificables contra ella si alguien tiene la pubkey en otro contexto.

**Por qué quedó fuera:** requiere distribución coordinada de un
archivo `revoked.json` con timestamps; se acerca a una PKI mínima.

**Cómo se haría:** archivo `revoked.json` con lista de fingerprints +
timestamp + razón; los `verify_*` consultarían antes de aceptar firmas.

**Esfuerzo:** 4-6 h.

---

## Frontend web

### 5. Web Worker para scrypt

**Estado:** scrypt corre en el main thread → bloquea la UI ~0.5-1.5 s
por operación (`init_identity`, `encrypt_and_sign`, `verify_and_decrypt`,
`delete`, `backup_export`).

**Por qué quedó fuera:** Pyodide en Web Worker cambia drásticamente la
arquitectura del bridge JS↔Python (los handlers serían async messages
en vez de llamadas directas). Riesgo alto antes de la presentación
final.

**Cómo se haría:** crear `pyodide-worker.js` que carga Pyodide en
worker thread; reemplazar `callPy()` por `postMessage` con request ID;
el worker responde con el resultado serializado.

**Esfuerzo:** 6-10 h + testing extenso.

### 6. SRI también para el wheel de cryptography

**Estado:** el script de Pyodide (`pyodide.js`) tiene `integrity=`
desde esta entrega, pero el wheel de `cryptography` se descarga
dinámicamente por `loadPackage()` sin verificación de hash.

**Por qué quedó fuera:** Pyodide gestiona sus paquetes internamente
sin exponer hooks de verificación. Requiere monkey-patch del fetch.

**Cómo se haría:** wrapper sobre `pyodide.loadPackage` que descargue
manualmente el wheel, verifique SHA-384, y luego instale.

**Esfuerzo:** 3-4 h.

### 7. Tests automatizados del frontend

**Estado:** cero tests. La compatibilidad CLI ↔ web es "por
construcción" (mismo `.py`), no probada.

**Por qué quedó fuera:** prioridad media; las 300 tests del backend
cubren la lógica criptográfica, y la capa de bridge es delgada.

**Cómo se haría:**
- **Tests de interop** (`tests/test_web_interop.py`): cifrar con
  `sddv_api.encrypt_and_sign`, descifrar con CLI; e inverso.
- **Tests e2e** con Playwright: crear identidad → cifrar → descifrar
  → verificar fingerprint preservado.

**Esfuerzo:** 4-6 h.

### 8. Address book / contactos

**Estado:** compartir un fingerprint X25519 requiere copy-paste manual
de 64 hex. No hay UI para gestionar contactos.

**Por qué quedó fuera:** no es core de la rúbrica D6; el rubric solo
exige cifrar/descifrar/firmar/verificar.

**Cómo se haría:** nueva pestaña "Contactos" con UI para alias →
fingerprint; integración con `<select>` en pestaña Cifrar.

**Esfuerzo:** 3-4 h.

### 9. Aviso para iOS Safari

**Estado:** iOS Safari puede agotar memoria por pestaña al cargar
Pyodide; existe rama `feature/ios-warning` (commit `2bc9c6c`) con un
aviso amigable, **no mergeada** a `main`.

**Por qué quedó fuera:** simple olvido / pendiente de revisión.

**Cómo se haría:** `git merge feature/ios-warning`.

**Esfuerzo:** 5 min + verificación.

### 10. Sincronización entre dispositivos

**Estado:** IndexedDB es local al navegador y al perfil. Pasar de
laptop a celular requiere export/import manual del backup.

**Por qué quedó fuera:** exige backend (rompería el principio
zero-server) o un protocolo P2P (complejidad alta).

**Esfuerzo:** ~20+ h.

---

## CI / DevOps

### 11. Auditoría automática en CI

**Estado:** la auditoría de tampering (`audit_tampering.py`) se corre
manualmente. Los 7 VULN-* fix tests están en `test_security_patches.py`
y sí corren en cada PR.

**Por qué quedó fuera:** medio implementado (los tests de regresión
cubren los fixes); falta correr `audit_tampering.py` como un step
formal del workflow.

**Cómo se haría:** agregar step a `.github/workflows/ci.yml` (todavía
no existe) que ejecute `python audit_tampering.py` y falle si
detecta una clase de manipulación no rechazada.

**Esfuerzo:** 2-3 h (incluye crear `ci.yml`).

### 12. Property-based testing con Hypothesis

**Estado:** los tests son ejemplo-based. Cobertura decente pero
podría mejorarse con `hypothesis` para fuzzing de tampering.

**Por qué quedó fuera:** dependencia adicional + curva de aprendizaje.

**Esfuerzo:** 4-6 h.

---

## Notas para la defensa de la presentación

Si la profe pregunta "¿por qué no implementaron X?", la respuesta
ideal es:

1. **Reconocer que es una mejora válida.**
2. **Explicar el trade-off concreto** (esfuerzo vs valor, scope vs
   tiempo, complejidad vs claridad pedagógica).
3. **Mostrar que está documentado** apuntando a este archivo.

Eso convierte un hueco potencial en evidencia de madurez técnica.

---

## Acciones de bajo costo / alto impacto si hay 1 hora extra

1. Mergear `feature/ios-warning` → main (5 min).
2. Agregar SRI al wheel de cryptography (3-4 h, alto valor de seguridad).
3. Test de interop CLI ↔ web (~2 h, cierra defensa "¿cómo saben que funciona?").
