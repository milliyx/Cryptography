# D1 — Modelo de Amenazas (Threat Model) del SDDV

> Este documento consolida el modelo de amenazas que hasta ahora vivia
> distribuido entre `README.md`, `docs/D2_Encryption_Design.md` y
> `docs/D5_Signature_Design.md`. Se mantiene aqui como referencia
> unica para las entregas D1–D6.
>
> Estado: documento vivo. Se extiende en D6 con los riesgos especificos
> de la gestion de llaves (seccion 6).

---

## 1. Alcance del sistema

El SDDV es una "boveda digital segura" para documentos. El sistema:

- Cifra archivos (D2 — AEAD simetrico).
- Comparte archivos cifrados con multiples destinatarios (D3 — cifrado
  hibrido X25519 + KEM/DEM).
- Autentica el origen de cada archivo (D5 — firma Ed25519).
- Persiste las llaves privadas de cada identidad cifradas con un
  password (D6 — key management).

Fuera del alcance:

- Distribucion / publicacion de llaves publicas (PKI, web of trust).
- Proteccion contra ataques al sistema en ejecucion (malware,
  keyloggers, dumps de RAM).
- Almacenamiento confiable (se asume hostil; ver ADV-1).

---

## 2. Activos protegidos

| Activo | Sensibilidad | Donde vive | Protegido por |
|---|---|---|---|
| Contenido de archivos | Alta | Contenedor SDDV/SDDH | AES-256-GCM (D2/D3) |
| Metadatos (filename, timestamp, recipients) | Media | Cabecera AAD del contenedor | Tag AEAD (D2/D3) |
| Llave privada Ed25519 (firma) | Critica | Archivo PEM PKCS8 / keystore JSON | Cifrado con password (D6) |
| Llave privada X25519 (cifrado) | Critica | (a partir de D6) keystore JSON | Cifrado con password (D6) |
| Password del usuario | Critica | Memoria del proceso, no en disco | UX (getpass), no caching (D6) |
| Firma digital del firmante | Media | Footer del contenedor firmado | Ed25519 (EUF-CMA) |
| Nonces AEAD | Media | Cabecera del contenedor | os.urandom + tag |

---

## 3. Adversarios

| ID | Adversario | Capacidades | Limitaciones (asunciones) |
|---|---|---|---|
| **ADV-1** | Atacante externo con acceso al almacenamiento | Lee, copia y modifica contenedores cifrados; copia el keystore | No puede romper AES-256 ni Ed25519; no observa el proceso en ejecucion |
| **ADV-2** | Destinatario malicioso | Lee su propio archivo legitimamente; intenta forjar contenedores que parezcan de otros | No tiene la privada del remitente |
| **ADV-3** | Man-in-the-Middle en la distribucion de claves publicas | Intercepta y sustituye llaves publicas en transito | No puede descifrar sin la privada correspondiente |
| **ADV-4** | Acceso fisico temporal al equipo | Copia el keystore completo (`keystore/*.json`) | No conoce el password; no instala malware persistente |
| **ADV-5** | Atacante que re-empaqueta firmas | Toma una firma valida y la reasocia a otro contenido o identidad | No puede recomputar la firma sin la privada |
| **ADV-6** *(fuera de scope)* | Atacante con codigo ejecutandose en la maquina (malware) | RAM dump, keylogger, hooking de la libreria | — (fuera de scope explicito) |

---

## 4. Supuestos de confianza

1. Los usuarios eligen contrasenas fuertes (>= 12 caracteres). El
   sistema valida la fortaleza (`validate_password_strength`).
2. Las claves publicas distribuidas son autenticas (canal de
   distribucion fuera de scope; D6 muestra el fingerprint para
   verificacion out-of-band).
3. El SO provee CSPRNG seguro: `/dev/urandom` (Linux/macOS),
   `BCryptGenRandom` (Windows).
4. El almacenamiento es no confiable: contenedores y keystore se
   asumen accesibles para ADV-1 y ADV-4.
5. La aplicacion no ha sido modificada (integridad del codigo fuera
   de scope; se asume entrega controlada).
6. No hay malware activo durante el uso (ADV-6 fuera de scope).
7. La libreria `cryptography` de Python es correcta.

---

## 5. Superficie de ataque (resumen)

| Punto de entrada | Riesgo | Requisito afectado | Mitigacion |
|---|---|---|---|
| Generacion de nonce | Reutilizacion catastrofica en GCM | RS-1, RS-2 | `os.urandom(12)` + clave fresca por archivo |
| Keystore (D6) | Fuerza bruta offline sobre password | RS-4 | scrypt cost + `MIN_PASSWORD_LENGTH=12` |
| Importacion de claves publicas | MitM en distribucion | RS-3 | Fuera de scope; fingerprints visibles |
| Entrada de filename | DoS / path traversal | RS-1 | `validate_filename` + `safe_path_join` (VULN-001/006) |
| Entrada de timestamp | Replay de contenedores viejos | — | `validate_timestamp` (VULN-002) |
| Entrada de longitudes de campo | DoS por allocations | — | `validate_ciphertext_length`, `MAX_RECIPIENTS` (VULN-003/004) |
| Orden de verificacion | Descifrar antes de verificar | RS-3 | `secure_verify_and_decrypt` lo impone |

---

## 6. Riesgos de la gestion de llaves (D6 — extension D1)

Esta seccion se completa en la Fase 3 del plan D6 con el analisis
detallado de los siguientes escenarios:

- **6.1 Robo del keystore (ADV-1, ADV-4).** Que ocurre si el atacante
  obtiene `keystore/<name>.json` completo.
- **6.2 Password debil del usuario.** Cuanto cuesta una busqueda
  exhaustiva offline dada la configuracion de scrypt.
- **6.3 Dispositivo comprometido (ADV-6).** Que NO protege D6 cuando
  ya hay codigo malicioso ejecutandose con privilegios del usuario.
- **6.4 Perdida del password.** Recuperacion via backup cifrado con
  password independiente.

---

## 7. Requisitos de seguridad (RS) — referencia

| ID | Requisito | Cubierto por |
|---|---|---|
| RS-1 | Confidencialidad 256-bit | AES-256-GCM (D2/D3) |
| RS-2 | Integridad del contenido | Tag AEAD 128-bit + AAD (D2/D3) |
| RS-3 | Autenticidad del remitente | Firma Ed25519 + verify-first (D5) |
| RS-4 | Proteccion de llaves privadas | Keystore cifrado con KDF + AEAD (D6) |
| RS-5 | Proteccion contra manipulacion | AAD + firma sobre todo el contenedor |
| RS-6 | Unicidad de nonce | os.urandom por cifrado |
| RS-7 | Gestion del ciclo de vida de llaves | KeyStore API: rotate/revoke/backup/restore (D6) |
