# Arquitectura del frontend web

Documento de referencia del diseño técnico del frontend SDDV.

## 1. Visión de alto nivel

El frontend es una **single-page application estática** que ejecuta
toda la criptografía dentro del navegador del usuario mediante Pyodide
(CPython compilado a WebAssembly). No hay backend, no hay base de
datos, no hay servicios SaaS. La persistencia es local (IndexedDB).

```
┌──────────────────────────────────────────────────────────────┐
│                       NAVEGADOR DEL USUARIO                   │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                       UI (HTML / CSS / JS)                │ │
│  │  index.html · styles.css · app.js                         │ │
│  └────────────────────────┬─────────────────────────────────┘ │
│                            │  callPy(funcName, args)           │
│  ┌────────────────────────▼─────────────────────────────────┐ │
│  │                    BRIDGE  (pyodide-runtime.js)           │ │
│  │  - Bootstrap Pyodide v0.27.2                              │ │
│  │  - Monta IDBFS en /keystore                               │ │
│  │  - Descarga crypto/*.py al filesystem virtual             │ │
│  │  - Expone runtime.callPy / persistKeystore                │ │
│  └────────────────────────┬─────────────────────────────────┘ │
│                            │  pyodide.runPython(...)           │
│  ┌────────────────────────▼─────────────────────────────────┐ │
│  │                  PYTHON  (Pyodide / WASM)                  │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │  sddv_api.py  (adapter: hex<->bytes, JSON output)     │ │ │
│  │  └──────────────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │  crypto/  (mismo modulo que el CLI, sin cambios)       │ │ │
│  │  │  aead.py · hybrid.py · signatures.py · secure_send.py  │ │ │
│  │  │  keystore.py · keystore_format.py · keystore_backup.py │ │ │
│  │  │  kdf.py · keys.py                                      │ │ │
│  │  └──────────────────────────────────────────────────────┘ │ │
│  │  Dependencias: cryptography (wheel oficial Pyodide)        │ │
│  └────────────────────────┬─────────────────────────────────┘ │
│                            │  FS.syncfs(false)                 │
│  ┌────────────────────────▼─────────────────────────────────┐ │
│  │                     INDEXEDDB  (IDBFS)                    │ │
│  │  /keystore/<name>.json    (cifrado AES-256-GCM)           │ │
│  │  /keystore/<name>.rotated-<ts>.json                       │ │
│  └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘

                   ▲                                     ▲
                   │ HTTPS  (primera carga)              │ HTTPS
                   │                                     │
        ┌──────────┴──────────┐               ┌──────────┴──────────┐
        │  cdn.jsdelivr.net    │               │  GitHub Pages       │
        │  Pyodide v0.27.2     │               │  index.html, .js,   │
        │  cryptography wheel  │               │  styles.css,        │
        │                      │               │  crypto/*.py        │
        │  (SRI sha384)        │               │                     │
        └──────────────────────┘               └──────────────────────┘
```

## 2. Stack tecnológico

| Capa | Tecnología | Por qué |
|---|---|---|
| HTML | Vanilla HTML5 + `<dialog>` nativo | Sin framework, sin build |
| CSS | CSS3 con custom properties (`--accent`, `--bg`) | Tema dark coherente |
| JS | ES Modules vanilla | Sin transpilación |
| Runtime Python | Pyodide v0.27.2 | CPython estable en WASM |
| Cripto Python | `cryptography` (pyca, wheel oficial) | Mismas primitivas que el CLI |
| Persistencia | IndexedDB vía IDBFS | Local, transparente para Python |
| Deploy | GitHub Pages (estático) | Cero infraestructura |
| Dev server | `http.server` stdlib | Cero deps |

## 3. Flujo de carga (primera visita)

1. Browser solicita `index.html` desde GitHub Pages.
2. `<script src=".../pyodide.js" integrity="sha384-...">` carga el
   loader de Pyodide. Si el hash no coincide, el navegador rechaza
   el script (defensa contra supply chain de jsdelivr).
3. `<script type="module" src="app.js">` arranca el IIFE de bootstrap.
4. `initRuntime()` en `pyodide-runtime.js` ejecuta:
   - `loadPyodide({indexURL: CDN})` — descarga el WASM (~10 MB).
   - `loadPackage(["cryptography"])` — descarga el wheel oficial.
   - `FS.mount(IDBFS, {}, "/keystore")` — monta IndexedDB.
   - `FS.syncfs(true)` — lee identidades previas si las hay.
5. Por cada nombre en `CRYPTO_FILES`, `fetch("./crypto/<f>")` y
   `FS.writeFile("/crypto/<f>", text)`.
6. `sys.path.insert(0, "/")` + `import sddv_api`.
7. UI oculta `#boot`, muestra `#app`, llama `refreshIdentities()`.

**Tiempo total primera carga:** ~5-15 s en conexión decente.
**Cargas siguientes:** ~1-2 s (Pyodide y crypto cacheados por el navegador).

## 4. Bridge JS ↔ Python (ejemplo: cifrar archivo)

```
[user clicks "Cifrar y firmar"]   app.js (#form-send submit)
        │
        │ file.arrayBuffer() → Uint8Array
        ▼
callPy("encrypt_and_sign", [signer, pwd, recipients[], buf, name])
        │  pyodide.globals.set("__arg_i", argJS)
        │  Uint8Array → memoryview/bytes (zero-copy)
        ▼
pyodide.runPython("sddv_api.encrypt_and_sign(__arg_0, __arg_1, ...)")
        │
        ▼
sddv_api.encrypt_and_sign()  (web/frontend/sddv_api.py)
        │  parsea recipients hex → X25519PublicKey
        ▼
crypto.secure_send.encrypt_and_sign_from_keystore  (mismo .py que CLI)
        │  → KeyStore("/keystore")  (IDBFS)
        │  → hashlib.scrypt KDF
        │  → AESGCM unwrap envelope
        │  → Ed25519 sign + crypto.hybrid.encrypt_for_recipients
        ▼
container: bytes  ─►  PyProxy ─► pyToJs() / toJs()  (app.js)
        ▼
downloadBytes(name+".sddh", Uint8Array)
        │  Blob + URL.createObjectURL + <a download>
        ▼
[archivo descargado al disco del usuario]
```

## 5. Persistencia (IDBFS)

El módulo `crypto.keystore.KeyStore` no sabe que está en navegador.
Escribe a `Path("/keystore")` igual que si fuera un disco. El truco
está en montar IDBFS en esa ruta:

```javascript
pyodide.FS.mount(pyodide.FS.filesystems.IDBFS, {}, "/keystore");
```

Después de cualquier mutación (init, change-password, rotate, delete,
revoke, restore) se llama:

```javascript
await new Promise((resolve, reject) =>
  pyodide.FS.syncfs(false, err => err ? reject(err) : resolve())
);
```

Esto vuelca los cambios de IDBFS a IndexedDB. Limitación conocida:
no es atómico para múltiples archivos. Una operación que toque más de
un archivo (ej. `rotate_keys` que crea el nuevo + archiva el viejo)
puede dejar el keystore en estado inconsistente si el usuario cierra
la pestaña en medio.

## 6. Zero-divergence con el backend

El workflow `.github/workflows/pages.yml` copia literalmente la
carpeta `crypto/` al artifact que publica Pages:

```yaml
- run: cp -r crypto _site/crypto
```

**Resultado:** el frontend y el CLI ejecutan EXACTAMENTE los mismos
archivos `.py`. Imposible que se desincronicen sin notarlo. Los 300
tests del backend cubren toda la lógica criptográfica que corre en
el navegador.

## 7. Trade-offs documentados

| Decisión | Por qué | Costo |
|---|---|---|
| Pyodide en lugar de cripto JS | Reuso del módulo `crypto/` auditado | ~10 MB de WASM, ~150ms scrypt |
| IndexedDB en lugar de localStorage | Cuotas mayores + acceso desde IDBFS | API async |
| GitHub Pages en lugar de servidor | Cero infraestructura | Sin headers HTTP custom |
| Sin Web Worker | Simplicidad del bridge | scrypt bloquea UI |
| Sin framework | Bundle pequeño, sin build | Más código manual |
| Lista hardcoded de `CRYPTO_FILES` | Simplicidad | Olvidar actualizarla rompe en producción |

## 8. Próximos pasos (roadmap)

Documentado en `docs/ROADMAP.md`. Las prioridades altas son:
- Web Worker para scrypt (no bloquear UI)
- Auto-discovery de `CRYPTO_FILES` desde manifest
- Tests automatizados de interoperabilidad CLI ↔ web
- SRI también para el wheel de `cryptography`
- Botón "Rotar llaves" en UI (función ya existe en `sddv_api.py`)
