# SDDV Web UI

Interfaz web del SDDV. **Todo corre en el navegador** — sin backend, sin
servidores. Python se ejecuta dentro de la pagina via Pyodide (WebAssembly),
y los keystores se persisten en IndexedDB del usuario.

## Por que asi

- El modelo de amenazas del SDDV (D1) asume que las llaves privadas viven
  solo en el equipo del usuario. Con Pyodide eso es literal: las privadas
  jamas dejan el navegador.
- Despliegue trivial: GitHub Pages sirve un sitio estatico.
- Reusa el modulo `crypto/` del repo tal cual; no se reimplementa nada
  criptografico en JavaScript.

## Estructura

```
web/
├── dev-server.py        # servidor local que sirve frontend/ y crypto/
└── frontend/
    ├── index.html
    ├── styles.css
    ├── app.js              # UI: vistas, formularios, handlers
    ├── pyodide-runtime.js  # bootstrap de Pyodide + IDBFS + carga de crypto/
    └── sddv_api.py         # wrapper Python que expone funciones a JS
```

## Correr local

Desde la raiz del repo:

```bash
python web/dev-server.py
```

Abre http://localhost:5500. La primera carga descarga Pyodide (~10 MB) y
la libreria `cryptography`; despues queda cacheado.

## Operaciones disponibles

- Crear, listar, ver, revocar y borrar identidades
- Cifrar archivo para destinatarios (X25519) y firmarlo (Ed25519)
- Verificar firma y descifrar
- Exportar / restaurar backups con password independiente

## Despliegue en GitHub Pages

`.github/workflows/pages.yml` arma el sitio juntando `web/frontend/` con
`crypto/` al mismo nivel y lo publica en Pages al hacer push a `main`.

La primera vez que se publica hay que activar Pages en el repo:
**Settings -> Pages -> Source: GitHub Actions**.

## Modelo de amenaza del frontend

El frontend **mantiene** sustancialmente las propiedades del backend
(verify-first, AAD del DEM, fingerprint binding, fail-closed en
`InvalidTag`/`InvalidSignature`) porque ejecuta el mismo codigo
`crypto/*.py` dentro de Pyodide. Pero la decision de mover la
ejecucion al navegador **modifica el modelo de amenaza** respecto al
CLI, y aqui lo declaramos explicitamente.

### Que se mantiene igual al CLI

| Adversario D1 | Estado en el frontend |
|---|---|
| ADV-1 (storage attacker) | Mantenido — keystore vive cifrado en IndexedDB |
| ADV-2 (destinatario malicioso) | Mantenido — firma Ed25519 se valida igual |
| ADV-4 (acceso fisico al storage) | Mantenido — IndexedDB cifrado igual que JSON local |
| ADV-5 (fuerza bruta offline) | Mantenido — scrypt corre en WASM con mismos params |

### Que cambia respecto al CLI

| Adversario | Cambio | Mitigacion |
|---|---|---|
| ADV-3 (supply chain) | Degradado: el script de Pyodide y el wheel de `cryptography` se cargan desde CDN externa (`cdn.jsdelivr.net`) | **Subresource Integrity (SRI)** con `sha384` sobre `pyodide.js` (`index.html`). El wheel de `cryptography` no tiene SRI todavia — roadmap. |
| ADV-6 (dispositivo comprometido) | **Amplificado**: el navegador expone superficies que el CLI no — extensiones, DevTools, content scripts, history API | Sin mitigacion. Documentado como trade-off consciente: la conveniencia de la UI web vale el costo SI el usuario controla su navegador. Para entornos sensibles, **usar el CLI**. |
| Nuevo: XSS / inyeccion | Posible si hay XSS futura | `escapeHtml` aplicado a todo dato renderizado; sin `eval`/`Function()`; CSP via `<meta>` |
| Nuevo: Clickjacking | Posible al embeber el sitio en iframe hostil | `X-Frame-Options: DENY` recomendado al hacer deploy con headers customizables |

### Asunciones nuevas del frontend

1. **El navegador del usuario es confiable** — sin extensiones
   maliciosas, sin malware con privilegios de pagina.
2. **TLS efectivo en GitHub Pages** — HSTS y cert valido (Pages lo
   garantiza por default).
3. **El CDN de jsdelivr no esta comprometido**; ademas verificamos
   el hash SRI de `pyodide.js`. Si el hash falla el navegador
   rechaza el script.
4. **`IndexedDB` no es accesible a otros origenes** — same-origin
   policy es la garantia.

### Limitaciones conocidas

- **scrypt bloquea el main thread** ~0.5-1.5 s por operacion en
  Pyodide (WASM single-thread). Sin Web Worker todavia. La UI
  parece "colgada" durante init/encrypt/decrypt.
- **iOS Safari** puede agotar memoria por pestaña en archivos
  grandes — rama `feature/ios-warning` agrega un aviso amigable
  (no mergeada todavia).
- **Sin tests automatizados del frontend**. La compatibilidad
  CLI ↔ web es "por construccion" (mismo `.py`), no probada por
  tests dedicados de interoperabilidad.
- **CRYPTO_FILES hardcoded** en `pyodide-runtime.js` — si alguien
  agrega un modulo a `crypto/` y olvida actualizar la lista,
  rompe silenciosamente en produccion.

### Recomendacion

Para almacenar identidades de **uso real con secretos sensibles**,
preferir el **CLI** (`python -m crypto`). El frontend web es ideal
para demostracion, evaluacion academica y casos donde la
conveniencia compensa la superficie adicional.
