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
