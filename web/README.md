# SDDV Web UI

Interfaz web del SDDV con backend en Appwrite Cloud.

## Estructura

- `frontend/` — HTML + JS estatico. Login/registro con Appwrite Auth.
  Pensado para hospedar en GitHub Pages.
- `functions/` — (proximamente) Appwrite Functions en Python que reusan
  el modulo `crypto/` del repo para operaciones cripto.

## Correr el frontend local

```bash
cd web/frontend
python -m http.server 5500
```

Abrir http://localhost:5500.

## Configuracion Appwrite

Los IDs publicos viven en `frontend/config.js`. Plataformas autorizadas
en el proyecto Appwrite (CORS):

- `localhost` — desarrollo local
- `milliyx.github.io` — produccion en GitHub Pages
