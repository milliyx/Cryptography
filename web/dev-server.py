"""Servidor local para desarrollar el frontend del SDDV.

En produccion el sitio se publica en GitHub Pages con `src/` y los archivos
del frontend al mismo nivel; aqui replicamos esa estructura sirviendo
`web/frontend/` como raiz y mapeando `/src/` al `src/` de la raiz del repo.

Uso:
    python web/dev-server.py
    -> abre http://localhost:5500
"""
from __future__ import annotations

import http.server
import json
import socketserver
import sys
from pathlib import Path

ROOT   = Path(__file__).resolve().parent.parent
FRONT  = ROOT / "web" / "frontend"
SRC = ROOT / "src"
PORT   = 5500


def _crypto_manifest() -> dict:
    """Lista los .py de src/ para que el frontend haga auto-discovery."""
    files = sorted(p.name for p in SRC.glob("*.py"))
    if "__init__.py" in files:
        files.remove("__init__.py")
        files.insert(0, "__init__.py")
    return {"files": files, "version": 1}


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:  # type: ignore[override]
        # Interceptar /src/_manifest.json para generarlo on-the-fly
        # (en produccion lo genera el workflow de Pages).
        if self.path.split("?", 1)[0] == "/src/_manifest.json":
            body = json.dumps(_crypto_manifest(), indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def translate_path(self, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if clean == "/src" or clean.startswith("/src/"):
            rel = clean[len("/src"):].lstrip("/")
            return str(SRC / rel)
        rel = clean.lstrip("/")
        return str(FRONT / rel) if rel else str(FRONT / "index.html")

    def end_headers(self):
        # Evita que el navegador cachee 404 / contenido viejo durante desarrollo.
        self.send_header("Cache-Control", "no-store, max-age=0")

        # Headers de seguridad: replicamos en local lo que GitHub Pages no
        # nos deja inyectar facilmente. Asi probamos la app con las mismas
        # garantias que tendra en produccion + lo que podamos agregar.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy",
                         "geolocation=(), camera=(), microphone=(), "
                         "payment=(), usb=(), interest-cohort=()")
        # Nota: la CSP completa esta en el <meta> de index.html porque
        # tiene que aplicarse antes de que cargue cualquier script;
        # aqui solo ponemos el header de respaldo.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; "
                         "script-src 'self' https://cdn.jsdelivr.net 'wasm-unsafe-eval'; "
                         "style-src 'self' 'unsafe-inline'; "
                         "connect-src 'self' https://cdn.jsdelivr.net; "
                         "img-src 'self' data:; object-src 'none'; "
                         "base-uri 'self'; frame-ancestors 'none';")
        super().end_headers()


def main():
    # Pyodide en Chrome quiere COOP/COEP para algunas cosas; no las necesitamos.
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}"
        print(f"Sirviendo SDDV en {url}")
        print(f"  frontend: {FRONT}")
        print(f"  src:   {SRC}")
        print("Ctrl+C para parar.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDetenido.")
            sys.exit(0)


if __name__ == "__main__":
    main()
