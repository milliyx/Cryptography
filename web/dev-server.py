"""Servidor local para desarrollar el frontend del SDDV.

En produccion el sitio se publica en GitHub Pages con `crypto/` y los archivos
del frontend al mismo nivel; aqui replicamos esa estructura sirviendo
`web/frontend/` como raiz y mapeando `/crypto/` al `crypto/` de la raiz del repo.

Uso:
    python web/dev-server.py
    -> abre http://localhost:5500
"""
from __future__ import annotations

import http.server
import socketserver
import sys
from pathlib import Path

ROOT   = Path(__file__).resolve().parent.parent
FRONT  = ROOT / "web" / "frontend"
CRYPTO = ROOT / "crypto"
PORT   = 5500


class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path: str) -> str:
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if clean == "/crypto" or clean.startswith("/crypto/"):
            rel = clean[len("/crypto"):].lstrip("/")
            return str(CRYPTO / rel)
        rel = clean.lstrip("/")
        return str(FRONT / rel) if rel else str(FRONT / "index.html")

    def end_headers(self):
        # Evita que el navegador cachee 404 / contenido viejo durante desarrollo.
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()


def main():
    # Pyodide en Chrome quiere COOP/COEP para algunas cosas; no las necesitamos.
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        url = f"http://localhost:{PORT}"
        print(f"Sirviendo SDDV en {url}")
        print(f"  frontend: {FRONT}")
        print(f"  crypto:   {CRYPTO}")
        print("Ctrl+C para parar.\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDetenido.")
            sys.exit(0)


if __name__ == "__main__":
    main()
