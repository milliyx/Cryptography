"""
crypto/kdf.py
=============
KDF (Key Derivation Function) explicito para el keystore D6.

Por que un KDF en lugar de usar el password directo como clave:
  Un password humano tiene pocos bits de entropia (10-40 bits tipico
  para 8-12 caracteres). Una clave AES-256 necesita 256 bits "indistin-
  guibles" de aleatorio. Un KDF estira la entropia y, mas importante,
  AGREGA COSTO COMPUTACIONAL al atacante que intenta probar passwords
  uno por uno offline tras robar el keystore.

Por que scrypt (RFC 7914) en lugar de PBKDF2:
  - PBKDF2 solo gasta CPU. Un atacante con GPU/ASIC paraleliza
    millones de candidatos por segundo a coste lineal.
  - scrypt es MEMORY-HARD: cada intento exige ~N*r*64 bytes de RAM.
    Con los parametros por defecto (N=2**15, r=8) son ~16 MiB por
    intento, lo que destroza la economia del ataque con GPU/ASIC.
  - scrypt esta en la libreria estandar (`hashlib.scrypt`), no
    introduce dependencias nuevas.

Parametros por defecto (OWASP Password Storage Cheat Sheet, 2024):
    N = 2**15   (32768) — factor de costo (memoria y tiempo)
    r = 8                  — tamano de bloque
    p = 1                  — paralelismo
    dklen = 32             — 256 bits para AES-256-GCM

Un intento toma ~150 ms en una laptop tipica y exige ~80 MiB de RAM.
Esto se documenta en docs/D6_Key_Management.md.

Referencia: RFC 7914 (scrypt), OWASP CS Password Storage.
"""

from __future__ import annotations

import hashlib
import os
from typing import Dict


# ── parametros por defecto ────────────────────────────────────────────────────

DEFAULT_KDF_PARAMS: Dict[str, int] = {
    "n":     2 ** 15,   # 32768
    "r":     8,
    "p":     1,
    "dklen": 32,
}

SALT_SIZE = 16  # 128 bits, holgado para evitar colisiones de salt


# ── API publica ───────────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Genera un salt aleatorio fresco con el CSPRNG del SO."""
    return os.urandom(SALT_SIZE)


def validate_params(params: Dict[str, int]) -> None:
    """
    Valida la estructura y los valores de los parametros KDF.

    Lanza ValueError si:
      - falta alguna clave esperada
      - algun valor no es int
      - n no es potencia de 2 (requisito de scrypt)
      - r, p o dklen son <= 0
      - dklen no es 32 (este proyecto fija la salida a AES-256)

    El proposito es atrapar parametros corruptos en el JSON del
    keystore antes de pasarselos a scrypt (que devolveria errores
    crypticos).
    """
    required = {"n", "r", "p", "dklen"}
    if not isinstance(params, dict):
        raise ValueError("kdf params debe ser un dict")
    missing = required - set(params.keys())
    if missing:
        raise ValueError(f"kdf params: faltan claves {sorted(missing)}")

    for key in required:
        if not isinstance(params[key], int):
            raise ValueError(f"kdf params: {key} debe ser int, no {type(params[key]).__name__}")

    n, r, p, dklen = params["n"], params["r"], params["p"], params["dklen"]

    if n <= 1 or (n & (n - 1)) != 0:
        raise ValueError(f"kdf params: n debe ser potencia de 2 > 1, recibido {n}")
    if r <= 0:
        raise ValueError(f"kdf params: r debe ser > 0, recibido {r}")
    if p <= 0:
        raise ValueError(f"kdf params: p debe ser > 0, recibido {p}")
    if dklen != 32:
        # El keystore cifra con AES-256-GCM; cualquier otra longitud
        # rompe el envelope. Lo hacemos error explicito en lugar de
        # un crash mas adelante.
        raise ValueError(f"kdf params: dklen debe ser 32 (AES-256), recibido {dklen}")


def derive_key(password: str, salt: bytes, params: Dict[str, int]) -> bytes:
    """
    Deriva una clave simetrica de 32 bytes a partir del password y el salt.

    No valida la fortaleza del password aqui -- esa validacion vive en
    crypto.keys.validate_password_strength y se invoca antes de llamar
    a este derive_key (en KeyStore.init_identity / change_password).

    Lanza:
        ValueError -- si los parametros KDF son invalidos.
    """
    if not isinstance(password, str):
        raise ValueError("password debe ser str")
    if not isinstance(salt, (bytes, bytearray)):
        raise ValueError("salt debe ser bytes")
    if len(salt) < 8:
        # 8 bytes es el minimo para que dos identidades distintas casi
        # nunca colisionen su salt. Nosotros usamos 16 por convencion.
        raise ValueError(f"salt demasiado corto: {len(salt)} bytes (>=8 requerido)")

    validate_params(params)

    return hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=bytes(salt),
        n=params["n"],
        r=params["r"],
        p=params["p"],
        dklen=params["dklen"],
        # maxmem: scrypt por defecto exige >= 128*n*r bytes; lo hacemos
        # explicito con un margen para que `n` configurables grandes no
        # tropiecen con el limite por defecto de Python (~32 MiB).
        maxmem=128 * params["n"] * params["r"] * 2,
    )
