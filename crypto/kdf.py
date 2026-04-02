"""
crypto/kdf.py
=============
Módulo de derivación de claves (KDF) para el SDDV.

Convierte un password de usuario en una clave simétrica de 256 bits usando
Argon2id — el ganador de la Password Hashing Competition (2015) y el KDF
recomendado actualmente para proteger claves contra fuerza bruta.

Por qué Argon2id (y no PBKDF2 ni bcrypt):
  - Es resistente a ataques con GPU/ASIC porque requiere mucha memoria (no
    solo tiempo de CPU). Un atacante que quiera probar N contraseñas necesita
    N × 64 MB de RAM en paralelo — eso es lo que lo hace caro.
  - El parámetro `time_cost` controla las iteraciones (CPU).
  - El parámetro `memory_cost` controla la memoria necesaria (RAM).
  - Parámetros mínimos del D1 RS-4: memory >= 64 MB, iterations >= 3.

Flujo de uso normal:
  # Cifrar (primera vez — se genera salt aleatorio)
  key, salt = derive_key("mi_password_seguro")
  # guardar salt junto al contenedor cifrado

  # Descifrar (salt recuperado del contenedor)
  key, _ = derive_key("mi_password_seguro", salt=salt)

El salt NUNCA es secreto — se guarda en texto claro en el contenedor.
Lo que lo protege es el costo computacional de Argon2id: sin saber el
password, recalcular la clave cuesta 64 MB × 3 iteraciones por intento.

Dependencia: pip install argon2-cffi
"""

import os
import struct
from argon2.low_level import hash_secret_raw, Type

# ─────────────────────────── parámetros Argon2id ────────────────────────────

SALT_SIZE    = 16       # 128 bits — tamaño de salt recomendado por OWASP
KEY_SIZE     = 32       # 256 bits — para AES-256-GCM y ChaCha20-Poly1305

# Parámetros mínimos del D1 (RS-4): memory >= 64 MB, time >= 3
MEMORY_COST  = 65_536   # 64 MB en KiB (1 KiB = 1024 bytes)
TIME_COST    = 3        # número de iteraciones
PARALLELISM  = 1        # hilos de cómputo paralelo


# ─────────────────────────── interfaz pública ────────────────────────────────

def derive_key(
    password:    str,
    salt:        bytes = None,
    memory_cost: int = MEMORY_COST,
    time_cost:   int = TIME_COST,
    parallelism: int = PARALLELISM,
) -> tuple:
    """
    Deriva una clave simétrica de 256 bits a partir de un password.

    Si no se pasa `salt`, se genera uno aleatorio de 128 bits con os.urandom().
    Ese salt se debe guardar junto al contenedor cifrado para poder reproducir
    la misma clave al descifrar.

    El mismo password + mismo salt → siempre la misma clave (determinista).
    Password distinto o salt distinto → clave completamente diferente.

    Parámetros:
        password:    contraseña del usuario (string UTF-8)
        salt:        bytes de 16 bytes; None genera uno fresco
        memory_cost: RAM en KiB (default 64 MB = 65536 KiB)
        time_cost:   iteraciones (default 3)
        parallelism: hilos (default 1)

    Retorna:
        (key: bytes[32], salt: bytes[16])

    Lanza:
        ValueError — si el salt no tiene el tamaño correcto
    """
    if salt is None:
        # Nuevo cifrado: salt fresco con CSPRNG del SO
        salt = os.urandom(SALT_SIZE)
    elif len(salt) != SALT_SIZE:
        raise ValueError(
            f"Salt inválido: se esperaban {SALT_SIZE} bytes, "
            f"se recibieron {len(salt)}"
        )

    if not password:
        raise ValueError("El password no puede estar vacío")

    # Argon2id con los parámetros indicados
    # Type.ID = Argon2id (combina Argon2i y Argon2d: resiste ataques de
    # canal lateral Y ataques de análisis de tiempo-memoria)
    key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )

    return key, salt


def serialize_kdf_params(salt: bytes, memory_cost: int = MEMORY_COST,
                          time_cost: int = TIME_COST,
                          parallelism: int = PARALLELISM) -> bytes:
    """
    Serializa los parámetros KDF para almacenarlos en el contenedor.

    Formato (26 bytes):
        salt        : 16 bytes
        memory_cost :  4 bytes (big-endian uint32, en KiB)
        time_cost   :  4 bytes (big-endian uint32)
        parallelism :  2 bytes (big-endian uint16)
    """
    return (
        salt
        + struct.pack(">I", memory_cost)
        + struct.pack(">I", time_cost)
        + struct.pack(">H", parallelism)
    )


def deserialize_kdf_params(data: bytes, offset: int = 0) -> tuple:
    """
    Deserializa los parámetros KDF desde bytes del contenedor.

    Retorna:
        (salt, memory_cost, time_cost, parallelism, bytes_consumidos)
    """
    PARAMS_SIZE = SALT_SIZE + 4 + 4 + 2  # 26 bytes

    if len(data) < offset + PARAMS_SIZE:
        raise ValueError("Datos insuficientes para deserializar parámetros KDF")

    salt        = data[offset : offset + SALT_SIZE]
    memory_cost = struct.unpack(">I", data[offset + 16 : offset + 20])[0]
    time_cost   = struct.unpack(">I", data[offset + 20 : offset + 24])[0]
    parallelism = struct.unpack(">H", data[offset + 24 : offset + 26])[0]

    return salt, memory_cost, time_cost, parallelism, PARAMS_SIZE
