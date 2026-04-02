"""
tests/test_aead.py
==================
Tests unitarios para el módulo crypto/aead.py — D2 del proyecto SDDV.

Ejecutar con:
    pytest tests/test_aead.py -v

Requiere:
    pip install pytest cryptography
"""

import os
import struct

import pytest
from cryptography.exceptions import InvalidTag

from crypto.aead import (
    Algorithm,
    NONCE_SIZE,
    TAG_SIZE,
    _parse_header,
    decrypt_file,
    encrypt_file,
    generate_key,
)

# ─────────────────────────── datos de prueba ────────────────────────────────

SAMPLE_PLAINTEXT = b"Este es un documento confidencial de la UNAM - semestre 2026-2."
SAMPLE_FILENAME  = "reporte_financiero.pdf"


# ─────────────────────────────── helpers ────────────────────────────────────

def encrypt_default(algo: Algorithm = Algorithm.AES_256_GCM):
    """Shortcut para cifrar con los datos de prueba estándar."""
    return encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, algo=algo)


def locate_ciphertext_start(container: bytes) -> int:
    """
    Devuelve el índice del primer byte del ciphertext dentro del contenedor.
    Útil para modificar el ciphertext sin tocar la cabecera ni el nonce.
    """
    _, header_end = _parse_header(container)
    # header_end + nonce(12) + ct_len_field(4)
    return header_end + NONCE_SIZE + 4


# ═══════════════════════════════════════════════════════════════════════════
# CASO 1 — Cifrar → descifrar devuelve el archivo idéntico
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("algo", [Algorithm.AES_256_GCM, Algorithm.CHACHA20_POLY1305])
def test_roundtrip_devuelve_plaintext_identico(algo):
    """
    El plaintext recuperado debe ser bit a bit idéntico al original,
    para ambos algoritmos AEAD soportados.
    """
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, algo=algo)
    recovered, metadata = decrypt_file(container, key)

    assert recovered == SAMPLE_PLAINTEXT, (
        "El plaintext recuperado no coincide con el original"
    )
    assert metadata["filename"] == SAMPLE_FILENAME
    assert metadata["algo"] == algo


def test_roundtrip_archivo_vacio():
    """El módulo debe manejar archivos de 0 bytes sin errores."""
    container, key = encrypt_file(b"", "empty.bin")
    recovered, _ = decrypt_file(container, key)
    assert recovered == b""


def test_roundtrip_archivo_grande():
    """Verificar con datos de 1 MB (texto y binario)."""
    big_data = os.urandom(1024 * 1024)
    container, key = encrypt_file(big_data, "documento_grande.bin")
    recovered, _ = decrypt_file(container, key)
    assert recovered == big_data


def test_roundtrip_nombre_con_caracteres_unicode():
    """Nombres de archivo en UTF-8 con caracteres no ASCII deben funcionar."""
    filename = "contrato_cláusula_ñoño_2026.pdf"
    container, key = encrypt_file(SAMPLE_PLAINTEXT, filename)
    _, metadata = decrypt_file(container, key)
    assert metadata["filename"] == filename


def test_roundtrip_preserva_timestamp():
    """El timestamp que se pasa al cifrar debe recuperarse en los metadatos."""
    ts = 1_700_000_000  # timestamp fijo para el test
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, timestamp=ts)
    _, metadata = decrypt_file(container, key)
    assert metadata["timestamp"] == ts


# ═══════════════════════════════════════════════════════════════════════════
# CASO 2 — Clave incorrecta falla
# ═══════════════════════════════════════════════════════════════════════════

def test_clave_incorrecta_lanza_invalid_tag():
    """
    Con una clave diferente a la usada en el cifrado, decrypt_file() debe
    lanzar InvalidTag sin devolver ningún dato del plaintext.
    """
    container, _ = encrypt_default()
    wrong_key = os.urandom(32)  # clave completamente aleatoria ≠ la original
    with pytest.raises(InvalidTag):
        decrypt_file(container, wrong_key)


def test_clave_de_ceros_falla():
    """Una clave de 32 ceros también debe causar InvalidTag."""
    container, _ = encrypt_default()
    zero_key = bytes(32)
    with pytest.raises(InvalidTag):
        decrypt_file(container, zero_key)


def test_clave_correcta_pero_un_bit_diferente_falla():
    """
    Cambiar solo un bit de la clave correcta debe hacer fallar la verificación.
    Esto demuestra que no hay "claves cercanas" que funcionen.
    """
    container, key = encrypt_default()
    # Voltear el último bit de la clave
    corrupted_key = bytearray(key)
    corrupted_key[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_file(container, bytes(corrupted_key))


# ═══════════════════════════════════════════════════════════════════════════
# CASO 3 — Ciphertext modificado falla
# ═══════════════════════════════════════════════════════════════════════════

def test_ciphertext_modificado_falla():
    """
    Voltear un byte en el ciphertext debe invalidar el tag de autenticación.
    Demuestra que el tag cubre el ciphertext completo.
    """
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
    ct_start = locate_ciphertext_start(container)

    # Solo tiene sentido modificar si hay ciphertext (archivo no vacío)
    assert ct_start < len(container) - TAG_SIZE, "No hay ciphertext para modificar"

    tampered = bytearray(container)
    tampered[ct_start] ^= 0xFF  # voltear todos los bits del primer byte
    with pytest.raises(InvalidTag):
        decrypt_file(bytes(tampered), key)


def test_ciphertext_byte_final_modificado_falla():
    """Modificar el último byte del ciphertext (justo antes del tag) también falla."""
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
    tag_start = len(container) - TAG_SIZE
    ct_start  = locate_ciphertext_start(container)

    assert ct_start < tag_start, "No hay ciphertext para modificar"

    tampered = bytearray(container)
    tampered[tag_start - 1] ^= 0x01  # último byte del ciphertext
    with pytest.raises(InvalidTag):
        decrypt_file(bytes(tampered), key)


def test_contenedor_truncado_falla():
    """Recortar los últimos bytes del contenedor debe fallar de forma segura."""
    container, key = encrypt_default()
    truncated = container[:-20]  # eliminar 20 bytes del final (parte del tag)
    with pytest.raises((ValueError, InvalidTag)):
        decrypt_file(truncated, key)


def test_contenedor_con_bytes_extra_falla():
    """Añadir bytes al final del contenedor debe ser detectado."""
    container, key = encrypt_default()
    extended = container + b"\x00" * 10
    with pytest.raises(ValueError):
        decrypt_file(extended, key)


# ═══════════════════════════════════════════════════════════════════════════
# CASO 4 — Metadatos modificados falla
# ═══════════════════════════════════════════════════════════════════════════

def test_version_en_cabecera_modificada_falla():
    """
    Modificar el byte VERSION en la cabecera (AAD) debe invalidar el tag.
    Demuestra que los metadatos están vinculados al tag AEAD.
    """
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
    tampered = bytearray(container)
    tampered[4] ^= 0x01  # byte de versión (posición fija en el formato)
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file(bytes(tampered), key)


def test_algo_id_en_cabecera_modificado_falla():
    """Cambiar el byte del algoritmo en la cabecera debe fallar."""
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME,
                                   algo=Algorithm.AES_256_GCM)
    tampered = bytearray(container)
    # Cambiar ALGO_ID de 0x01 (AES-GCM) a 0x02 (ChaCha20)
    tampered[5] = int(Algorithm.CHACHA20_POLY1305)
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file(bytes(tampered), key)


def test_timestamp_en_cabecera_modificado_falla():
    """
    Cambiar el timestamp en el AAD debe invalidar el tag de autenticación.
    El timestamp está en los bytes [6:14] de la cabecera.
    """
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, timestamp=1_000_000)
    tampered = bytearray(container)
    tampered[6] ^= 0x01  # modificar el byte más significativo del timestamp
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file(bytes(tampered), key)


def test_filename_en_cabecera_modificado_falla():
    """
    Cambiar un carácter del nombre de archivo en el AAD debe hacer fallar
    la verificación del tag.
    """
    container, key = encrypt_file(SAMPLE_PLAINTEXT, "original.pdf")
    # El filename empieza en el byte 16 de la cabecera
    tampered = bytearray(container)
    tampered[16] ^= 0x01  # modificar primer byte del filename en el AAD
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file(bytes(tampered), key)


def test_magic_bytes_invalidos_falla():
    """Un contenedor con magic bytes incorrectos debe rechazarse antes del AEAD."""
    container, key = encrypt_default()
    tampered = b"FAKE" + container[4:]
    with pytest.raises(ValueError, match="Magic bytes"):
        decrypt_file(tampered, key)


# ═══════════════════════════════════════════════════════════════════════════
# CASO 5 — Múltiples cifrados producen ciphertexts diferentes
# ═══════════════════════════════════════════════════════════════════════════

def test_mismo_plaintext_misma_clave_produce_ciphertexts_distintos():
    """
    Dos cifrados del mismo plaintext con la misma clave deben producir
    contenedores distintos porque cada cifrado genera un nonce diferente.
    """
    key = generate_key()
    container1, _ = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, key=key)
    container2, _ = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, key=key)

    assert container1 != container2, (
        "Dos cifrados del mismo archivo produjeron el mismo contenedor — "
        "¡posible reutilización de nonce!"
    )


def test_claves_distintas_producen_ciphertexts_distintos():
    """Con claves distintas (modo por defecto) los contenedores también difieren."""
    container1, _ = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
    container2, _ = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
    assert container1 != container2


def test_nonces_son_unicos_en_100_cifrados():
    """
    Verificar que 100 cifrados consecutivos generen 100 nonces distintos.
    Con 96 bits de entropía, la probabilidad de colisión es despreciable
    (birthday bound: ≈ 2^-32 tras 2^32 muestras).
    """
    nonces = set()
    for _ in range(100):
        container, _ = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
        _, header_end = _parse_header(container)
        nonce = container[header_end : header_end + NONCE_SIZE]
        nonces.add(nonce)

    assert len(nonces) == 100, (
        f"Se detectaron nonces repetidos: {100 - len(nonces)} colisiones en 100 muestras"
    )


def test_claves_generadas_son_unicas():
    """generate_key() debe producir claves distintas en cada invocación."""
    keys = {generate_key() for _ in range(50)}
    assert len(keys) == 50, "generate_key() produjo claves repetidas"


# ═══════════════════════════════════════════════════════════════════════════
# Tests de algoritmo alternativo — ChaCha20-Poly1305
# ═══════════════════════════════════════════════════════════════════════════

def test_chacha20_roundtrip_completo():
    """ChaCha20-Poly1305 debe pasar el ciclo completo de cifrado/descifrado."""
    data = b"Datos sensibles cifrados con ChaCha20-Poly1305."
    container, key = encrypt_file(data, "test_chacha.txt", algo=Algorithm.CHACHA20_POLY1305)
    recovered, meta = decrypt_file(container, key)

    assert recovered == data
    assert meta["algo"] == Algorithm.CHACHA20_POLY1305


def test_chacha20_ciphertext_modificado_falla():
    """ChaCha20-Poly1305 también debe detectar manipulación del ciphertext."""
    container, key = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME,
                                   algo=Algorithm.CHACHA20_POLY1305)
    ct_start = locate_ciphertext_start(container)
    tampered  = bytearray(container)
    tampered[ct_start] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_file(bytes(tampered), key)


# ═══════════════════════════════════════════════════════════════════════════
# Tests de robustez y casos borde
# ═══════════════════════════════════════════════════════════════════════════

def test_clave_de_tamano_incorrecto_lanza_error():
    """Pasar una clave de longitud incorrecta debe lanzar ValueError antes del cifrado."""
    with pytest.raises(ValueError, match="mano de clave incorrecto"):
        encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, key=b"demasiado_corta")


def test_roundtrip_datos_binarios_arbitrarios():
    """El módulo debe funcionar con cualquier secuencia de bytes (no solo texto)."""
    binary_data = bytes(range(256)) * 100  # todos los valores de byte posibles
    container, key = encrypt_file(binary_data, "binario.bin")
    recovered, _ = decrypt_file(container, key)
    assert recovered == binary_data


def test_tag_modificado_falla():
    """Modificar el tag de autenticación (últimos 16 bytes) debe fallar."""
    container, key = encrypt_default()
    tampered = bytearray(container)
    tampered[-1] ^= 0xFF  # último byte del tag
    with pytest.raises(InvalidTag):
        decrypt_file(bytes(tampered), key)
