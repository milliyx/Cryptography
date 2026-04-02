"""
tests/test_kdf.py
=================
Tests unitarios para crypto/kdf.py y el modo PASSWORD de crypto/aead.py.
Ejecutar con: pytest tests/test_kdf.py -v
"""
import os
import pytest
from cryptography.exceptions import InvalidTag

from crypto.kdf import derive_key, serialize_kdf_params, deserialize_kdf_params, KEY_SIZE, SALT_SIZE
from crypto.aead import (
    encrypt_file_with_password,
    decrypt_file_with_password,
    encrypt_file,
    decrypt_file,
    VERSION_PASSWORD,
    VERSION_RAW,
)

PASSWORD    = "contrasena_segura_UNAM_2026!"
WRONG_PASS  = "contrasena_incorrecta"
PLAINTEXT   = b"Documento confidencial de la UNAM - expediente medico."
FILENAME    = "expediente.pdf"


# ══════════════════════════════════════════════════════════════════════
# Tests de derive_key
# ══════════════════════════════════════════════════════════════════════

def test_derive_key_devuelve_bytes_de_256_bits():
    key, salt = derive_key(PASSWORD)
    assert len(key) == KEY_SIZE
    assert len(salt) == SALT_SIZE

def test_mismo_password_mismo_salt_da_misma_clave():
    """Argon2id es determinista: mismo input → misma clave."""
    key1, salt = derive_key(PASSWORD)
    key2, _    = derive_key(PASSWORD, salt=salt)
    assert key1 == key2

def test_mismo_password_distinto_salt_da_claves_distintas():
    """Salt diferente → clave completamente distinta."""
    key1, _ = derive_key(PASSWORD)
    key2, _ = derive_key(PASSWORD)
    assert key1 != key2

def test_distinto_password_mismo_salt_da_claves_distintas():
    _, salt = derive_key(PASSWORD)
    key1, _ = derive_key(PASSWORD,    salt=salt)
    key2, _ = derive_key(WRONG_PASS,  salt=salt)
    assert key1 != key2

def test_password_vacio_lanza_error():
    with pytest.raises(ValueError):
        derive_key("")

def test_salt_tamano_incorrecto_lanza_error():
    with pytest.raises(ValueError):
        derive_key(PASSWORD, salt=b"demasiado_corto")

def test_salts_generados_son_unicos():
    salts = {derive_key(PASSWORD)[1] for _ in range(20)}
    assert len(salts) == 20


# ══════════════════════════════════════════════════════════════════════
# Tests de serialización de parámetros KDF
# ══════════════════════════════════════════════════════════════════════

def test_serialize_deserialize_kdf_params_roundtrip():
    _, salt = derive_key(PASSWORD)
    serialized = serialize_kdf_params(salt, 65536, 3, 1)
    s2, mem, tc, par, consumed = deserialize_kdf_params(serialized)
    assert s2 == salt
    assert mem == 65536
    assert tc == 3
    assert par == 1
    assert consumed == 26  # 16 + 4 + 4 + 2


# ══════════════════════════════════════════════════════════════════════
# Tests de encrypt/decrypt con password (modo v2)
# ══════════════════════════════════════════════════════════════════════

def test_roundtrip_password_devuelve_plaintext_identico():
    """Cifrar con password y descifrar con el mismo password → idéntico."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    recovered, metadata = decrypt_file_with_password(container, PASSWORD)
    assert recovered == PLAINTEXT
    assert metadata["filename"] == FILENAME
    assert metadata["version"] == VERSION_PASSWORD

def test_contenedor_v2_tiene_kdf_en_metadata():
    """Los metadatos deben incluir los parámetros KDF."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    _, metadata = decrypt_file_with_password(container, PASSWORD)
    kdf = metadata["kdf"]
    assert kdf is not None
    assert len(kdf["salt"]) == SALT_SIZE
    assert kdf["memory_cost"] == 65536
    assert kdf["time_cost"] == 3

def test_password_incorrecto_lanza_invalid_tag():
    """Password equivocado → InvalidTag, sin datos filtrados."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    with pytest.raises(InvalidTag):
        decrypt_file_with_password(container, WRONG_PASS)

def test_password_correcto_un_caracter_diferente_falla():
    """Cambiar un carácter del password debe fallar."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    with pytest.raises(InvalidTag):
        decrypt_file_with_password(container, PASSWORD[:-1] + "X")

def test_ciphertext_modificado_falla_con_password():
    """Modificar el ciphertext debe fallar aunque el password sea correcto."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    tampered  = bytearray(container)
    tampered[-20] ^= 0xFF  # voltear byte en zona del ciphertext
    with pytest.raises(InvalidTag):
        decrypt_file_with_password(bytes(tampered), PASSWORD)

def test_salt_modificado_en_contenedor_falla():
    """El salt está en el AAD — modificarlo invalida el tag."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    # El salt empieza después de: magic(4)+version(1)+algo(1)+ts(8)+fname_len(2)+filename
    fname_len = len(FILENAME.encode())
    salt_offset = 16 + fname_len  # inicio del salt en la cabecera v2
    tampered = bytearray(container)
    tampered[salt_offset] ^= 0x01
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_file_with_password(bytes(tampered), PASSWORD)

def test_multiples_cifrados_producen_contenedores_distintos():
    """Dos cifrados del mismo archivo con el mismo password deben diferir (salt fresco)."""
    c1 = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    c2 = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    assert c1 != c2

def test_salts_distintos_en_multiples_cifrados():
    """Cada cifrado con password usa un salt distinto → claves distintas."""
    fname_len   = len(FILENAME.encode())
    salt_offset = 16 + fname_len
    contenedores = [encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD) for _ in range(5)]
    salts = {c[salt_offset:salt_offset+SALT_SIZE] for c in contenedores}
    assert len(salts) == 5, "Salts repetidos detectados"

def test_usar_decrypt_file_con_contenedor_v2_lanza_error():
    """decrypt_file() (modo RAW) no debe aceptar un contenedor v2."""
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)
    fake_key  = os.urandom(32)
    with pytest.raises((ValueError, InvalidTag)):
        decrypt_file(container, fake_key)

def test_usar_decrypt_password_con_contenedor_v1_lanza_error():
    """decrypt_file_with_password() no debe aceptar un contenedor v1."""
    container, _ = encrypt_file(PLAINTEXT, FILENAME)
    with pytest.raises(ValueError, match="v1"):
        decrypt_file_with_password(container, PASSWORD)

def test_roundtrip_archivo_vacio_con_password():
    container = encrypt_file_with_password(b"", "vacio.txt", PASSWORD)
    recovered, _ = decrypt_file_with_password(container, PASSWORD)
    assert recovered == b""

def test_roundtrip_archivo_grande_con_password():
    big = os.urandom(512 * 1024)  # 512 KB
    container = encrypt_file_with_password(big, "grande.bin", PASSWORD)
    recovered, _ = decrypt_file_with_password(container, PASSWORD)
    assert recovered == big
