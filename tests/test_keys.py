"""
tests/test_keys.py
==================
Tests unitarios para crypto/keys.py -- SDDV.
Ejecutar con: pytest tests/test_keys.py -v
"""
import os
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto.keys import (
    generate_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    get_fingerprint,
    generate_and_save_keypair,
    PRIVATE_KEY_SUFFIX,
    PUBLIC_KEY_SUFFIX,
)

PASSWORD   = "password_seguro_UNAM_2026!"
WRONG_PASS = "password_incorrecto"


# == Fixtures ==================================================================

@pytest.fixture
def keypair():
    return generate_keypair()

@pytest.fixture
def tmp_base(tmp_path):
    return str(tmp_path / "llave_test")


# == Generacion de llaves ======================================================

def test_generate_keypair_produce_objetos_validos(keypair):
    priv, pub = keypair
    assert isinstance(priv, Ed25519PrivateKey)

def test_generate_keypair_produce_pares_distintos():
    """Cada llamada genera un par diferente."""
    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    assert get_fingerprint(pub1) != get_fingerprint(pub2)

def test_llave_publica_se_deriva_de_privada(keypair):
    priv, pub = keypair
    assert get_fingerprint(pub) == get_fingerprint(priv.public_key())


# == Guardar y cargar llave privada ============================================

def test_save_load_private_key_roundtrip(keypair, tmp_base):
    priv, pub = keypair
    path = tmp_base + PRIVATE_KEY_SUFFIX
    save_private_key(priv, path, PASSWORD)
    assert os.path.exists(path)
    loaded = load_private_key(path, PASSWORD)
    assert get_fingerprint(loaded.public_key()) == get_fingerprint(pub)

def test_llave_privada_guardada_en_pem_cifrado(keypair, tmp_base):
    """El archivo debe estar en formato PEM cifrado (PKCS8), no en texto plano."""
    priv, _ = keypair
    path = tmp_base + PRIVATE_KEY_SUFFIX
    save_private_key(priv, path, PASSWORD)
    with open(path, "rb") as f:
        contenido = f.read()
    # PEM cifrado comienza con este encabezado estandar
    assert contenido.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")

def test_password_incorrecto_al_cargar_privada_falla(keypair, tmp_base):
    priv, _ = keypair
    path = tmp_base + PRIVATE_KEY_SUFFIX
    save_private_key(priv, path, PASSWORD)
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path, WRONG_PASS)

def test_password_un_caracter_diferente_falla(keypair, tmp_base):
    priv, _ = keypair
    path = tmp_base + PRIVATE_KEY_SUFFIX
    save_private_key(priv, path, PASSWORD)
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path, PASSWORD[:-1] + "X")

def test_archivo_privada_manipulado_falla(keypair, tmp_base):
    """Modificar el archivo de llave privada debe causar error al cargar."""
    priv, _ = keypair
    path = tmp_base + PRIVATE_KEY_SUFFIX
    save_private_key(priv, path, PASSWORD)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    # Corromper bytes del bloque cifrado (evitar el encabezado PEM)
    data[-10] ^= 0xFF
    with open(path, "wb") as f:
        f.write(bytes(data))
    with pytest.raises((ValueError, TypeError)):
        load_private_key(path, PASSWORD)

def test_archivo_privada_no_existe_lanza_error(tmp_base):
    with pytest.raises(FileNotFoundError):
        load_private_key(tmp_base + "_no_existe" + PRIVATE_KEY_SUFFIX, PASSWORD)


# == Guardar y cargar llave publica ============================================

def test_save_load_public_key_roundtrip(keypair, tmp_base):
    _, pub = keypair
    path = tmp_base + PUBLIC_KEY_SUFFIX
    save_public_key(pub, path)
    assert os.path.exists(path)
    loaded = load_public_key(path)
    assert get_fingerprint(loaded) == get_fingerprint(pub)

def test_llave_publica_guardada_en_pem(keypair, tmp_base):
    """La llave publica debe guardarse en formato PEM legible."""
    _, pub = keypair
    path = tmp_base + PUBLIC_KEY_SUFFIX
    save_public_key(pub, path)
    with open(path, "rb") as f:
        contenido = f.read()
    assert contenido.startswith(b"-----BEGIN PUBLIC KEY-----")

def test_archivo_publico_no_existe_lanza_error(tmp_base):
    with pytest.raises(FileNotFoundError):
        load_public_key(tmp_base + "_no_existe" + PUBLIC_KEY_SUFFIX)


# == Fingerprint ===============================================================

def test_fingerprint_es_hex_de_64_chars(keypair):
    _, pub = keypair
    fp = get_fingerprint(pub)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)

def test_fingerprint_es_determinista(keypair):
    _, pub = keypair
    assert get_fingerprint(pub) == get_fingerprint(pub)

def test_fingerprints_distintos_para_llaves_distintas():
    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    assert get_fingerprint(pub1) != get_fingerprint(pub2)

def test_fingerprint_desde_archivo(keypair, tmp_base):
    from crypto.keys import get_fingerprint_from_file
    _, pub = keypair
    path = tmp_base + PUBLIC_KEY_SUFFIX
    save_public_key(pub, path)
    assert get_fingerprint_from_file(path) == get_fingerprint(pub)


# == Flujo completo: generate_and_save_keypair =================================

def test_generate_and_save_keypair_crea_ambos_archivos(tmp_base):
    result = generate_and_save_keypair(tmp_base, PASSWORD)
    assert os.path.exists(result["private_key_path"])
    assert os.path.exists(result["public_key_path"])
    assert len(result["fingerprint"]) == 64

def test_generate_and_save_keypair_llave_recuperable(tmp_base):
    result  = generate_and_save_keypair(tmp_base, PASSWORD)
    priv    = load_private_key(result["private_key_path"], PASSWORD)
    pub     = load_public_key(result["public_key_path"])
    fp_priv = get_fingerprint(priv.public_key())
    fp_pub  = get_fingerprint(pub)
    assert fp_priv == fp_pub == result["fingerprint"]

def test_dos_pares_generados_tienen_fingerprints_distintos(tmp_base):
    r1 = generate_and_save_keypair(tmp_base + "_alice", PASSWORD)
    r2 = generate_and_save_keypair(tmp_base + "_bob",   PASSWORD)
    assert r1["fingerprint"] != r2["fingerprint"]
