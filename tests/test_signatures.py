"""
tests/test_signatures.py
========================
Tests unitarios para crypto/signatures.py — Fase 3 del SDDV.
Ejecutar con: pytest tests/test_signatures.py -v
"""
import os
import pytest
from cryptography.exceptions import InvalidSignature

from crypto.keys import generate_keypair, get_fingerprint
from crypto.aead import encrypt_file
from crypto.signatures import (
    sign_container,
    verify_container,
    get_signer_fingerprint,
    is_signed,
    SIGN_FOOTER_SIZE,
)

PLAINTEXT = b"Documento confidencial - expediente medico UNAM 2026."
FILENAME  = "expediente.pdf"


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def alice():
    priv, pub = generate_keypair()
    return {"priv": priv, "pub": pub, "fp": get_fingerprint(pub)}

@pytest.fixture
def bob():
    priv, pub = generate_keypair()
    return {"priv": priv, "pub": pub, "fp": get_fingerprint(pub)}

@pytest.fixture
def container():
    c, _ = encrypt_file(PLAINTEXT, FILENAME)
    return c


# ════════════════════════════════════════════════════════════════════
# Firma y verificacion correcta
# ════════════════════════════════════════════════════════════════════

def test_sign_verify_roundtrip(alice, container):
    """Firmar con privada de Alice y verificar con su publica debe pasar."""
    signed    = sign_container(container, alice["priv"])
    recovered = verify_container(signed, alice["pub"])
    assert recovered == container

def test_signed_container_es_mas_largo(alice, container):
    """El contenedor firmado debe tener exactamente 100 bytes mas."""
    signed = sign_container(container, alice["priv"])
    assert len(signed) == len(container) + SIGN_FOOTER_SIZE

def test_is_signed_detecta_firma(alice, container):
    assert not is_signed(container)
    signed = sign_container(container, alice["priv"])
    assert is_signed(signed)

def test_get_signer_fingerprint_correcto(alice, container):
    """El fingerprint extraido debe coincidir con el del firmante."""
    signed = sign_container(container, alice["priv"])
    fp     = get_signer_fingerprint(signed)
    assert fp == alice["fp"]


# ════════════════════════════════════════════════════════════════════
# Llave incorrecta falla
# ════════════════════════════════════════════════════════════════════

def test_verificar_con_llave_incorrecta_falla(alice, bob, container):
    """Firmar con Alice y verificar con Bob debe lanzar InvalidSignature."""
    signed = sign_container(container, alice["priv"])
    with pytest.raises(InvalidSignature):
        verify_container(signed, bob["pub"])

def test_verificar_con_nueva_llave_falla(alice, container):
    """Verificar con una llave completamente nueva debe fallar."""
    signed = sign_container(container, alice["priv"])
    _, nueva_pub = generate_keypair()
    with pytest.raises(InvalidSignature):
        verify_container(signed, nueva_pub)


# ════════════════════════════════════════════════════════════════════
# Contenedor modificado falla
# ════════════════════════════════════════════════════════════════════

def test_contenedor_modificado_invalida_firma(alice, container):
    """Modificar un byte del contenedor debe invalidar la firma."""
    signed   = sign_container(container, alice["priv"])
    tampered = bytearray(signed)
    tampered[10] ^= 0xFF  # modificar un byte del contenedor (antes de la firma)
    with pytest.raises(InvalidSignature):
        verify_container(bytes(tampered), alice["pub"])

def test_firma_modificada_falla(alice, container):
    """Modificar un byte de la firma al final debe fallar."""
    signed   = sign_container(container, alice["priv"])
    tampered = bytearray(signed)
    tampered[-1] ^= 0xFF  # ultimo byte de la firma
    with pytest.raises(InvalidSignature):
        verify_container(bytes(tampered), alice["pub"])

def test_fingerprint_modificado_falla(alice, container):
    """Cambiar el fingerprint en el footer debe fallar la verificacion."""
    signed   = sign_container(container, alice["priv"])
    tampered = bytearray(signed)
    # El fingerprint esta despues del SIGN_MAGIC (4 bytes), desde el final
    fp_offset = len(signed) - SIGN_FOOTER_SIZE + 4
    tampered[fp_offset] ^= 0x01
    with pytest.raises((InvalidSignature, ValueError)):
        verify_container(bytes(tampered), alice["pub"])

def test_magic_de_firma_incorrecto_falla(alice, container):
    """Sin el magic SIGS correcto, verify_container debe lanzar ValueError."""
    signed   = sign_container(container, alice["priv"])
    tampered = bytearray(signed)
    # Reemplazar el magic SIGS
    magic_offset = len(signed) - SIGN_FOOTER_SIZE
    tampered[magic_offset:magic_offset+4] = b"FAKE"
    with pytest.raises(ValueError, match="Magic de firma invalido"):
        verify_container(bytes(tampered), alice["pub"])

def test_contenedor_sin_firma_falla(container, alice):
    """Un contenedor SDDV sin firma no debe pasar verify_container."""
    with pytest.raises(ValueError):
        verify_container(container, alice["pub"])


# ════════════════════════════════════════════════════════════════════
# Patron Encrypt-then-Sign (flujo completo)
# ════════════════════════════════════════════════════════════════════

def test_flujo_completo_encrypt_then_sign(alice):
    """Cifrar, firmar, verificar y descifrar — flujo completo."""
    from crypto.aead import decrypt_file

    container, key = encrypt_file(PLAINTEXT, FILENAME)

    # 1. Firmar el contenedor cifrado
    signed = sign_container(container, alice["priv"])

    # 2. Verificar ANTES de descifrar
    container_verificado = verify_container(signed, alice["pub"])

    # 3. Descifrar solo si la verificacion paso
    recovered, _ = decrypt_file(container_verificado, key)
    assert recovered == PLAINTEXT

def test_flujo_con_password_encrypt_then_sign(alice):
    """Flujo completo con modo PASSWORD (v2) + firma."""
    from crypto.aead import encrypt_file_with_password, decrypt_file_with_password

    PASSWORD = "mi_password_seguro_2026"
    container = encrypt_file_with_password(PLAINTEXT, FILENAME, PASSWORD)

    signed               = sign_container(container, alice["priv"])
    container_verificado = verify_container(signed, alice["pub"])
    recovered, _         = decrypt_file_with_password(container_verificado, PASSWORD)

    assert recovered == PLAINTEXT

def test_no_descifrar_si_firma_invalida(alice, bob):
    """Si la firma falla, no se debe llegar a descifrar."""
    from crypto.aead import decrypt_file

    container, key = encrypt_file(PLAINTEXT, FILENAME)
    signed         = sign_container(container, alice["priv"])

    # Bob intenta verificar con su propia llave (deberia fallar)
    with pytest.raises(InvalidSignature):
        verify_container(signed, bob["pub"])


# ════════════════════════════════════════════════════════════════════
# Casos borde
# ════════════════════════════════════════════════════════════════════

def test_contenedor_demasiado_corto_falla(alice):
    with pytest.raises(ValueError):
        verify_container(b"corto", alice["pub"])

def test_dos_firmas_del_mismo_contenedor_son_identicas(alice, container):
    """Ed25519 es determinista: misma llave + mismo mensaje = misma firma."""
    s1 = sign_container(container, alice["priv"])
    s2 = sign_container(container, alice["priv"])
    assert s1 == s2

def test_firmas_de_distintos_contenedores_son_distintas(alice):
    c1, _ = encrypt_file(PLAINTEXT, "archivo1.pdf")
    c2, _ = encrypt_file(PLAINTEXT, "archivo2.pdf")
    s1    = sign_container(c1, alice["priv"])
    s2    = sign_container(c2, alice["priv"])
    assert s1 != s2
