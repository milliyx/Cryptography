"""
tests/test_d4_hybrid_signed.py
==============================
Tests del entregable D4 — firma digital sobre contenedores hibridos (SDDH).

Cubre los escenarios obligatorios del rubric D4:
    1. Firma valida -> archivo aceptado
    2. Ciphertext modificado -> rechazado
    3. Metadata modificada -> rechazado (filename, timestamp, algo)
    4. Lista de destinatarios modificada -> rechazado
    5. Llave publica incorrecta -> rechazado
    6. Firma eliminada -> rechazado
    7. Re-firmado por un atacante -> el verificador original lo rechaza

Mas tests de defensa en profundidad:
    8. Flujo Alice firma -> Bob y Carol descifran
    9. No-destinatario no puede descifrar aunque la firma sea valida
   10. Verificar antes de descifrar (orden correcto)
   11. Casos borde sobre el contenedor firmado

Ejecutar con:
    pytest tests/test_d4_hybrid_signed.py -v
"""

import struct

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from crypto.aead import Algorithm
from crypto.hybrid import (
    NONCE_SIZE,
    TAG_SIZE,
    _parse_hybrid_header,
    decrypt_for_recipient,
    encrypt_for_recipients,
    generate_x25519_keypair,
)
from crypto.keys import generate_keypair, get_fingerprint
from crypto.signatures import (
    SIGN_FOOTER_SIZE,
    SIGN_MAGIC,
    get_signer_fingerprint,
    is_signed,
    sign_hybrid_container,
    verify_hybrid_container,
)
from crypto.secure_send import (
    secure_encrypt_and_sign,
    secure_verify_and_decrypt,
)


# ─────────────────────────── datos de prueba ─────────────────────────────────

PLAINTEXT = b"Documento confidencial UNAM 2026-2 - prueba D4 firma + cifrado hibrido."
FILENAME  = "expediente_secreto.pdf"


# ─────────────────────────── fixtures ────────────────────────────────────────

@pytest.fixture
def alice():
    """Firmante Ed25519."""
    priv, pub = generate_keypair()
    return {"priv": priv, "pub": pub, "fp": get_fingerprint(pub)}


@pytest.fixture
def eve():
    """Atacante con llaves Ed25519 propias."""
    priv, pub = generate_keypair()
    return {"priv": priv, "pub": pub, "fp": get_fingerprint(pub)}


@pytest.fixture
def bob_x25519():
    """Destinatario X25519."""
    priv, pub = generate_x25519_keypair()
    return {"priv": priv, "pub": pub}


@pytest.fixture
def carol_x25519():
    """Otro destinatario X25519."""
    priv, pub = generate_x25519_keypair()
    return {"priv": priv, "pub": pub}


@pytest.fixture
def mallory_x25519():
    """Tercero no autorizado."""
    priv, pub = generate_x25519_keypair()
    return {"priv": priv, "pub": pub}


@pytest.fixture
def signed_sddh(alice, bob_x25519, carol_x25519):
    """Contenedor SDDH firmado por Alice para Bob y Carol."""
    return secure_encrypt_and_sign(
        plaintext=PLAINTEXT,
        filename=FILENAME,
        recipients=[bob_x25519["pub"], carol_x25519["pub"]],
        signer_priv=alice["priv"],
    )


# ════════════════════════════════════════════════════════════════════════════
# CASO 1 — Firma valida -> archivo aceptado
# ════════════════════════════════════════════════════════════════════════════

def test_firma_valida_sobre_sddh_aceptada(alice, bob_x25519, signed_sddh):
    """El flujo completo D4 debe recuperar el plaintext original sin error."""
    plaintext, metadata = secure_verify_and_decrypt(
        signed_sddh,
        expected_signer_pub=alice["pub"],
        recipient_priv=bob_x25519["priv"],
    )
    assert plaintext == PLAINTEXT
    assert metadata["filename"] == FILENAME


def test_firma_valida_carol_tambien_descifra(alice, carol_x25519, signed_sddh):
    """El segundo destinatario tambien puede verificar y descifrar."""
    plaintext, _ = secure_verify_and_decrypt(
        signed_sddh,
        expected_signer_pub=alice["pub"],
        recipient_priv=carol_x25519["priv"],
    )
    assert plaintext == PLAINTEXT


def test_signer_fingerprint_extraible_sin_verificar(signed_sddh, alice):
    """get_signer_fingerprint expone la identidad sin verificar la firma."""
    fp = get_signer_fingerprint(signed_sddh)
    assert fp == alice["fp"]


def test_is_signed_detecta_firma_en_sddh(signed_sddh, bob_x25519):
    """is_signed reconoce un SDDH firmado y rechaza uno sin firmar."""
    assert is_signed(signed_sddh) is True
    sin_firmar = encrypt_for_recipients(PLAINTEXT, FILENAME, [bob_x25519["pub"]])
    assert is_signed(sin_firmar) is False


# ════════════════════════════════════════════════════════════════════════════
# CASO 2 — Ciphertext modificado -> rechazado
# ════════════════════════════════════════════════════════════════════════════

def test_ciphertext_modificado_invalida_firma(alice, bob_x25519, signed_sddh):
    """
    Modificar 1 byte del ciphertext debe ser detectado por la firma Ed25519
    (la firma cubre el SDDH completo, incluyendo el ciphertext).
    """
    sddh_only = signed_sddh[:-SIGN_FOOTER_SIZE]
    _, header_end = _parse_hybrid_header(sddh_only)
    ct_start = header_end + NONCE_SIZE + 4

    tampered = bytearray(signed_sddh)
    tampered[ct_start] ^= 0xFF

    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


def test_ciphertext_modificado_secure_flow_rechaza(alice, bob_x25519, signed_sddh):
    """El flujo combinado tambien rechaza ciphertext manipulado."""
    sddh_only = signed_sddh[:-SIGN_FOOTER_SIZE]
    _, header_end = _parse_hybrid_header(sddh_only)
    ct_start = header_end + NONCE_SIZE + 4

    tampered = bytearray(signed_sddh)
    tampered[ct_start] ^= 0xFF

    with pytest.raises(InvalidSignature):
        secure_verify_and_decrypt(
            bytes(tampered),
            expected_signer_pub=alice["pub"],
            recipient_priv=bob_x25519["priv"],
        )


def test_tag_aead_modificado_invalida_firma(alice, signed_sddh):
    """El tag AEAD esta antes del footer de firma; modificarlo invalida la firma."""
    tag_pos = len(signed_sddh) - SIGN_FOOTER_SIZE - 1   # ultimo byte del tag AEAD

    tampered = bytearray(signed_sddh)
    tampered[tag_pos] ^= 0x01

    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


# ════════════════════════════════════════════════════════════════════════════
# CASO 3 — Metadata modificada -> rechazado
# ════════════════════════════════════════════════════════════════════════════

def test_filename_modificado_invalida_firma(alice, signed_sddh):
    """Cambiar 1 byte del filename (en el AAD del SDDH) debe rechazarse."""
    tampered = bytearray(signed_sddh)
    tampered[16] ^= 0x01   # primer byte del filename
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


def test_timestamp_modificado_invalida_firma(alice, signed_sddh):
    """Cambiar el timestamp (parte de la cabecera/AAD) debe rechazarse."""
    tampered = bytearray(signed_sddh)
    tampered[6] ^= 0x01   # byte mas significativo del timestamp
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


def test_algo_id_modificado_invalida_firma(alice, signed_sddh):
    """Cambiar el byte del algoritmo en la cabecera debe rechazarse."""
    tampered = bytearray(signed_sddh)
    tampered[5] = 0x02 if tampered[5] == 0x01 else 0x01
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


def test_magic_bytes_invalidos_rechazado(alice, signed_sddh):
    """Cambiar el magic SDDH desincronizar y debe rechazarse."""
    tampered = bytearray(signed_sddh)
    tampered[:4] = b"FAKE"
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


# ════════════════════════════════════════════════════════════════════════════
# CASO 4 — Lista de destinatarios modificada -> rechazado
# ════════════════════════════════════════════════════════════════════════════

def test_lista_destinatarios_modificada_invalida_firma(alice, signed_sddh):
    """
    Cambiar 1 bit en el fingerprint de un destinatario (dentro del AAD)
    debe ser detectado por la firma sobre el SDDH completo.
    """
    fname_len = struct.unpack(">H", signed_sddh[14:16])[0]
    fp_start = 16 + fname_len + 2   # +2 por RECIPIENT_COUNT
    tampered = bytearray(signed_sddh)
    tampered[fp_start] ^= 0x01
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


def test_recipient_count_modificado_invalida_firma(alice, signed_sddh):
    """
    Cambiar RECIPIENT_COUNT (de 2 a 1, "eliminando" a Carol) debe detectarse.
    """
    fname_len = struct.unpack(">H", signed_sddh[14:16])[0]
    rcpt_pos  = 16 + fname_len
    tampered  = bytearray(signed_sddh)
    tampered[rcpt_pos:rcpt_pos + 2] = struct.pack(">H", 1)   # de 2 a 1
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


def test_eph_pub_modificado_invalida_firma(alice, signed_sddh):
    """
    El eph_pub de un destinatario tambien esta en el AAD del SDDH y por tanto
    bajo la firma. Modificarlo debe rechazarse.
    """
    fname_len = struct.unpack(">H", signed_sddh[14:16])[0]
    # primer destinatario empieza en 16 + fname_len + 2 (recipient_count)
    # fingerprint(32) + eph_pub(32) — modificar un byte de eph_pub
    eph_pub_offset = 16 + fname_len + 2 + 32
    tampered = bytearray(signed_sddh)
    tampered[eph_pub_offset] ^= 0x01
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(bytes(tampered), alice["pub"])


# ════════════════════════════════════════════════════════════════════════════
# CASO 5 — Llave publica incorrecta -> rechazado
# ════════════════════════════════════════════════════════════════════════════

def test_verificar_con_llave_de_eve_falla(eve, signed_sddh):
    """
    El contenedor lo firmo Alice; verificar con la pubkey de Eve debe fallar
    (los fingerprints no coinciden, no se llega a verificar la firma).
    """
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(signed_sddh, eve["pub"])


def test_verificar_con_llave_recien_generada_falla(signed_sddh):
    """Una llave Ed25519 recien generada no debe verificar nada previo."""
    _, nueva_pub = generate_keypair()
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(signed_sddh, nueva_pub)


def test_secure_flow_con_llave_incorrecta_no_descifra(eve, bob_x25519, signed_sddh):
    """El flujo combinado falla en verify ANTES de invocar decrypt."""
    with pytest.raises(InvalidSignature):
        secure_verify_and_decrypt(
            signed_sddh,
            expected_signer_pub=eve["pub"],
            recipient_priv=bob_x25519["priv"],
        )


# ════════════════════════════════════════════════════════════════════════════
# CASO 6 — Firma eliminada -> rechazado
# ════════════════════════════════════════════════════════════════════════════

def test_footer_de_firma_eliminado_falla(alice, signed_sddh):
    """Un SDDH sin el footer de firma no debe pasar verify."""
    sin_firma = signed_sddh[:-SIGN_FOOTER_SIZE]
    with pytest.raises(ValueError):
        verify_hybrid_container(sin_firma, alice["pub"])


def test_firma_truncada_falla(alice, signed_sddh):
    """Truncar la firma a la mitad debe rechazarse."""
    truncado = signed_sddh[:-32]   # cortar 32 bytes de la firma de 64
    with pytest.raises((InvalidSignature, ValueError)):
        verify_hybrid_container(truncado, alice["pub"])


def test_solo_magic_sin_firma_falla(alice, bob_x25519):
    """
    Un atacante podria intentar pegar SIGN_MAGIC al final esperando que
    is_signed retorne True. verify debe rechazarlo de todas formas.
    """
    sddh = encrypt_for_recipients(PLAINTEXT, FILENAME, [bob_x25519["pub"]])
    fake = sddh + SIGN_MAGIC + bytes(32 + 64)   # magic + ceros
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(fake, alice["pub"])


# ════════════════════════════════════════════════════════════════════════════
# CASO 7 — Re-firmado por atacante -> el verificador original rechaza
# ════════════════════════════════════════════════════════════════════════════

def test_eve_no_puede_resignar_haciendose_pasar_por_alice(alice, eve, bob_x25519, signed_sddh):
    """
    Eve toma el SDDH publico de Alice, le quita el footer de firma de Alice
    y firma con SU llave. Bob, que esperaba a Alice, debe rechazarlo porque
    el fingerprint del footer ya no coincide con la pubkey de Alice.
    """
    sddh_only = signed_sddh[:-SIGN_FOOTER_SIZE]
    re_firmado_por_eve = sign_hybrid_container(sddh_only, eve["priv"])

    # Bob esperaba a Alice -> rechazo
    with pytest.raises(InvalidSignature):
        verify_hybrid_container(re_firmado_por_eve, alice["pub"])

    # Confirmar que el footer DICE que es de Eve (no se "convirtio en Alice")
    fp_en_footer = get_signer_fingerprint(re_firmado_por_eve)
    assert fp_en_footer == eve["fp"]
    assert fp_en_footer != alice["fp"]


def test_eve_resignado_si_pasa_verify_con_pubkey_de_eve(eve, bob_x25519, signed_sddh):
    """
    Coda al test anterior: si Bob aceptara verificar con la pubkey de Eve,
    el contenedor re-firmado por Eve si pasaria. La defensa esta en que Bob
    decide a priori que firmante espera (Alice), no en aceptar a quien sea.
    """
    sddh_only = signed_sddh[:-SIGN_FOOTER_SIZE]
    re_firmado_por_eve = sign_hybrid_container(sddh_only, eve["priv"])

    # Si Bob conoce y espera a Eve, la firma de Eve verifica correctamente
    sddh_recuperado = verify_hybrid_container(re_firmado_por_eve, eve["pub"])
    assert sddh_recuperado == sddh_only


# ════════════════════════════════════════════════════════════════════════════
# CASOS 8-11 — Defensa en profundidad
# ════════════════════════════════════════════════════════════════════════════

def test_no_destinatario_no_descifra_aunque_firma_valida(
    alice, bob_x25519, mallory_x25519, signed_sddh
):
    """
    Mallory tiene la pubkey de Alice (puede verificar la firma) pero no esta
    en la lista de destinatarios. La verificacion pasa, el descifrado falla.
    Esto demuestra que firma y acceso son capas independientes.
    """
    with pytest.raises(ValueError, match="no esta autorizado"):
        secure_verify_and_decrypt(
            signed_sddh,
            expected_signer_pub=alice["pub"],
            recipient_priv=mallory_x25519["priv"],
        )


def test_orden_correcto_verify_falla_antes_de_decrypt(eve, bob_x25519, signed_sddh):
    """
    Si la firma falla, la funcion combinada no debe llegar a decrypt.
    Aqui verificamos que el error es InvalidSignature, no InvalidTag o algo
    relacionado con descifrado — eso confirma que el orden es correcto.
    """
    with pytest.raises(InvalidSignature):
        secure_verify_and_decrypt(
            signed_sddh,
            expected_signer_pub=eve["pub"],
            recipient_priv=bob_x25519["priv"],
        )


def test_ed25519_firma_es_determinista(alice, bob_x25519):
    """
    Ed25519 es determinista: misma llave + mismo SDDH -> misma firma.
    Lo verificamos sobre el contenedor completo. (El SDDH cambia entre
    invocaciones por el nonce/ephemeral, asi que aqui lo fijamos.)
    """
    sddh = encrypt_for_recipients(PLAINTEXT, FILENAME, [bob_x25519["pub"]])
    s1 = sign_hybrid_container(sddh, alice["priv"])
    s2 = sign_hybrid_container(sddh, alice["priv"])
    assert s1 == s2


def test_chacha20_tambien_funciona_con_firma(alice, bob_x25519):
    """El flujo D4 funciona tanto con AES-GCM como con ChaCha20-Poly1305."""
    signed = secure_encrypt_and_sign(
        plaintext=PLAINTEXT,
        filename=FILENAME,
        recipients=[bob_x25519["pub"]],
        signer_priv=alice["priv"],
        algo=Algorithm.CHACHA20_POLY1305,
    )
    plaintext, meta = secure_verify_and_decrypt(
        signed,
        expected_signer_pub=alice["pub"],
        recipient_priv=bob_x25519["priv"],
    )
    assert plaintext == PLAINTEXT
    assert meta["algo"] == Algorithm.CHACHA20_POLY1305


def test_archivo_grande_1mb_con_firma(alice, bob_x25519):
    """Archivos de 1 MB tambien deben firmarse y verificarse correctamente."""
    import os
    big = os.urandom(1024 * 1024)
    signed = secure_encrypt_and_sign(
        plaintext=big,
        filename="grande.bin",
        recipients=[bob_x25519["pub"]],
        signer_priv=alice["priv"],
    )
    recovered, _ = secure_verify_and_decrypt(
        signed, alice["pub"], bob_x25519["priv"]
    )
    assert recovered == big


def test_overhead_firma_es_exactamente_100_bytes(alice, bob_x25519):
    """El footer de firma anade exactamente SIGN_FOOTER_SIZE bytes (100)."""
    sddh = encrypt_for_recipients(PLAINTEXT, FILENAME, [bob_x25519["pub"]])
    signed = sign_hybrid_container(sddh, alice["priv"])
    assert len(signed) == len(sddh) + SIGN_FOOTER_SIZE
    assert SIGN_FOOTER_SIZE == 100
