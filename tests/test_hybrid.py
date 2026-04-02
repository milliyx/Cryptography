"""
tests/test_hybrid.py
====================
Tests unitarios para el modulo crypto/hybrid.py -- D3 del proyecto SDDV.

Ejecutar con:
    pytest tests/test_hybrid.py -v

Requiere:
    pip install pytest cryptography
"""

import os
import struct

import pytest
from cryptography.exceptions import InvalidTag

from crypto.aead import Algorithm, encrypt_file
from crypto.hybrid import (
    MAGIC_HYBRID,
    NONCE_SIZE,
    RECIPIENT_ENTRY_SIZE,
    TAG_SIZE,
    _parse_hybrid_header,
    decrypt_for_recipient,
    encrypt_for_recipients,
    generate_x25519_keypair,
    get_recipient_fingerprints,
    get_x25519_fingerprint,
    is_hybrid_container,
)

# ───────────────────────── datos de prueba ────────────────────────────────────

SAMPLE_PLAINTEXT = b"Documento confidencial SDDV - prueba de cifrado hibrido D3."
SAMPLE_FILENAME  = "contrato_secreto.pdf"


def make_keypair():
    """Atajo para generar un par de claves X25519."""
    return generate_x25519_keypair()


# =========================================================================
# CASO 1 -- Ciclo cifrado/descifrado basico
# =========================================================================

@pytest.mark.parametrize("algo", [Algorithm.AES_256_GCM, Algorithm.CHACHA20_POLY1305])
def test_roundtrip_un_destinatario(algo):
    """Un unico destinatario puede cifrar y descifrar correctamente."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub], algo=algo)
    recovered, meta = decrypt_for_recipient(container, priv)

    assert recovered == SAMPLE_PLAINTEXT
    assert meta["filename"] == SAMPLE_FILENAME
    assert meta["algo"] == algo


def test_roundtrip_dos_destinatarios_ambos_descifran():
    """
    Con dos destinatarios, AMBOS deben poder descifrar y obtener el mismo plaintext.
    Demuestra que el file_key se envuelve independientemente para cada uno.
    """
    priv1, pub1 = make_keypair()
    priv2, pub2 = make_keypair()

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub1, pub2])

    recovered1, _ = decrypt_for_recipient(container, priv1)
    recovered2, _ = decrypt_for_recipient(container, priv2)

    assert recovered1 == SAMPLE_PLAINTEXT
    assert recovered2 == SAMPLE_PLAINTEXT
    assert recovered1 == recovered2


def test_roundtrip_tres_destinatarios():
    """Tres destinatarios, todos pueden descifrar independientemente."""
    keypairs = [make_keypair() for _ in range(3)]
    pubs = [pub for _, pub in keypairs]

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, pubs)

    for priv, _ in keypairs:
        recovered, _ = decrypt_for_recipient(container, priv)
        assert recovered == SAMPLE_PLAINTEXT


def test_roundtrip_archivo_vacio():
    """El modulo debe manejar archivos de 0 bytes sin errores."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(b"", "empty.bin", [pub])
    recovered, _ = decrypt_for_recipient(container, priv)
    assert recovered == b""


def test_roundtrip_archivo_grande():
    """Verificar con datos de 1 MB."""
    big_data = os.urandom(1024 * 1024)
    priv, pub = make_keypair()
    container = encrypt_for_recipients(big_data, "grande.bin", [pub])
    recovered, _ = decrypt_for_recipient(container, priv)
    assert recovered == big_data


def test_roundtrip_preserva_timestamp():
    """El timestamp que se pasa al cifrar debe recuperarse en los metadatos."""
    ts = 1_700_000_000
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub], timestamp=ts)
    _, meta = decrypt_for_recipient(container, priv)
    assert meta["timestamp"] == ts


def test_roundtrip_filename_unicode():
    """Nombres de archivo con caracteres no ASCII (UTF-8) deben funcionar."""
    filename = "archivo_cifrado_nono_2026.pdf"
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, filename, [pub])
    _, meta = decrypt_for_recipient(container, priv)
    assert meta["filename"] == filename


def test_roundtrip_datos_binarios_arbitrarios():
    """El modulo debe funcionar con cualquier secuencia de bytes."""
    binary_data = bytes(range(256)) * 100
    priv, pub = make_keypair()
    container = encrypt_for_recipients(binary_data, "binario.bin", [pub])
    recovered, _ = decrypt_for_recipient(container, priv)
    assert recovered == binary_data


# =========================================================================
# CASO 2 -- Destinatario no autorizado no puede descifrar
# =========================================================================

def test_destinatario_no_autorizado_lanza_error():
    """
    Un usuario cuya clave no esta en la lista de destinatarios debe recibir
    ValueError indicando que no esta autorizado.
    """
    _, pub_autorizado = make_keypair()
    priv_no_autorizado, _ = make_keypair()

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub_autorizado])

    with pytest.raises(ValueError, match="no esta autorizado"):
        decrypt_for_recipient(container, priv_no_autorizado)


def test_clave_privada_de_tercero_falla():
    """
    La clave privada de un tercero (no en la lista) debe causar rechazo,
    no devolver datos incorrectos silenciosamente.
    """
    _, pub1 = make_keypair()
    priv3, _ = make_keypair()   # par distinto al registrado

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub1])

    with pytest.raises(ValueError, match="no esta autorizado"):
        decrypt_for_recipient(container, priv3)


def test_solo_destinatario_1_no_puede_usar_contenedor_de_destinatario_2():
    """
    Si el contenedor es solo para usuario 2, el usuario 1 no puede descifrar.
    """
    priv1, pub1 = make_keypair()
    _,     pub2 = make_keypair()

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub2])

    with pytest.raises(ValueError, match="no esta autorizado"):
        decrypt_for_recipient(container, priv1)


# =========================================================================
# CASO 3 -- Integridad del contenedor
# =========================================================================

def test_ciphertext_modificado_falla():
    """Modificar el ciphertext debe invalidar el tag AEAD del archivo."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])

    _, header_end = _parse_hybrid_header(container)
    ct_start = header_end + NONCE_SIZE + 4   # header + nonce + ct_len_field

    assert ct_start < len(container) - TAG_SIZE, "No hay ciphertext para modificar"

    tampered = bytearray(container)
    tampered[ct_start] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_for_recipient(bytes(tampered), priv)


def test_tag_modificado_falla():
    """Modificar el tag de autenticacion (ultimos 16 bytes) debe fallar."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    tampered = bytearray(container)
    tampered[-1] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_for_recipient(bytes(tampered), priv)


def test_lista_destinatarios_modificada_falla():
    """
    Modificar la lista de destinatarios en el AAD debe invalidar el tag AEAD.
    Demuestra que la lista esta vinculada criptograficamente al contenido.
    """
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])

    # El fingerprint del destinatario esta en los bytes [header_fixed_end + 2 : +34]
    # header fijo: MAGIC(4)+VER(1)+ALGO(1)+TS(8)+FNAME_LEN(2)+FNAME+RCPT_COUNT(2)
    fname_len = struct.unpack(">H", container[14:16])[0]
    fingerprint_start = 16 + fname_len + 2   # +2 para RECIPIENT_COUNT

    tampered = bytearray(container)
    tampered[fingerprint_start] ^= 0x01   # modificar un bit del fingerprint en AAD
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_for_recipient(bytes(tampered), priv)


def test_eliminar_destinatario_invalida_contenedor():
    """
    Cambiar RECIPIENT_COUNT de 1 a 0 (eliminar logicamente al destinatario)
    debe ser detectado: falla al buscar la entrada o invalida el tag.
    """
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])

    fname_len     = struct.unpack(">H", container[14:16])[0]
    rcpt_count_pos = 16 + fname_len

    tampered = bytearray(container)
    tampered[rcpt_count_pos : rcpt_count_pos + 2] = struct.pack(">H", 0)

    with pytest.raises((InvalidTag, ValueError)):
        decrypt_for_recipient(bytes(tampered), priv)


def test_filename_modificado_falla():
    """Cambiar el filename en el AAD debe invalidar el tag."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, "original.pdf", [pub])

    tampered = bytearray(container)
    tampered[16] ^= 0x01   # primer byte del filename
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_for_recipient(bytes(tampered), priv)


def test_timestamp_modificado_falla():
    """Modificar el timestamp en el AAD debe invalidar el tag."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub], timestamp=1_000_000)

    tampered = bytearray(container)
    tampered[6] ^= 0x01   # byte mas significativo del timestamp
    with pytest.raises((InvalidTag, ValueError)):
        decrypt_for_recipient(bytes(tampered), priv)


def test_magic_bytes_invalidos_falla():
    """Un contenedor con magic bytes incorrectos debe rechazarse antes del AEAD."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    tampered = b"FAKE" + container[4:]
    with pytest.raises(ValueError, match="Magic bytes"):
        decrypt_for_recipient(tampered, priv)


def test_contenedor_truncado_falla():
    """Recortar los ultimos bytes del contenedor debe fallar de forma segura."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    truncated = container[:-20]
    with pytest.raises((ValueError, InvalidTag)):
        decrypt_for_recipient(truncated, priv)


def test_contenedor_con_bytes_extra_falla():
    """Agregar bytes extra al final del contenedor debe detectarse."""
    priv, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    extended = container + b"\x00" * 10
    with pytest.raises(ValueError):
        decrypt_for_recipient(extended, priv)


# =========================================================================
# CASO 4 -- Aleatoriedad y unicidad
# =========================================================================

def test_mismo_plaintext_produce_contenedores_distintos():
    """
    Dos cifrados del mismo plaintext para el mismo destinatario deben producir
    contenedores distintos porque cada cifrado genera nonce y claves efimeras nuevas.
    """
    _, pub = make_keypair()
    c1 = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    c2 = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    assert c1 != c2, "Dos cifrados del mismo archivo produjeron el mismo contenedor"


def test_claves_generadas_son_unicas():
    """generate_x25519_keypair() debe producir pares distintos en cada llamada."""
    fingerprints = set()
    for _ in range(50):
        _, pub = make_keypair()
        fingerprints.add(get_x25519_fingerprint(pub))
    assert len(fingerprints) == 50, "Se detectaron fingerprints repetidos"


def test_nonces_son_unicos_en_50_cifrados():
    """
    50 cifrados consecutivos deben generar nonces DEM distintos.
    Con 96 bits de entropia, la probabilidad de colision es despreciable.
    """
    _, pub = make_keypair()
    nonces = set()
    for _ in range(50):
        container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
        _, header_end = _parse_hybrid_header(container)
        nonce = container[header_end : header_end + NONCE_SIZE]
        nonces.add(nonce)
    assert len(nonces) == 50, "Se detectaron nonces repetidos"


# =========================================================================
# CASO 5 -- Utilidades e inspeccion del contenedor
# =========================================================================

def test_get_recipient_fingerprints_retorna_lista_correcta():
    """get_recipient_fingerprints() retorna los fingerprints en el mismo orden."""
    _, pub1 = make_keypair()
    _, pub2 = make_keypair()
    fp1 = get_x25519_fingerprint(pub1)
    fp2 = get_x25519_fingerprint(pub2)

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub1, pub2])
    fps = get_recipient_fingerprints(container)

    assert set(fps) == {fp1, fp2}
    assert len(fps) == 2


def test_is_hybrid_container_verdadero():
    """is_hybrid_container() retorna True para contenedores SDDH."""
    _, pub = make_keypair()
    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub])
    assert is_hybrid_container(container) is True


def test_is_hybrid_container_falso_para_sddv_clasico():
    """is_hybrid_container() retorna False para contenedores AEAD clasicos (SDDV)."""
    container, _ = encrypt_file(SAMPLE_PLAINTEXT, SAMPLE_FILENAME)
    assert is_hybrid_container(container) is False


def test_is_hybrid_container_falso_para_datos_arbitrarios():
    """is_hybrid_container() retorna False para bytes aleatorios."""
    assert is_hybrid_container(os.urandom(200)) is False


def test_sin_destinatarios_lanza_error():
    """encrypt_for_recipients() con lista vacia debe lanzar ValueError."""
    with pytest.raises(ValueError, match="al menos un destinatario"):
        encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [])


def test_fingerprint_es_hex_de_64_chars():
    """El fingerprint es SHA-256 del raw public key: 64 chars hexadecimales."""
    _, pub = make_keypair()
    fp = get_x25519_fingerprint(pub)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_metadata_contiene_lista_de_destinatarios():
    """Los metadatos retornados por decrypt incluyen la lista de destinatarios."""
    priv1, pub1 = make_keypair()
    priv2, pub2 = make_keypair()
    fp1 = get_x25519_fingerprint(pub1)
    fp2 = get_x25519_fingerprint(pub2)

    container = encrypt_for_recipients(SAMPLE_PLAINTEXT, SAMPLE_FILENAME, [pub1, pub2])
    _, meta = decrypt_for_recipient(container, priv1)

    fps_in_meta = {e["fingerprint"] for e in meta["recipients"]}
    assert fp1 in fps_in_meta
    assert fp2 in fps_in_meta
    assert len(meta["recipients"]) == 2
