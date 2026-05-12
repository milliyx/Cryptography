"""
tests/test_keystore_format.py
=============================
Tests del envelope AEAD y del esquema JSON v1 del keystore D6.

Cubre:
  - encrypt/decrypt private bundle: roundtrip y deteccion de manipulaciones
  - build_keystore_dict produce un JSON v1 con todos los campos requeridos
  - validate_keystore_schema atrapa estructuras invalidas
  - unlock_keystore_dict: pipeline completo (validar + derivar + descifrar)
"""

import base64
import copy
import json

import pytest
from cryptography.exceptions import InvalidTag

from crypto.kdf import generate_salt, derive_key
from crypto.keystore_format import (
    KEYSTORE_VERSION,
    ENVELOPE_NONCE_SIZE,
    ENVELOPE_TAG_SIZE,
    build_keystore_dict,
    decrypt_private_bundle,
    encrypt_private_bundle,
    unlock_keystore_dict,
    validate_keystore_schema,
)
from crypto.keys import generate_keypair as generate_ed25519_keypair
from crypto.hybrid import generate_x25519_keypair


# Parametros pequenos para velocidad de tests (n=2**10 ~ instantaneo).
FAST_PARAMS = {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}
PASSWORD = "passwordSeguro_UNAM_2026!"


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ed25519_keypair():
    return generate_ed25519_keypair()


@pytest.fixture
def x25519_keypair():
    return generate_x25519_keypair()


@pytest.fixture
def derived_key():
    salt = generate_salt()
    return derive_key(PASSWORD, salt, FAST_PARAMS), salt


@pytest.fixture
def fresh_keystore_dict(ed25519_keypair, x25519_keypair):
    """Un dict JSON v1 valido recien construido (usado en muchos tests)."""
    ed_priv, _ = ed25519_keypair
    x_priv,  _ = x25519_keypair
    salt = generate_salt()
    dk   = derive_key(PASSWORD, salt, FAST_PARAMS)
    return build_keystore_dict(
        name="alice",
        ed25519_priv=ed_priv,
        x25519_priv=x_priv,
        derived_key=dk,
        salt=salt,
        kdf_params=FAST_PARAMS,
    )


# ── envelope AEAD: roundtrip ──────────────────────────────────────────────────

def test_envelope_roundtrip_bundle_simple(derived_key):
    dk, _ = derived_key
    plaintext = b'{"ed25519_priv_b64":"AAA="}'
    nonce, ct, tag = encrypt_private_bundle(plaintext, dk)
    assert len(nonce) == ENVELOPE_NONCE_SIZE
    assert len(tag)   == ENVELOPE_TAG_SIZE
    assert ct != plaintext  # algo se cifro
    recovered = decrypt_private_bundle(ct, nonce, tag, dk)
    assert recovered == plaintext


def test_envelope_dos_cifrados_mismo_plaintext_difieren(derived_key):
    """Nonce fresco por llamada -> ciphertext distinto cada vez."""
    dk, _ = derived_key
    plaintext = b"hola"
    n1, c1, t1 = encrypt_private_bundle(plaintext, dk)
    n2, c2, t2 = encrypt_private_bundle(plaintext, dk)
    assert n1 != n2 and (c1, t1) != (c2, t2)


def test_envelope_descifrar_con_clave_incorrecta_lanza_InvalidTag(derived_key):
    dk, _ = derived_key
    bad_dk = bytes(b ^ 0xFF for b in dk)
    nonce, ct, tag = encrypt_private_bundle(b"x" * 64, dk)
    with pytest.raises(InvalidTag):
        decrypt_private_bundle(ct, nonce, tag, bad_dk)


def test_envelope_descifrar_con_nonce_modificado_lanza_InvalidTag(derived_key):
    dk, _ = derived_key
    nonce, ct, tag = encrypt_private_bundle(b"x" * 64, dk)
    tampered_nonce = bytearray(nonce); tampered_nonce[0] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_private_bundle(ct, bytes(tampered_nonce), tag, dk)


def test_envelope_descifrar_con_tag_modificado_lanza_InvalidTag(derived_key):
    dk, _ = derived_key
    nonce, ct, tag = encrypt_private_bundle(b"x" * 64, dk)
    tampered_tag = bytearray(tag); tampered_tag[0] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_private_bundle(ct, nonce, bytes(tampered_tag), dk)


def test_envelope_descifrar_con_ciphertext_modificado_lanza_InvalidTag(derived_key):
    dk, _ = derived_key
    nonce, ct, tag = encrypt_private_bundle(b"x" * 64, dk)
    tampered_ct = bytearray(ct); tampered_ct[0] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_private_bundle(bytes(tampered_ct), nonce, tag, dk)


def test_envelope_rechaza_derived_key_tamano_incorrecto():
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt_private_bundle(b"hi", b"\x00" * 31)
    with pytest.raises(ValueError, match="32 bytes"):
        decrypt_private_bundle(b"", b"\x00" * 12, b"\x00" * 16, b"\x00" * 31)


# ── build_keystore_dict: estructura del JSON v1 ───────────────────────────────

def test_build_keystore_dict_estructura_v1(fresh_keystore_dict):
    d = fresh_keystore_dict
    assert d["version"] == KEYSTORE_VERSION
    assert d["name"] == "alice"
    assert d["status"] == "active"
    assert set(d.keys()) >= {
        "version", "name", "created_at", "status",
        "kdf", "encryption", "encrypted_private_key",
        "public_keys", "fingerprints", "metadata",
    }


def test_build_keystore_dict_kdf_block(fresh_keystore_dict):
    kdf_block = fresh_keystore_dict["kdf"]
    assert kdf_block["algorithm"] == "scrypt"
    assert kdf_block["n"] == FAST_PARAMS["n"]
    assert kdf_block["r"] == FAST_PARAMS["r"]
    assert kdf_block["p"] == FAST_PARAMS["p"]
    assert kdf_block["dklen"] == 32
    # salt es base64 valido
    assert base64.b64decode(kdf_block["salt_b64"])


def test_build_keystore_dict_encryption_block(fresh_keystore_dict):
    enc = fresh_keystore_dict["encryption"]
    assert enc["algorithm"] == "AES-256-GCM"
    assert len(base64.b64decode(enc["nonce_b64"])) == ENVELOPE_NONCE_SIZE
    assert len(base64.b64decode(enc["tag_b64"]))   == ENVELOPE_TAG_SIZE


def test_build_keystore_dict_no_contiene_plaintext_de_la_privada(
    fresh_keystore_dict, ed25519_keypair
):
    """La privada raw nunca debe aparecer en el JSON serializado."""
    ed_priv, _ = ed25519_keypair
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption,
    )
    raw = ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    serialized = json.dumps(fresh_keystore_dict).encode("utf-8")
    assert raw not in serialized
    # tampoco el base64 de la privada raw
    raw_b64 = base64.b64encode(raw)
    assert raw_b64 not in serialized


def test_build_keystore_dict_fingerprints_son_hex_64(fresh_keystore_dict):
    fps = fresh_keystore_dict["fingerprints"]
    assert "ed25519" in fps and "x25519" in fps
    for v in fps.values():
        assert len(v) == 64
        assert all(c in "0123456789abcdef" for c in v)


def test_build_keystore_dict_sin_x25519(ed25519_keypair):
    """Si no se pasa X25519, el dict no debe tener x25519_pub ni fingerprint."""
    ed_priv, _ = ed25519_keypair
    salt = generate_salt()
    dk = derive_key(PASSWORD, salt, FAST_PARAMS)
    d = build_keystore_dict(
        name="solo-firma", ed25519_priv=ed_priv, x25519_priv=None,
        derived_key=dk, salt=salt, kdf_params=FAST_PARAMS,
    )
    assert "x25519_pub_b64" not in d["public_keys"]
    assert "x25519" not in d["fingerprints"]


def test_build_keystore_dict_rechaza_status_invalido(ed25519_keypair):
    ed_priv, _ = ed25519_keypair
    salt = generate_salt()
    dk = derive_key(PASSWORD, salt, FAST_PARAMS)
    with pytest.raises(ValueError, match="status"):
        build_keystore_dict(
            name="alice", ed25519_priv=ed_priv, x25519_priv=None,
            derived_key=dk, salt=salt, kdf_params=FAST_PARAMS,
            status="cosa-rara",
        )


# ── validate_keystore_schema ──────────────────────────────────────────────────

def test_validate_keystore_schema_acepta_dict_valido(fresh_keystore_dict):
    validate_keystore_schema(fresh_keystore_dict)


@pytest.mark.parametrize("missing_key", [
    "version", "name", "kdf", "encryption", "encrypted_private_key",
    "public_keys", "fingerprints", "metadata",
])
def test_validate_keystore_schema_rechaza_clave_top_faltante(
    fresh_keystore_dict, missing_key
):
    bad = copy.deepcopy(fresh_keystore_dict)
    del bad[missing_key]
    with pytest.raises(ValueError, match="faltan"):
        validate_keystore_schema(bad)


def test_validate_keystore_schema_rechaza_version_distinta(fresh_keystore_dict):
    bad = copy.deepcopy(fresh_keystore_dict)
    bad["version"] = 999
    with pytest.raises(ValueError, match="version"):
        validate_keystore_schema(bad)


def test_validate_keystore_schema_rechaza_kdf_algorithm_desconocido(fresh_keystore_dict):
    bad = copy.deepcopy(fresh_keystore_dict)
    bad["kdf"]["algorithm"] = "pbkdf2"
    with pytest.raises(ValueError, match="algoritmo no soportado"):
        validate_keystore_schema(bad)


def test_validate_keystore_schema_rechaza_encryption_algorithm_desconocido(
    fresh_keystore_dict
):
    bad = copy.deepcopy(fresh_keystore_dict)
    bad["encryption"]["algorithm"] = "AES-256-CBC"
    with pytest.raises(ValueError, match="algoritmo no soportado"):
        validate_keystore_schema(bad)


def test_validate_keystore_schema_rechaza_status_invalido(fresh_keystore_dict):
    bad = copy.deepcopy(fresh_keystore_dict)
    bad["status"] = "que-status?"
    with pytest.raises(ValueError, match="status"):
        validate_keystore_schema(bad)


def test_validate_keystore_schema_rechaza_no_dict():
    with pytest.raises(ValueError, match="objeto JSON"):
        validate_keystore_schema("no soy dict")


# ── unlock_keystore_dict: pipeline completo ───────────────────────────────────

def test_unlock_keystore_dict_roundtrip_recupera_llaves(fresh_keystore_dict, ed25519_keypair, x25519_keypair):
    ed_priv_recovered, x_priv_recovered = unlock_keystore_dict(
        fresh_keystore_dict, PASSWORD,
    )
    # Comparamos por bytes raw (los objetos no implementan __eq__)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption,
    )
    ed_orig, _ = ed25519_keypair
    x_orig,  _ = x25519_keypair
    assert ed_priv_recovered.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) == \
           ed_orig.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    assert x_priv_recovered.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) == \
           x_orig.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def test_unlock_keystore_dict_password_incorrecto_lanza_InvalidTag(fresh_keystore_dict):
    with pytest.raises(InvalidTag):
        unlock_keystore_dict(fresh_keystore_dict, "password-equivocado!!")


def test_unlock_keystore_dict_dict_modificado_lanza_InvalidTag(fresh_keystore_dict):
    """Manipular el ciphertext base64 invalida el tag."""
    bad = copy.deepcopy(fresh_keystore_dict)
    ct_raw = base64.b64decode(bad["encrypted_private_key"])
    ct_raw = bytearray(ct_raw); ct_raw[0] ^= 0xFF
    bad["encrypted_private_key"] = base64.b64encode(bytes(ct_raw)).decode("ascii")
    with pytest.raises(InvalidTag):
        unlock_keystore_dict(bad, PASSWORD)


def test_unlock_keystore_dict_salt_modificado_lanza_InvalidTag(fresh_keystore_dict):
    """Cambiar el salt cambia la clave derivada -> InvalidTag."""
    bad = copy.deepcopy(fresh_keystore_dict)
    salt = bytearray(base64.b64decode(bad["kdf"]["salt_b64"])); salt[0] ^= 0xFF
    bad["kdf"]["salt_b64"] = base64.b64encode(bytes(salt)).decode("ascii")
    with pytest.raises(InvalidTag):
        unlock_keystore_dict(bad, PASSWORD)


def test_unlock_keystore_dict_solo_ed25519(ed25519_keypair):
    """Identidad sin X25519 retorna (Ed25519PrivateKey, None)."""
    ed_priv, _ = ed25519_keypair
    salt = generate_salt()
    dk = derive_key(PASSWORD, salt, FAST_PARAMS)
    d = build_keystore_dict(
        name="solo-firma", ed25519_priv=ed_priv, x25519_priv=None,
        derived_key=dk, salt=salt, kdf_params=FAST_PARAMS,
    )
    ed_rec, x_rec = unlock_keystore_dict(d, PASSWORD)
    assert ed_rec is not None
    assert x_rec is None
