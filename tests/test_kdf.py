"""
tests/test_kdf.py
=================
Tests del KDF (scrypt) del keystore D6.

Cubre:
  - generate_salt() es aleatorio y del tamano correcto
  - derive_key es deterministico con (password, salt, params) fijos
  - derive_key cambia si cualquier entrada cambia
  - validate_params atrapa parametros invalidos
"""

import pytest

from crypto import kdf
from crypto.kdf import (
    DEFAULT_KDF_PARAMS,
    SALT_SIZE,
    derive_key,
    generate_salt,
    validate_params,
)


# Parametros pequenos solo para velocidad de tests; produccion usa DEFAULT.
FAST_PARAMS = {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}
PASSWORD = "passwordSeguro_UNAM_2026!"


# ── generate_salt ─────────────────────────────────────────────────────────────

def test_generate_salt_devuelve_bytes_del_tamano_correcto():
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == SALT_SIZE


def test_generate_salt_es_aleatorio():
    """100 salts consecutivos no deberian coincidir."""
    salts = {generate_salt() for _ in range(100)}
    assert len(salts) == 100


# ── derive_key: determinismo y dependencias ───────────────────────────────────

def test_derive_key_es_deterministico_con_mismas_entradas():
    salt = generate_salt()
    k1 = derive_key(PASSWORD, salt, FAST_PARAMS)
    k2 = derive_key(PASSWORD, salt, FAST_PARAMS)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_cambia_con_salt_distinto():
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert derive_key(PASSWORD, salt1, FAST_PARAMS) != derive_key(PASSWORD, salt2, FAST_PARAMS)


def test_derive_key_cambia_con_password_distinto():
    salt = generate_salt()
    k1 = derive_key(PASSWORD, salt, FAST_PARAMS)
    k2 = derive_key(PASSWORD + "!", salt, FAST_PARAMS)
    assert k1 != k2


def test_derive_key_cambia_con_parametros_distintos():
    salt = generate_salt()
    k1 = derive_key(PASSWORD, salt, FAST_PARAMS)
    other = dict(FAST_PARAMS, n=2 ** 11)
    k2 = derive_key(PASSWORD, salt, other)
    assert k1 != k2


def test_derive_key_default_params_produce_32_bytes():
    """Sanity: parametros de produccion -- usamos un salt fijo solo para
    no medir tiempos exactos. No comparamos con un vector conocido porque
    scrypt no tiene RFC test vectors universales para estos parametros."""
    salt = b"\x00" * SALT_SIZE
    k = derive_key("X" * 16, salt, DEFAULT_KDF_PARAMS)
    assert len(k) == 32


# ── derive_key: errores de entrada ────────────────────────────────────────────

def test_derive_key_rechaza_password_no_string():
    with pytest.raises(ValueError, match="password"):
        derive_key(123, generate_salt(), FAST_PARAMS)


def test_derive_key_rechaza_salt_no_bytes():
    with pytest.raises(ValueError, match="salt"):
        derive_key(PASSWORD, "no soy bytes", FAST_PARAMS)


def test_derive_key_rechaza_salt_demasiado_corto():
    with pytest.raises(ValueError, match="salt"):
        derive_key(PASSWORD, b"abc", FAST_PARAMS)


# ── validate_params ───────────────────────────────────────────────────────────

def test_validate_params_acepta_default():
    validate_params(DEFAULT_KDF_PARAMS)
    validate_params(FAST_PARAMS)


@pytest.mark.parametrize("bad_key", ["n", "r", "p", "dklen"])
def test_validate_params_rechaza_clave_faltante(bad_key):
    params = dict(FAST_PARAMS)
    del params[bad_key]
    with pytest.raises(ValueError, match=bad_key):
        validate_params(params)


def test_validate_params_rechaza_no_dict():
    with pytest.raises(ValueError, match="dict"):
        validate_params("no soy dict")


def test_validate_params_rechaza_n_no_potencia_de_2():
    params = dict(FAST_PARAMS, n=1000)
    with pytest.raises(ValueError, match="potencia de 2"):
        validate_params(params)


def test_validate_params_rechaza_n_uno_o_cero():
    for bad_n in (0, 1):
        with pytest.raises(ValueError, match="potencia de 2"):
            validate_params(dict(FAST_PARAMS, n=bad_n))


@pytest.mark.parametrize("field", ["r", "p"])
def test_validate_params_rechaza_r_p_no_positivos(field):
    with pytest.raises(ValueError, match=f"{field} debe ser > 0"):
        validate_params(dict(FAST_PARAMS, **{field: 0}))


def test_validate_params_rechaza_dklen_distinto_de_32():
    with pytest.raises(ValueError, match="dklen debe ser 32"):
        validate_params(dict(FAST_PARAMS, dklen=16))


def test_validate_params_rechaza_tipo_no_int():
    with pytest.raises(ValueError, match="int"):
        validate_params(dict(FAST_PARAMS, n="32768"))


# ── propiedades adicionales ───────────────────────────────────────────────────

def test_derive_key_produce_bytes_no_str():
    """Sanity: scrypt retorna bytes. Critico porque AES-GCM recibe bytes."""
    k = derive_key(PASSWORD, generate_salt(), FAST_PARAMS)
    assert isinstance(k, bytes)


def test_default_kdf_params_tiene_estructura_esperada():
    assert set(DEFAULT_KDF_PARAMS) == {"n", "r", "p", "dklen"}
    assert DEFAULT_KDF_PARAMS["dklen"] == 32
    # n debe ser potencia de 2 razonable (>= 2**14 segun OWASP 2024)
    assert DEFAULT_KDF_PARAMS["n"] >= 2 ** 14
