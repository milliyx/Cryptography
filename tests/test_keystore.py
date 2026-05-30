"""
tests/test_keystore.py
======================
Tests de la KeyStore API (D6 Fase 2).

Cubre:
  - init_identity persiste un JSON v1, no plaintext de la privada
  - exists / list_identities / get_public_keys (sin password)
  - unlock_signing_key / unlock_encryption_key con password correcto
  - rechazo con password incorrecto, keystore modificado, identidad no
    encontrada
  - unlock NO cachea (cada llamada re-deriva)

Los tests usan parametros KDF rapidos (n=2**10) para velocidad. La logica
es la misma; solo se reduce el costo de scrypt.
"""

import base64
import copy
import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from src.keystore import (
    IdentityAlreadyExistsError,
    IdentityNotFoundError,
    KeyStore,
    KeyStoreError,
)


FAST_PARAMS = {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}
PASSWORD       = "passwordSeguro_UNAM_2026!"
WRONG_PASSWORD = "password-equivocado-12345!"


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def ks(tmp_path):
    """KeyStore fresca en directorio temporal con KDF rapido."""
    return KeyStore(tmp_path / "keystore", kdf_params=FAST_PARAMS)


@pytest.fixture
def ks_alice(ks):
    """KeyStore con una identidad 'alice' ya creada."""
    ks.init_identity("alice", PASSWORD)
    return ks


# ── creacion ──────────────────────────────────────────────────────────────────

def test_init_identity_crea_archivo_json(ks):
    info = ks.init_identity("alice", PASSWORD)
    assert Path(info["path"]).is_file()
    assert info["name"] == "alice"
    assert len(info["ed25519_fp"]) == 64
    assert len(info["x25519_fp"])  == 64


def test_init_identity_archivo_es_json_valido_v1(ks):
    ks.init_identity("alice", PASSWORD)
    data = json.loads((ks.dir / "alice.json").read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert data["name"] == "alice"
    assert data["status"] == "active"
    assert data["kdf"]["algorithm"] == "scrypt"
    assert data["encryption"]["algorithm"] == "AES-256-GCM"


def test_init_identity_duplicada_lanza_error(ks):
    ks.init_identity("alice", PASSWORD)
    with pytest.raises(IdentityAlreadyExistsError):
        ks.init_identity("alice", PASSWORD)


def test_init_identity_rechaza_password_debil(ks):
    with pytest.raises(ValueError, match="Password"):
        ks.init_identity("alice", "abc")


def test_init_identity_acepta_force_weak_password(ks):
    """Escape hatch para tests rapidos / legacy."""
    info = ks.init_identity("alice", "abc", force_weak_password=True)
    assert Path(info["path"]).is_file()


def test_init_identity_no_persiste_password_en_disco(ks):
    """El password no debe aparecer literal en el JSON."""
    ks.init_identity("alice", PASSWORD)
    raw = (ks.dir / "alice.json").read_text(encoding="utf-8")
    assert PASSWORD not in raw


def test_init_identity_no_persiste_privada_en_claro(ks):
    """La privada raw del Ed25519 no debe aparecer en el JSON."""
    info = ks.init_identity("alice", PASSWORD)
    # Tomar la privada Ed25519 recien generada y verificar que sus bytes
    # raw NO esten en el JSON. Para esto la abrimos con el password.
    ed_priv = ks.unlock_signing_key("alice", PASSWORD)
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, NoEncryption,
    )
    raw = ed_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_b64 = base64.b64encode(raw)
    blob = (ks.dir / "alice.json").read_bytes()
    assert raw not in blob
    assert raw_b64 not in blob


def test_init_identity_solo_ed25519(ks):
    info = ks.init_identity("solo", PASSWORD, with_x25519=False)
    assert info["x25519_fp"] == ""
    with pytest.raises(KeyStoreError, match="X25519"):
        ks.unlock_encryption_key("solo", PASSWORD)


@pytest.mark.parametrize("bad_name", [
    "", "..", ".", "../alice", "alice/x", "alice\\x",
    "with space",  # OK en realidad? no -- nuestra blacklist no lo bloquea, pero
                   # mejor verificar comportamiento documentado abajo
    "alice\0",
])
def test_init_identity_rechaza_nombres_peligrosos(ks, bad_name):
    if bad_name == "with space":
        # 'with space' no esta en la lista negra; documentamos que se permite.
        info = ks.init_identity(bad_name, PASSWORD)
        assert Path(info["path"]).is_file()
        return
    with pytest.raises(ValueError):
        ks.init_identity(bad_name, PASSWORD)


# ── consultas sin password ────────────────────────────────────────────────────

def test_exists(ks_alice):
    assert ks_alice.exists("alice")
    assert not ks_alice.exists("bob")
    assert not ks_alice.exists("../etc/passwd")   # nombre invalido -> False


def test_list_identities_devuelve_metadata_publica(ks):
    ks.init_identity("alice", PASSWORD)
    ks.init_identity("bob",   PASSWORD)
    rows = ks.list_identities()
    names = {r["name"] for r in rows}
    assert names == {"alice", "bob"}
    for r in rows:
        assert r["status"] == "active"
        assert len(r["ed25519_fp"]) == 64


def test_list_identities_no_expone_encrypted_private_key(ks_alice):
    rows = ks_alice.list_identities()
    for r in rows:
        assert "encrypted_private_key" not in r
        assert "kdf" not in r


def test_get_public_keys_no_requiere_password(ks_alice):
    info = ks_alice.get_public_keys("alice")
    assert info["ed25519_pub"] is not None
    assert info["x25519_pub"]  is not None
    assert len(info["fingerprints"]["ed25519"]) == 64


def test_get_public_keys_identidad_inexistente(ks_alice):
    with pytest.raises(IdentityNotFoundError):
        ks_alice.get_public_keys("inexistente")


# ── unlock con password correcto ──────────────────────────────────────────────

def test_unlock_signing_key_con_password_correcto(ks_alice):
    """Rubrica: Correct password -> access granted."""
    ed_priv = ks_alice.unlock_signing_key("alice", PASSWORD)
    # Verificacion robusta: la privada descifrada corresponde a la pub
    # del keystore.
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_recovered = ed_priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    pub_stored = ks_alice.get_public_keys("alice")["ed25519_pub"].public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    assert pub_recovered == pub_stored


def test_unlock_encryption_key_con_password_correcto(ks_alice):
    x_priv = ks_alice.unlock_encryption_key("alice", PASSWORD)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pub_recovered = x_priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    pub_stored = ks_alice.get_public_keys("alice")["x25519_pub"].public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw,
    )
    assert pub_recovered == pub_stored


def test_unlock_funciona_y_es_repetible(ks_alice):
    """Llamar dos veces produce dos objetos diferentes (no cache) pero
    ambos representan la misma clave matematica."""
    ed1 = ks_alice.unlock_signing_key("alice", PASSWORD)
    ed2 = ks_alice.unlock_signing_key("alice", PASSWORD)
    assert ed1 is not ed2  # objetos distintos
    # ambos firman el mismo mensaje al mismo valor (Ed25519 deterministico)
    sig1 = ed1.sign(b"hola")
    sig2 = ed2.sign(b"hola")
    assert sig1 == sig2


# ── unlock con password incorrecto / keystore modificado ──────────────────────

def test_unlock_password_incorrecto_lanza_InvalidTag(ks_alice):
    """Rubrica: Wrong password -> access denied."""
    with pytest.raises(InvalidTag):
        ks_alice.unlock_signing_key("alice", WRONG_PASSWORD)


def test_unlock_identidad_inexistente(ks_alice):
    with pytest.raises(IdentityNotFoundError):
        ks_alice.unlock_signing_key("nadie", PASSWORD)


@pytest.mark.parametrize("field_path", [
    ("encrypted_private_key",),
    ("encryption", "nonce_b64"),
    ("encryption", "tag_b64"),
    ("kdf", "salt_b64"),
])
def test_unlock_keystore_modificado_lanza_InvalidTag(ks_alice, field_path):
    """Rubrica: Modified keystore -> failure (parametrizado por ubicacion)."""
    path = ks_alice.dir / "alice.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    # Bajar al campo y flip-bit
    node = data
    for k in field_path[:-1]:
        node = node[k]
    leaf = field_path[-1]
    raw = bytearray(base64.b64decode(node[leaf]))
    raw[0] ^= 0xFF
    node[leaf] = base64.b64encode(bytes(raw)).decode("ascii")
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(InvalidTag):
        ks_alice.unlock_signing_key("alice", PASSWORD)


def test_unlock_keystore_con_name_inconsistente(ks_alice):
    """Renombrar el archivo a otro nombre debe ser detectado."""
    src = ks_alice.dir / "alice.json"
    dst = ks_alice.dir / "bob.json"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(KeyStoreError, match="inconsistente"):
        ks_alice.unlock_signing_key("bob", PASSWORD)


# ── integridad del directorio ─────────────────────────────────────────────────

def test_keystore_dir_es_creado_si_falta(tmp_path):
    target = tmp_path / "nuevo" / "ks"
    assert not target.exists()
    ks = KeyStore(target, kdf_params=FAST_PARAMS)
    assert target.is_dir()


def test_keystore_dir_con_create_false_exige_existente(tmp_path):
    target = tmp_path / "no_existe"
    with pytest.raises(FileNotFoundError):
        KeyStore(target, create=False, kdf_params=FAST_PARAMS)


def test_list_identities_ignora_archivos_invalidos(ks):
    ks.init_identity("alice", PASSWORD)
    # Archivo basura en el directorio: la lista no lo incluye ni se rompe.
    (ks.dir / "ruido.json").write_text("{\"esto\": \"no es un keystore\"}", encoding="utf-8")
    rows = ks.list_identities()
    assert {r["name"] for r in rows} == {"alice"}


def test_list_identities_ignora_rotated(ks):
    ks.init_identity("alice", PASSWORD)
    ks.rotate_keys("alice", PASSWORD)
    rows = ks.list_identities()
    # 'alice' aparece solo una vez (la nueva). El archivo .rotated-* no se cuenta.
    assert sum(1 for r in rows if r["name"] == "alice") == 1


# ── fingerprints consistentes con D5 ──────────────────────────────────────────

def test_fingerprints_coinciden_con_get_fingerprint_de_keys(ks_alice):
    """El fingerprint del JSON coincide con src.keys.get_fingerprint."""
    from src.keys import get_fingerprint
    info = ks_alice.get_public_keys("alice")
    assert get_fingerprint(info["ed25519_pub"]) == info["fingerprints"]["ed25519"]


def test_fingerprints_x25519_coincide_con_hybrid(ks_alice):
    from src.hybrid import get_x25519_fingerprint
    info = ks_alice.get_public_keys("alice")
    assert get_x25519_fingerprint(info["x25519_pub"]) == info["fingerprints"]["x25519"]
