"""
tests/test_keystore_lifecycle.py
================================
Tests del ciclo de vida de identidades en la KeyStore (D6 Fase 2).

Cubre:
  - change_password: re-cifra correctamente, password viejo deja de
    funcionar, las llaves publicas no cambian.
  - rotate_keys: genera fingerprint nuevo, archiva el viejo, marca
    el archivado como 'rotated', encadena `rotated_from`.
  - revoke: status='revoked', bloquea unlock pero deja get_public_keys
    para verificar firmas historicas.
  - delete: borra solo si el password es correcto.
  - Integracion con secure_send: encrypt_and_sign_from_keystore y su
    contraparte de descifrado funcionan end-to-end.
"""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.exceptions import InvalidTag

from src.hybrid import generate_x25519_keypair
from src.keystore import (
    IdentityExpiredError,
    IdentityNotFoundError,
    IdentityRevokedError,
    KeyStore,
    KeyStoreError,
)
from src.secure_send import (
    encrypt_and_sign_from_keystore,
    verify_and_decrypt_from_keystore,
)


FAST_PARAMS = {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}
PASSWORD     = "passwordSeguro_UNAM_2026!"
PASSWORD_NEW = "otroPasswordIgualmenteFuerte!2026"
PASSWORD_BAD = "password-equivocado-12345!"


@pytest.fixture
def ks(tmp_path):
    return KeyStore(tmp_path / "keystore", kdf_params=FAST_PARAMS)


@pytest.fixture
def ks_alice(ks):
    ks.init_identity("alice", PASSWORD)
    return ks


# ── change_password ───────────────────────────────────────────────────────────

def test_change_password_re_cifra_y_old_pwd_falla(ks_alice):
    old_pub = ks_alice.get_public_keys("alice")["ed25519_pub"]
    ks_alice.change_password("alice", PASSWORD, PASSWORD_NEW)

    # Old password ya no abre la identidad
    with pytest.raises(InvalidTag):
        ks_alice.unlock_signing_key("alice", PASSWORD)

    # New password si abre, y la pubkey es la misma
    ks_alice.unlock_signing_key("alice", PASSWORD_NEW)
    new_pub = ks_alice.get_public_keys("alice")["ed25519_pub"]
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    assert old_pub.public_bytes(Encoding.Raw, PublicFormat.Raw) == \
           new_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_change_password_con_pwd_actual_incorrecto_falla(ks_alice):
    with pytest.raises(InvalidTag):
        ks_alice.change_password("alice", PASSWORD_BAD, PASSWORD_NEW)


def test_change_password_rechaza_nuevo_debil(ks_alice):
    with pytest.raises(ValueError, match="Password"):
        ks_alice.change_password("alice", PASSWORD, "abc")


def test_change_password_renueva_salt_y_nonce(ks_alice, tmp_path):
    """Despues de cambiar, el JSON debe tener un salt y nonce distintos."""
    path = ks_alice.dir / "alice.json"
    before = json.loads(path.read_text(encoding="utf-8"))
    ks_alice.change_password("alice", PASSWORD, PASSWORD_NEW)
    after  = json.loads(path.read_text(encoding="utf-8"))
    assert before["kdf"]["salt_b64"]              != after["kdf"]["salt_b64"]
    assert before["encryption"]["nonce_b64"]      != after["encryption"]["nonce_b64"]
    assert before["encrypted_private_key"]        != after["encrypted_private_key"]
    # created_at NO debe cambiar (es el momento original)
    assert before["created_at"] == after["created_at"]


# ── rotate_keys ───────────────────────────────────────────────────────────────

def test_rotate_keys_cambia_fingerprint(ks_alice):
    old_fp = ks_alice.get_public_keys("alice")["fingerprints"]["ed25519"]
    result = ks_alice.rotate_keys("alice", PASSWORD)
    new_fp = ks_alice.get_public_keys("alice")["fingerprints"]["ed25519"]
    assert result["old_ed25519_fp"] == old_fp
    assert result["new_ed25519_fp"] == new_fp
    assert old_fp != new_fp


def test_rotate_keys_archiva_el_viejo_con_status_rotated(ks_alice):
    result = ks_alice.rotate_keys("alice", PASSWORD)
    archived = json.loads(open(result["archived_path"], encoding="utf-8").read())
    assert archived["status"] == "rotated"
    assert archived["name"] == "alice"


def test_rotate_keys_setea_rotated_from_al_old_fp(ks_alice):
    old_fp = ks_alice.get_public_keys("alice")["fingerprints"]["ed25519"]
    ks_alice.rotate_keys("alice", PASSWORD)
    new_data = json.loads((ks_alice.dir / "alice.json").read_text(encoding="utf-8"))
    assert new_data["metadata"]["rotated_from"] == old_fp


def test_rotate_keys_con_password_incorrecto_falla(ks_alice):
    with pytest.raises(InvalidTag):
        ks_alice.rotate_keys("alice", PASSWORD_BAD)


def test_rotate_keys_el_archivo_rotated_no_permite_unlock_por_nombre(ks):
    """Despues de rotar, el alias 'alice' apunta a la NUEVA identidad.
    No hay forma directa por nombre de abrir la vieja (los .rotated-* son
    solo para auditoria; cargarlos requiere herramientas separadas)."""
    ks.init_identity("alice", PASSWORD)
    ks.rotate_keys("alice", PASSWORD)
    # unlock_signing_key("alice", PASSWORD) usa la nueva (sin error).
    ks.unlock_signing_key("alice", PASSWORD)


# ── revoke ────────────────────────────────────────────────────────────────────

def test_revoke_marca_status_y_bloquea_unlock(ks_alice):
    ks_alice.revoke("alice", reason="key compromise")
    data = json.loads((ks_alice.dir / "alice.json").read_text(encoding="utf-8"))
    assert data["status"] == "revoked"
    assert "key compromise" in data["metadata"]["comment"]
    with pytest.raises(IdentityRevokedError):
        ks_alice.unlock_signing_key("alice", PASSWORD)


def test_revoke_deja_publicas_consultables(ks_alice):
    """Aun revocada, la publica sigue accesible para verificar firmas viejas."""
    pub_before = ks_alice.get_public_keys("alice")
    ks_alice.revoke("alice")
    pub_after = ks_alice.get_public_keys("alice")
    assert pub_after["status"] == "revoked"
    assert pub_after["fingerprints"] == pub_before["fingerprints"]


def test_revoke_identidad_inexistente(ks):
    with pytest.raises(IdentityNotFoundError):
        ks.revoke("nadie")


# ── expiracion ────────────────────────────────────────────────────────────────

def test_expires_at_pasado_bloquea_unlock(ks):
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    ks.init_identity("alice", PASSWORD, expires_at=past)
    with pytest.raises(IdentityExpiredError):
        ks.unlock_signing_key("alice", PASSWORD)


def test_expires_at_futuro_permite_unlock(ks):
    future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(timespec="seconds").replace("+00:00", "Z")
    ks.init_identity("alice", PASSWORD, expires_at=future)
    ks.unlock_signing_key("alice", PASSWORD)  # no lanza


def test_expires_at_none_es_sin_expiracion(ks_alice):
    ks_alice.unlock_signing_key("alice", PASSWORD)  # no lanza


# ── delete ────────────────────────────────────────────────────────────────────

def test_delete_borra_archivo(ks_alice):
    path = ks_alice.dir / "alice.json"
    assert path.exists()
    ks_alice.delete("alice", PASSWORD)
    assert not path.exists()
    assert not ks_alice.exists("alice")


def test_delete_requiere_password_correcto(ks_alice):
    with pytest.raises(InvalidTag):
        ks_alice.delete("alice", PASSWORD_BAD)
    # archivo sigue ahi
    assert (ks_alice.dir / "alice.json").exists()


def test_delete_identidad_inexistente(ks):
    with pytest.raises(IdentityNotFoundError):
        ks.delete("nadie", PASSWORD)


# ── integracion con secure_send (flujo D5 desde keystore) ─────────────────────

def test_integracion_d5_completo_desde_keystore(ks):
    """End-to-end: Alice firma+cifra para Bob; Bob verifica+descifra.
    Ambos usan keystore para sus llaves privadas."""
    ks.init_identity("alice", PASSWORD)
    ks.init_identity("bob",   PASSWORD)

    bob_pub_x25519 = ks.get_public_keys("bob")["x25519_pub"]

    container = encrypt_and_sign_from_keystore(
        ks, "alice", PASSWORD,
        plaintext=b"Hola Bob, mensaje confidencial.",
        filename="mensaje.txt",
        recipients_x25519=[bob_pub_x25519],
    )

    alice_pub_ed = ks.get_public_keys("alice")["ed25519_pub"]
    plaintext, meta = verify_and_decrypt_from_keystore(
        ks, "bob", PASSWORD,
        signed_container=container,
        expected_signer_pub=alice_pub_ed,
    )
    assert plaintext == b"Hola Bob, mensaje confidencial."
    assert meta["filename"] == "mensaje.txt"


def test_integracion_d5_falla_con_password_bob_incorrecto(ks):
    ks.init_identity("alice", PASSWORD)
    ks.init_identity("bob",   PASSWORD)
    container = encrypt_and_sign_from_keystore(
        ks, "alice", PASSWORD,
        plaintext=b"x",
        filename="x.txt",
        recipients_x25519=[ks.get_public_keys("bob")["x25519_pub"]],
    )
    with pytest.raises(InvalidTag):
        verify_and_decrypt_from_keystore(
            ks, "bob", PASSWORD_BAD,
            signed_container=container,
            expected_signer_pub=ks.get_public_keys("alice")["ed25519_pub"],
        )


def test_integracion_d5_falla_si_alice_revocada(ks):
    ks.init_identity("alice", PASSWORD)
    ks.init_identity("bob",   PASSWORD)
    ks.revoke("alice")
    bob_pub = ks.get_public_keys("bob")["x25519_pub"]
    with pytest.raises(IdentityRevokedError):
        encrypt_and_sign_from_keystore(
            ks, "alice", PASSWORD,
            plaintext=b"x",
            filename="x.txt",
            recipients_x25519=[bob_pub],
        )
