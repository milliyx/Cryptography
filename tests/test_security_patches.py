"""
tests/test_security_patches.py
==============================
Tests de regresion para los parches de seguridad.

  - VULN-001 (CWE-22):  Path traversal via filename
  - VULN-002 (CWE-294): Replay attack por falta de freshness

Cada test confirma que el sistema rechaza el ataque despues del parche.
"""

import time
import pytest

from cryptography.exceptions import InvalidTag

from crypto.aead import (
    encrypt_file,
    decrypt_file,
    DEFAULT_MAX_AGE,
    MAX_FUTURE_SKEW,
)
from crypto.hybrid import (
    encrypt_for_recipients,
    decrypt_for_recipient,
    generate_x25519_keypair,
)
from crypto.keys import generate_keypair
from crypto.secure_send import secure_encrypt_and_sign, secure_verify_and_decrypt


# ═══════════════════════════════════════════════════════════════════════════
# VULN-001 — Path traversal via filename (CWE-22)
# ═══════════════════════════════════════════════════════════════════════════

class TestVuln001PathTraversal:

    @pytest.mark.parametrize("malicious_filename", [
        "../../../etc/passwd",
        "/etc/shadow",
        "..\\..\\Windows\\System32\\config\\SAM",
        "/absolute/path",
        "subdir/file.txt",
        "..",
        ".",
        "....//evil",
        "file/../../../etc/passwd",
    ])
    def test_encrypt_file_rechaza_path_traversal(self, malicious_filename):
        """encrypt_file debe rechazar filenames con separadores o '..'"""
        with pytest.raises(ValueError):
            encrypt_file(b"payload", malicious_filename)

    def test_encrypt_file_rechaza_null_byte(self):
        """Null byte injection debe ser rechazado."""
        with pytest.raises(ValueError, match="byte nulo"):
            encrypt_file(b"payload", "valid.txt\x00../../../tmp/pwned")

    def test_encrypt_file_rechaza_caracteres_control(self):
        """Caracteres de control (< 0x20) deben ser rechazados."""
        with pytest.raises(ValueError, match="caracteres de control"):
            encrypt_file(b"payload", "file\nname.txt")

    def test_encrypt_file_rechaza_filename_vacio(self):
        with pytest.raises(ValueError, match="vacio"):
            encrypt_file(b"payload", "")

    def test_encrypt_file_rechaza_filename_demasiado_largo(self):
        with pytest.raises(ValueError, match="excede"):
            encrypt_file(b"payload", "a" * 256)

    def test_encrypt_file_acepta_filenames_legitimos(self):
        """Filenames normales deben seguir funcionando."""
        for fname in ["doc.pdf", "contrato_2026.txt", "archivo-final.docx", "imagen.jpg"]:
            container, key = encrypt_file(b"payload", fname)
            pt, meta = decrypt_file(container, key)
            assert meta["filename"] == fname

    def test_encrypt_for_recipients_rechaza_path_traversal(self):
        """El parche aplica tambien a contenedores hibridos."""
        priv, pub = generate_x25519_keypair()
        with pytest.raises(ValueError):
            encrypt_for_recipients(b"x", "../../etc/passwd", [pub])

    def test_decrypt_file_defense_in_depth(self):
        """Aun si un atacante construye un contenedor con filename malicioso
        a mano, decrypt_file debe rechazarlo (defense-in-depth, CWE-22)."""
        from crypto.aead import (
            MAGIC, VERSION, Algorithm, NONCE_SIZE, TAG_SIZE,
        )
        import struct
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os

        filename = "../../etc/passwd"
        fname_bytes = filename.encode("utf-8")
        header = (
            MAGIC + bytes([VERSION, int(Algorithm.AES_256_GCM)])
            + struct.pack(">Q", int(time.time()))
            + struct.pack(">H", len(fname_bytes))
            + fname_bytes
        )
        key = os.urandom(32)
        nonce = os.urandom(NONCE_SIZE)
        ct = AESGCM(key).encrypt(nonce, b"payload", header)
        container = (
            header + nonce + struct.pack(">I", len(ct) - TAG_SIZE)
            + ct[:-TAG_SIZE] + ct[-TAG_SIZE:]
        )
        with pytest.raises(ValueError, match="separadores de path"):
            decrypt_file(container, key)


# ═══════════════════════════════════════════════════════════════════════════
# VULN-002 — Replay Attack (CWE-294)
# ═══════════════════════════════════════════════════════════════════════════

class TestVuln002ReplayAttack:

    def test_decrypt_rechaza_timestamp_antiguo(self):
        """Un contenedor con timestamp viejo debe ser rechazado por default."""
        old_ts = int(time.time()) - DEFAULT_MAX_AGE - 100
        container, key = encrypt_file(b"payload", "doc.txt", timestamp=old_ts)
        with pytest.raises(ValueError, match="demasiado antiguo"):
            decrypt_file(container, key)

    def test_decrypt_rechaza_timestamp_futuro(self):
        """Un timestamp significativamente en el futuro debe ser rechazado."""
        future_ts = int(time.time()) + MAX_FUTURE_SKEW + 100
        container, key = encrypt_file(b"payload", "doc.txt", timestamp=future_ts)
        with pytest.raises(ValueError, match="en el futuro"):
            decrypt_file(container, key)

    def test_decrypt_acepta_timestamp_dentro_de_ventana(self):
        """Un timestamp reciente dentro de la ventana debe pasar."""
        recent_ts = int(time.time()) - 100
        container, key = encrypt_file(b"payload", "doc.txt", timestamp=recent_ts)
        pt, _ = decrypt_file(container, key)
        assert pt == b"payload"

    def test_decrypt_acepta_clock_skew_pequeno(self):
        """Tolerar pequenios desfases de reloj hacia el futuro."""
        skewed_ts = int(time.time()) + 60
        container, key = encrypt_file(b"payload", "doc.txt", timestamp=skewed_ts)
        pt, _ = decrypt_file(container, key)
        assert pt == b"payload"

    def test_decrypt_max_age_none_deshabilita_check(self):
        """max_age_seconds=None permite descifrar contenedores muy viejos."""
        old_ts = int(time.time()) - 365 * 24 * 60 * 60
        container, key = encrypt_file(b"payload", "doc.txt", timestamp=old_ts)
        pt, _ = decrypt_file(container, key, max_age_seconds=None)
        assert pt == b"payload"

    def test_decrypt_max_age_personalizado(self):
        """max_age_seconds custom debe respetarse."""
        ts = int(time.time()) - 30
        container, key = encrypt_file(b"payload", "doc.txt", timestamp=ts)
        with pytest.raises(ValueError, match="demasiado antiguo"):
            decrypt_file(container, key, max_age_seconds=10)
        pt, _ = decrypt_file(container, key, max_age_seconds=60)
        assert pt == b"payload"

    def test_hybrid_rechaza_timestamp_antiguo(self):
        """El parche aplica a decrypt_for_recipient."""
        priv, pub = generate_x25519_keypair()
        old_ts = int(time.time()) - DEFAULT_MAX_AGE - 100
        container = encrypt_for_recipients(b"payload", "doc.txt", [pub], timestamp=old_ts)
        with pytest.raises(ValueError, match="demasiado antiguo"):
            decrypt_for_recipient(container, priv)

    def test_secure_send_rechaza_replay(self):
        """secure_verify_and_decrypt debe rechazar contenedores firmados antiguos."""
        bob_priv, bob_pub = generate_x25519_keypair()
        alice_sign_priv, alice_sign_pub = generate_keypair()

        old_ts = int(time.time()) - DEFAULT_MAX_AGE - 100
        signed = secure_encrypt_and_sign(
            plaintext=b"comando antiguo",
            filename="cmd.txt",
            recipients=[bob_pub],
            signer_priv=alice_sign_priv,
            timestamp=old_ts,
        )
        with pytest.raises(ValueError, match="demasiado antiguo"):
            secure_verify_and_decrypt(signed, alice_sign_pub, bob_priv)
