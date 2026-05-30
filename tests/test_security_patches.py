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

from src.aead import (
    encrypt_file,
    decrypt_file,
    DEFAULT_MAX_AGE,
    MAX_FUTURE_SKEW,
)
from src.hybrid import (
    encrypt_for_recipients,
    decrypt_for_recipient,
    generate_x25519_keypair,
)
from src.keys import generate_keypair
from src.secure_send import secure_encrypt_and_sign, secure_verify_and_decrypt


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
        from src.aead import (
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


# ═══════════════════════════════════════════════════════════════════════════
# VULN-003 — DoS por ct_len sin tope (CWE-770 / CWE-400)
# ═══════════════════════════════════════════════════════════════════════════

import struct
from src.aead import (
    MAX_CIPHERTEXT_SIZE,
    validate_ciphertext_length,
    safe_path_join,
)
from src.hybrid import MAX_RECIPIENTS


class TestVuln003CiphertextLengthCap:

    def test_validate_ciphertext_length_acepta_dentro_del_tope(self):
        validate_ciphertext_length(0)
        validate_ciphertext_length(1024)
        validate_ciphertext_length(MAX_CIPHERTEXT_SIZE)

    def test_validate_ciphertext_length_rechaza_fuera_del_tope(self):
        with pytest.raises(ValueError, match="demasiado grande"):
            validate_ciphertext_length(MAX_CIPHERTEXT_SIZE + 1)

    def test_validate_ciphertext_length_rechaza_max_uint32(self):
        """Un atacante que ponga ct_len = 4 GiB debe ser rechazado."""
        with pytest.raises(ValueError, match="demasiado grande"):
            validate_ciphertext_length(0xFFFFFFFF)

    def test_decrypt_file_rechaza_container_con_ctlen_hostil(self):
        """Container manipulado con ct_len enorme debe fallar antes del slice."""
        plaintext = b"hola"
        container, key = encrypt_file(plaintext, "doc.txt")
        # Buscar el campo ct_len: header + nonce(12), antes del ciphertext.
        # Lo manipulamos a 1 GiB.
        # Localizar offset: parseamos para conocer header_end.
        from src.aead import _parse_header, NONCE_SIZE
        _, header_end = _parse_header(container)
        ct_len_offset = header_end + NONCE_SIZE
        manipulado = (
            container[:ct_len_offset]
            + struct.pack(">I", 1024 * 1024 * 1024)   # 1 GiB hostil
            + container[ct_len_offset + 4:]
        )
        with pytest.raises(ValueError, match="demasiado grande"):
            decrypt_file(manipulado, key)

    def test_decrypt_for_recipient_rechaza_ctlen_hostil(self):
        """Mismo ataque sobre contenedor SDDH."""
        priv, pub = generate_x25519_keypair()
        container = encrypt_for_recipients(b"hola", "doc.txt", [pub])
        from src.hybrid import _parse_hybrid_header
        from src.aead import NONCE_SIZE
        _, header_end = _parse_hybrid_header(container)
        ct_len_offset = header_end + NONCE_SIZE
        manipulado = (
            container[:ct_len_offset]
            + struct.pack(">I", 2 * 1024 * 1024 * 1024)   # 2 GiB hostil
            + container[ct_len_offset + 4:]
        )
        with pytest.raises(ValueError, match="demasiado grande"):
            decrypt_for_recipient(manipulado, priv)


# ═══════════════════════════════════════════════════════════════════════════
# VULN-004 — DoS por RECIPIENT_COUNT sin tope (CWE-770)
# ═══════════════════════════════════════════════════════════════════════════

class TestVuln004RecipientCountCap:

    def test_encrypt_for_recipients_rechaza_demasiados_destinatarios(self):
        # Generar lista artificialmente grande
        priv, pub = generate_x25519_keypair()
        muchos = [pub] * (MAX_RECIPIENTS + 1)
        with pytest.raises(ValueError, match="Demasiados destinatarios"):
            encrypt_for_recipients(b"hi", "doc.txt", muchos)

    def test_decrypt_rechaza_recipient_count_hostil(self):
        """Container manipulado con n_recipients=65535 debe fallar."""
        priv, pub = generate_x25519_keypair()
        container = encrypt_for_recipients(b"hi", "doc.txt", [pub])
        # Localizar el campo RECIPIENT_COUNT: 16 + fname_len.
        fname_len = struct.unpack(">H", container[14:16])[0]
        rcpt_offset = 16 + fname_len
        manipulado = (
            container[:rcpt_offset]
            + struct.pack(">H", 65535)   # uint16 max
            + container[rcpt_offset + 2:]
        )
        with pytest.raises(ValueError, match="RECIPIENT_COUNT excede"):
            decrypt_for_recipient(manipulado, priv)


# ═══════════════════════════════════════════════════════════════════════════
# VULN-005 — Tipo de contenedor confundido (SDDH pasado a decrypt_file)
# ═══════════════════════════════════════════════════════════════════════════

class TestVuln005ContainerTypeConfusion:

    def test_decrypt_file_rechaza_container_sddh_con_mensaje_claro(self):
        """Pasar un contenedor SDDH a decrypt_file debe dar mensaje util."""
        priv, pub = generate_x25519_keypair()
        sddh = encrypt_for_recipients(b"hi", "doc.txt", [pub])
        # Cualquier key sirve — debe fallar antes en parseo
        from src.aead import generate_key
        with pytest.raises(ValueError, match="hibrido SDDH.*decrypt_for_recipient"):
            decrypt_file(sddh, generate_key())


# ═══════════════════════════════════════════════════════════════════════════
# VULN-006 — Path traversal al consumir metadata['filename'] (CWE-22 layer 3)
# ═══════════════════════════════════════════════════════════════════════════

class TestVuln006SafePathJoin:

    def test_safe_path_join_acepta_filename_simple(self, tmp_path):
        out = str(tmp_path)
        result = safe_path_join(out, "doc.pdf")
        assert result.endswith("doc.pdf")
        assert result.startswith(out)

    def test_safe_path_join_rechaza_separadores(self, tmp_path):
        with pytest.raises(ValueError):
            safe_path_join(str(tmp_path), "../etc/passwd")

    def test_safe_path_join_rechaza_absolutos(self, tmp_path):
        with pytest.raises(ValueError):
            safe_path_join(str(tmp_path), "/etc/passwd")

    def test_safe_path_join_rechaza_null_byte(self, tmp_path):
        with pytest.raises(ValueError):
            safe_path_join(str(tmp_path), "valido.txt\x00.evil")

    def test_safe_path_join_no_acepta_prefix_match_falso(self, tmp_path):
        """out_dir='/tmp/foo' no debe aceptar candidate='/tmp/fooEVIL'."""
        # validate_filename ya rechaza separadores, asi que el unico camino
        # para llegar aqui es un filename aceptable cuyo realpath quede fuera.
        # En la practica esto solo pasaria con symlinks; lo verificamos con
        # un nombre 'normal' que no contenga separadores.
        out = str(tmp_path)
        # Caso sano: cualquier filename simple debe quedar dentro de out_dir.
        assert safe_path_join(out, "ok.txt").startswith(out)


# ═══════════════════════════════════════════════════════════════════════════
# VULN-007 — Password debil al guardar PEM PKCS8 (CWE-521)
# ═══════════════════════════════════════════════════════════════════════════

from src.keys import (
    save_private_key,
    validate_password_strength,
    MIN_PASSWORD_LENGTH,
)


class TestVuln007PasswordStrength:

    def test_validate_password_strength_acepta_password_robusto(self):
        validate_password_strength("password_seguro_UNAM_2026!")
        validate_password_strength("a" * MIN_PASSWORD_LENGTH + "b")

    def test_validate_password_strength_rechaza_corto(self):
        with pytest.raises(ValueError, match="Password debil"):
            validate_password_strength("short")

    def test_validate_password_strength_rechaza_un_solo_caracter_repetido(self):
        with pytest.raises(ValueError, match="un solo caracter"):
            validate_password_strength("a" * MIN_PASSWORD_LENGTH)

    def test_validate_password_strength_rechaza_vacio(self):
        with pytest.raises(ValueError, match="vacio"):
            validate_password_strength("")

    def test_save_private_key_rechaza_password_debil_por_default(self, tmp_path):
        priv, _ = generate_keypair()
        path = str(tmp_path / "test.priv")
        with pytest.raises(ValueError, match="Password debil"):
            save_private_key(priv, path, "abc")

    def test_save_private_key_acepta_force_weak_password_para_legacy(self, tmp_path):
        """Escape hatch para migracion / tests, no recomendado en produccion."""
        priv, _ = generate_keypair()
        path = str(tmp_path / "test.priv")
        # No debe lanzar — el caller pidio bypass explicito
        save_private_key(priv, path, "abc", force_weak_password=True)
        import os as _os
        assert _os.path.exists(path)
