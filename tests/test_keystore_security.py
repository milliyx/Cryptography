"""
tests/test_keystore_security.py
===============================
Tests de seguridad D6 — los 5 tests REQUERIDOS por la rubrica:

  1. Correct password   -> access granted
  2. Wrong password     -> access denied
  3. Modified keystore  -> failure
  4. Backup -> restore  works
  5. Stolen keystore alone -> cannot decrypt

Estos tests viven en un archivo aparte (no en test_keystore.py) para
que sea trivial mapear "rubrica -> archivo de tests" en la entrega.
"""

import base64
import json
import shutil
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from src.hybrid import encrypt_for_recipients, decrypt_for_recipient
from src.keystore import (
    IdentityAlreadyExistsError,
    KeyStore,
)
from src.keystore_backup import export_backup, import_backup
from src.secure_send import (
    encrypt_and_sign_from_keystore,
    verify_and_decrypt_from_keystore,
)


FAST_PARAMS = {"n": 2 ** 10, "r": 8, "p": 1, "dklen": 32}
PASSWORD        = "passwordSeguro_UNAM_2026!"
BACKUP_PASSWORD = "passwordDeBackupDistinto_2026!"
NEW_PASSWORD    = "nuevoPasswordParaRestaurar_2026!"


# ── fixture base ──────────────────────────────────────────────────────────────

@pytest.fixture
def ks(tmp_path):
    return KeyStore(tmp_path / "keystore", kdf_params=FAST_PARAMS)


# ─────────────────────────────────────────────────────────────────────────────
# RUBRICA 1: Correct password -> access granted
# ─────────────────────────────────────────────────────────────────────────────

def test_correct_password_grants_access(ks):
    """
    Con el password correcto, la KeyStore devuelve la clave privada
    Ed25519 que puede firmar (operacion criptografica real).
    """
    ks.init_identity("alice", PASSWORD)
    ed_priv = ks.unlock_signing_key("alice", PASSWORD)

    # Firmamos algo y verificamos contra la publica del keystore.
    sig = ed_priv.sign(b"mensaje de prueba")
    pub = ks.get_public_keys("alice")["ed25519_pub"]
    pub.verify(sig, b"mensaje de prueba")  # no lanza -> exito


# ─────────────────────────────────────────────────────────────────────────────
# RUBRICA 2: Wrong password -> access denied
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("wrong_password", [
    "passwordIncorrecto_12345!",
    "passwordSeguro_UNAM_2025!",    # un caracter distinto
    "passwordSeguro_UNAM_2026 ",    # espacio extra al final
    "",                              # vacio
    "x" * 100,                       # largo random
])
def test_wrong_password_denies_access(ks, wrong_password):
    """
    Cualquier password que no sea el correcto debe lanzar InvalidTag.
    El sistema NUNCA debe devolver una clave parcial ni un objeto vacio.
    """
    ks.init_identity("alice", PASSWORD)
    with pytest.raises(InvalidTag):
        ks.unlock_signing_key("alice", wrong_password)
    # Tambien para la X25519
    with pytest.raises(InvalidTag):
        ks.unlock_encryption_key("alice", wrong_password)


# ─────────────────────────────────────────────────────────────────────────────
# RUBRICA 3: Modified keystore -> failure
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("target_field", [
    "encrypted_private_key",
    "encryption.nonce_b64",
    "encryption.tag_b64",
    "kdf.salt_b64",
])
def test_modified_keystore_byte_a_byte_falla(ks, target_field):
    """
    Si un atacante toca un solo byte de cualquier campo critico, el
    unlock debe fallar con InvalidTag. AES-GCM detecta la manipulacion
    sin distinguir cual campo fue tocado (mismo error siempre = fail-closed).
    """
    ks.init_identity("alice", PASSWORD)
    path = ks.dir / "alice.json"
    data = json.loads(path.read_text(encoding="utf-8"))

    # Navegar al campo objetivo (puede ser nested via punto).
    node = data
    parts = target_field.split(".")
    for k in parts[:-1]:
        node = node[k]
    leaf = parts[-1]

    # Flip-bit del primer byte tras decodificar base64.
    raw = bytearray(base64.b64decode(node[leaf]))
    raw[0] ^= 0xFF
    node[leaf] = base64.b64encode(bytes(raw)).decode("ascii")
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(InvalidTag):
        ks.unlock_signing_key("alice", PASSWORD)


def test_modified_keystore_truncado_falla(ks):
    """Truncar el ciphertext tambien debe lanzar InvalidTag (o similar)."""
    ks.init_identity("alice", PASSWORD)
    path = ks.dir / "alice.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    raw = base64.b64decode(data["encrypted_private_key"])
    truncated = raw[:max(1, len(raw) // 2)]
    data["encrypted_private_key"] = base64.b64encode(truncated).decode("ascii")
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises((InvalidTag, ValueError)):
        ks.unlock_signing_key("alice", PASSWORD)


def test_modified_keystore_swap_de_kdf_params_falla(ks):
    """Cambiar los parametros KDF cambia la clave derivada -> InvalidTag."""
    ks.init_identity("alice", PASSWORD)
    path = ks.dir / "alice.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["kdf"]["n"] = data["kdf"]["n"] * 2  # sigue siendo potencia de 2
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(InvalidTag):
        ks.unlock_signing_key("alice", PASSWORD)


# ─────────────────────────────────────────────────────────────────────────────
# RUBRICA 4: Backup -> restore works
# ─────────────────────────────────────────────────────────────────────────────

def test_backup_export_y_import_roundtrip(tmp_path, ks):
    """
    Backup -> borrar identidad -> restore con nombre nuevo ->
    la identidad restaurada conserva los fingerprints originales
    y puede firmar / descifrar mensajes encripatados a la ORIGINAL.
    """
    ks.init_identity("alice", PASSWORD)
    original_fps = ks.get_public_keys("alice")["fingerprints"]
    alice_pub_x = ks.get_public_keys("alice")["x25519_pub"]
    alice_pub_ed = ks.get_public_keys("alice")["ed25519_pub"]

    # Mensaje cifrado A LA ALICE ORIGINAL (antes del backup).
    container = encrypt_for_recipients(
        b"prueba de restauracion",
        filename="prueba.txt",
        recipients=[alice_pub_x],
    )

    # 1. Export
    backup_path = tmp_path / "alice.sddv_backup"
    out = export_backup(ks, "alice", PASSWORD, BACKUP_PASSWORD, str(backup_path))
    assert Path(out).is_file()

    # 2. Borrar la identidad activa
    ks.delete("alice", PASSWORD)
    assert not ks.exists("alice")

    # 3. Restaurar (nuevo password activo, distinto del de backup)
    info = import_backup(ks, str(backup_path), BACKUP_PASSWORD, NEW_PASSWORD)
    assert info["name"] == "alice"

    # 4. Los fingerprints coinciden con la original
    new_fps = ks.get_public_keys("alice")["fingerprints"]
    assert new_fps == original_fps

    # 5. La identidad restaurada puede descifrar el mensaje viejo
    restored_x_priv = ks.unlock_encryption_key("alice", NEW_PASSWORD)
    plaintext, _ = decrypt_for_recipient(container, restored_x_priv)
    assert plaintext == b"prueba de restauracion"

    # 6. La identidad restaurada puede firmar y verificar contra la pub original
    restored_ed_priv = ks.unlock_signing_key("alice", NEW_PASSWORD)
    sig = restored_ed_priv.sign(b"mensaje despues de restore")
    alice_pub_ed.verify(sig, b"mensaje despues de restore")


def test_backup_password_incorrecto_no_descifra_backup(tmp_path, ks):
    """Sin el password del backup el archivo es inservible."""
    ks.init_identity("alice", PASSWORD)
    backup = tmp_path / "alice.sddv_backup"
    export_backup(ks, "alice", PASSWORD, BACKUP_PASSWORD, str(backup))
    # Borrar la activa para asegurar que el unico camino es el backup.
    ks.delete("alice", PASSWORD)

    with pytest.raises(InvalidTag):
        import_backup(ks, str(backup), "passwordEquivocadoDeBackup!_123", NEW_PASSWORD)


def test_backup_no_se_puede_restaurar_si_ya_existe(tmp_path, ks):
    ks.init_identity("alice", PASSWORD)
    backup = tmp_path / "alice.sddv_backup"
    export_backup(ks, "alice", PASSWORD, BACKUP_PASSWORD, str(backup))
    with pytest.raises(IdentityAlreadyExistsError):
        import_backup(ks, str(backup), BACKUP_PASSWORD, NEW_PASSWORD)


def test_backup_se_puede_renombrar_al_restaurar(tmp_path, ks):
    """Permite restaurar como 'alice2' sin tocar la activa."""
    ks.init_identity("alice", PASSWORD)
    backup = tmp_path / "alice.sddv_backup"
    export_backup(ks, "alice", PASSWORD, BACKUP_PASSWORD, str(backup))
    info = import_backup(ks, str(backup), BACKUP_PASSWORD, NEW_PASSWORD, name="alice2")
    assert info["name"] == "alice2"
    assert ks.exists("alice") and ks.exists("alice2")
    assert ks.get_public_keys("alice")["fingerprints"] == \
           ks.get_public_keys("alice2")["fingerprints"]


def test_backup_archivo_corrupto_falla(tmp_path, ks):
    ks.init_identity("alice", PASSWORD)
    bad = tmp_path / "bad.sddv_backup"
    bad.write_text("{} no es json valido [", encoding="utf-8")
    with pytest.raises(ValueError):
        import_backup(ks, str(bad), BACKUP_PASSWORD, NEW_PASSWORD)


def test_backup_archivo_no_es_backup_falla(tmp_path, ks):
    """Un JSON sin el campo `backup_of` no se acepta."""
    ks.init_identity("alice", PASSWORD)
    # Tomamos el JSON activo (que NO tiene backup_of) y lo intentamos importar.
    fake_backup = tmp_path / "no_es_backup.json"
    fake_backup.write_text((ks.dir / "alice.json").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(ValueError, match="backup"):
        import_backup(ks, str(fake_backup), PASSWORD, NEW_PASSWORD)


# ─────────────────────────────────────────────────────────────────────────────
# RUBRICA 5: Stolen keystore alone -> cannot decrypt
# ─────────────────────────────────────────────────────────────────────────────

def test_stolen_keystore_sin_password_no_puede_descifrar(tmp_path):
    """
    Escenario: el atacante copia COMPLETO el directorio del keystore.
    Sin el password del usuario, no puede:
      (a) abrir la privada del keystore,
      (b) leer los contenedores que se enviaron a esa identidad.

    Este test ejecuta todas las vias de ataque "razonables" que
    podria intentar un adversario que solo tiene el directorio:
      - unlock con password vacio
      - unlock con passwords de diccionario
      - leer el JSON crudo a ver si la privada esta en claro
    """
    # 1. Victima crea su identidad y recibe un mensaje cifrado.
    victim_ks = KeyStore(tmp_path / "victim_keystore", kdf_params=FAST_PARAMS)
    victim_ks.init_identity("alice", PASSWORD)
    victim_x_pub = victim_ks.get_public_keys("alice")["x25519_pub"]
    container = encrypt_for_recipients(
        b"informacion-confidencial-de-alice",
        filename="confidencial.txt",
        recipients=[victim_x_pub],
    )

    # 2. Atacante COPIA todo el directorio del keystore.
    stolen_dir = tmp_path / "stolen"
    shutil.copytree(victim_ks.dir, stolen_dir)
    attacker_ks = KeyStore(stolen_dir, create=False, kdf_params=FAST_PARAMS)

    # 3. El JSON robado no contiene la privada en claro.
    raw = (stolen_dir / "alice.json").read_text(encoding="utf-8")
    assert "encrypted_private_key" in raw
    # Marcadores tipicos de exportes inseguros que NO deben aparecer:
    assert "BEGIN PRIVATE KEY" not in raw
    assert "BEGIN ENCRYPTED PRIVATE KEY" not in raw

    # 4. El atacante puede leer la metadata publica (eso es por diseno).
    public_info = attacker_ks.get_public_keys("alice")
    assert public_info["fingerprints"]["ed25519"] == \
           victim_ks.get_public_keys("alice")["fingerprints"]["ed25519"]

    # 5. Sin password (o con passwords adivinados), unlock falla.
    candidate_passwords = [
        "",                               # vacio
        "password",                        # adivinanza naive
        "12345678",                        # numerico
        "alice",                           # nombre
        "alice2026",                       # nombre + ano
        "Password123",                     # mayuscula + numero corto
        "qwertyuiop",                      # secuencia de teclado
    ]
    for guess in candidate_passwords:
        with pytest.raises((InvalidTag, ValueError)):
            attacker_ks.unlock_signing_key("alice", guess)
        with pytest.raises((InvalidTag, ValueError)):
            attacker_ks.unlock_encryption_key("alice", guess)

    # 6. El atacante no puede descifrar el contenedor robado:
    #    no puede obtener la X25519 privada de la victima.
    #    Verificamos que si el atacante intentara fabricar la "privada
    #    correspondiente" haciendo unlock con un guess random, el resultado
    #    no le permite descifrar el contenedor.
    with pytest.raises(InvalidTag):
        # Esta llamada fallaria en unlock; la prueba de que el ataque
        # NO progresa esta en que nunca obtiene la privada para llegar
        # al descifrado de hybrid.
        x_priv_attacker = attacker_ks.unlock_encryption_key("alice", "guess-final-XYZ")
        decrypt_for_recipient(container, x_priv_attacker)


def test_stolen_keystore_no_puede_firmar_como_la_victima(tmp_path):
    """
    El atacante no puede firmar mensajes haciendose pasar por la
    victima sin el password. Aunque tenga la publica, sin la privada
    no puede producir firmas validas.
    """
    victim_ks = KeyStore(tmp_path / "victim", kdf_params=FAST_PARAMS)
    victim_ks.init_identity("alice", PASSWORD)
    victim_pub = victim_ks.get_public_keys("alice")["ed25519_pub"]

    stolen_dir = tmp_path / "stolen"
    shutil.copytree(victim_ks.dir, stolen_dir)
    attacker_ks = KeyStore(stolen_dir, create=False, kdf_params=FAST_PARAMS)

    for guess in ["password", "alice", "", "qwerty12345"]:
        with pytest.raises(InvalidTag):
            attacker_ks.unlock_signing_key("alice", guess)

    # Aun con la publica, el atacante no puede generar una firma valida.
    # Si lo intentara con un Ed25519 generado al vuelo, no verificaria
    # contra la publica de la victima (cubierto por test_signatures).


# ─────────────────────────────────────────────────────────────────────────────
# Orden verify -> unlock en verify_and_decrypt_from_keystore
# ─────────────────────────────────────────────────────────────────────────────
#
# Si llega un contenedor con firma forjada, la verificacion debe rechazarlo
# ANTES de desbloquear la X25519 del destinatario (que cuesta scrypt). Para
# detectar regresiones del orden combinamos firma forjada + password
# equivocado: si el unlock corriera primero, lanzaria InvalidTag por el
# password; con el orden correcto lanza InvalidSignature por la firma.

def test_firma_forjada_se_rechaza_antes_de_intentar_unlock(tmp_path):
    from cryptography.exceptions import InvalidSignature

    ks = KeyStore(tmp_path / "ks", kdf_params=FAST_PARAMS)
    ks.init_identity("alice", PASSWORD)
    ks.init_identity("bob",   PASSWORD)
    ks.init_identity("eve",   PASSWORD)

    # Eve firma con SU clave, no la de Alice. El receptor (Bob) espera a Alice.
    bob_x = ks.get_public_keys("bob")["x25519_pub"]
    container = encrypt_and_sign_from_keystore(
        ks, "eve", PASSWORD,
        plaintext=b"payload",
        filename="m.txt",
        recipients_x25519=[bob_x],
    )
    alice_ed = ks.get_public_keys("alice")["ed25519_pub"]

    # Password de Bob incorrecto a proposito: el orden correcto rechaza por
    # firma; si unlock corriera primero, veriamos InvalidTag (no InvalidSignature).
    with pytest.raises(InvalidSignature):
        verify_and_decrypt_from_keystore(
            ks, "bob", "passwordIncorrecto_2026!",
            signed_container=container,
            expected_signer_pub=alice_ed,
        )
