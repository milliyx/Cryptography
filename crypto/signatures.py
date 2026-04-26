"""
crypto/signatures.py
====================
Modulo de firma digital para el SDDV.

Implementa firma y verificacion con Ed25519 siguiendo el patron
Encrypt-then-Sign: primero se cifra el archivo, luego se firma el
contenedor cifrado completo.

Por que Encrypt-then-Sign (no Sign-then-Encrypt):
  - Si se firmara el plaintext y luego se cifrara, el receptor tendria
    que descifrar antes de verificar la firma. Eso expone el plaintext
    antes de saber si es autentico.
  - Firmando el contenedor cifrado, el receptor puede verificar la firma
    ANTES de gastar recursos en descifrar y ANTES de aceptar el dato.
  - Ademas, si la firma del contenedor cifrado es valida, garantiza que
    el contenedor no fue modificado despues de que el remitente lo firmo.

Formato del contenedor firmado (signed container):
  [SDDV container original] || [SIGN_MAGIC(4)] || [FINGERPRINT(32)] || [SIGNATURE(64)]

  - SIGN_MAGIC:   b"SIGS" — identifica la seccion de firma
  - FINGERPRINT:  SHA-256 de la llave publica del firmante (32 bytes raw)
  - SIGNATURE:    firma Ed25519 de 64 bytes sobre TODO lo anterior

La firma cubre el contenedor SDDV completo mas el magic y el fingerprint.
Si se modifica cualquier byte del contenedor, la firma no verifica.

El fingerprint permite al receptor saber que llave publica usar para
verificar, sin necesidad de un canal separado para anunciarlo.
"""

import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ────────────────────────── constantes ───────────────────────────────────────

SIGN_MAGIC       = b"SIGS"   # marca el inicio de la seccion de firma
FINGERPRINT_SIZE = 32        # SHA-256 = 32 bytes
SIGNATURE_SIZE   = 64        # Ed25519 produce siempre 64 bytes
SIGN_FOOTER_SIZE = len(SIGN_MAGIC) + FINGERPRINT_SIZE + SIGNATURE_SIZE  # 100 bytes


# ─────────────────────────── funciones internas ───────────────────────────────

def _get_pubkey_raw(public_key) -> bytes:
    """Extrae los 32 bytes raw de la llave publica Ed25519."""
    return public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)


def _fingerprint_from_raw(raw_bytes: bytes) -> bytes:
    """SHA-256 de los bytes raw de la llave publica (32 bytes)."""
    return hashlib.sha256(raw_bytes).digest()


# ─────────────────────────── interfaz publica ────────────────────────────────

def sign_container(container: bytes, private_key) -> bytes:
    """
    Firma un contenedor SDDV y retorna el contenedor firmado.

    El contenedor firmado tiene el mismo contenido que el original mas
    100 bytes al final (magic + fingerprint + firma).

    La firma se calcula sobre: container + SIGN_MAGIC + fingerprint
    Esto vincula la identidad del firmante (fingerprint) a la firma,
    evitando que se sustituya el fingerprint sin invalidar la firma.

    Parametros:
        container:   bytes del contenedor SDDV (cifrado)
        private_key: objeto Ed25519PrivateKey del firmante

    Retorna:
        signed_container: bytes
    """
    public_key  = private_key.public_key()
    pubkey_raw  = _get_pubkey_raw(public_key)
    fingerprint = _fingerprint_from_raw(pubkey_raw)

    # Los datos que se firman = container + magic + fingerprint
    # (incluir el fingerprint en los datos firmados evita sustitucion de identidad)
    data_to_sign = container + SIGN_MAGIC + fingerprint

    signature = private_key.sign(data_to_sign)

    return container + SIGN_MAGIC + fingerprint + signature


def verify_container(signed_container: bytes, public_key) -> bytes:
    """
    Verifica la firma de un contenedor firmado y retorna el contenedor original.

    Siempre verificar ANTES de descifrar. Si la firma no verifica, no se
    debe pasar el contenedor a decrypt_file() ni decrypt_file_with_password().

    Parametros:
        signed_container: bytes del contenedor firmado
        public_key:       objeto Ed25519PublicKey del remitente esperado

    Retorna:
        container: bytes del contenedor SDDV original (sin la firma)

    Lanza:
        InvalidSignature — si la firma no es valida o la llave publica no coincide
        ValueError       — si el formato del contenedor firmado es invalido
    """
    if len(signed_container) < SIGN_FOOTER_SIZE:
        raise ValueError(
            f"Contenedor firmado demasiado corto: minimo {SIGN_FOOTER_SIZE} bytes"
        )

    # Separar las secciones
    container_end = len(signed_container) - SIGN_FOOTER_SIZE
    container     = signed_container[:container_end]
    footer        = signed_container[container_end:]

    magic       = footer[:4]
    fingerprint = footer[4:4 + FINGERPRINT_SIZE]
    signature   = footer[4 + FINGERPRINT_SIZE:]

    if magic != SIGN_MAGIC:
        raise ValueError(
            "Magic de firma invalido — este contenedor no tiene firma SDDV"
        )

    # Verificar que el fingerprint corresponde a la llave publica dada
    pubkey_raw          = _get_pubkey_raw(public_key)
    expected_fingerprint = _fingerprint_from_raw(pubkey_raw)

    if fingerprint != expected_fingerprint:
        raise InvalidSignature(
            "El fingerprint del contenedor no coincide con la llave publica proporcionada"
        )

    # Verificar la firma sobre (container + magic + fingerprint)
    # Lanza InvalidSignature si la firma no es valida
    data_to_verify = container + SIGN_MAGIC + fingerprint
    public_key.verify(signature, data_to_verify)

    return container


def get_signer_fingerprint(signed_container: bytes) -> str:
    """
    Extrae el fingerprint del firmante de un contenedor firmado (hex, 64 chars).

    Util para identificar quien firmo el contenedor antes de buscar su
    llave publica en un directorio o key store.

    Lanza:
        ValueError — si el contenedor no tiene firma valida
    """
    if len(signed_container) < SIGN_FOOTER_SIZE:
        raise ValueError("Contenedor demasiado corto para tener firma")

    container_end = len(signed_container) - SIGN_FOOTER_SIZE
    footer        = signed_container[container_end:]
    magic         = footer[:4]

    if magic != SIGN_MAGIC:
        raise ValueError("El contenedor no tiene firma SDDV")

    fingerprint_bytes = footer[4:4 + FINGERPRINT_SIZE]
    return fingerprint_bytes.hex()


def is_signed(data: bytes) -> bool:
    """
    Verifica rapido si un contenedor tiene firma SDDV (no verifica la firma).
    Solo comprueba la presencia del magic de firma.
    """
    if len(data) < SIGN_FOOTER_SIZE:
        return False
    footer_start = len(data) - SIGN_FOOTER_SIZE
    return data[footer_start:footer_start + 4] == SIGN_MAGIC


# ════════════════════════════════════════════════════════════════════════════
# D4 — Wrappers para contenedores hibridos (SDDH)
# ════════════════════════════════════════════════════════════════════════════
#
# El patron Encrypt-then-Sign aplica identicamente a contenedores SDDH (D3):
# se firma el blob completo del contenedor cifrado. La firma cubre por
# transitividad TODO lo que el contenedor SDDH cubre con su propio AAD:
# magic, version, algo, timestamp, filename, lista de destinatarios completa,
# nonce del DEM, ciphertext y tag.
#
# Estas funciones existen como API semantica explicita: el codigo cliente
# debe leer "firmo el contenedor hibrido" y no "firmo bytes arbitrarios".

def sign_hybrid_container(sddh_container: bytes, signer_priv) -> bytes:
    """
    Firma un contenedor hibrido SDDH (D3) siguiendo Encrypt-then-Sign.

    El layout resultante es identico al de los contenedores SDDV firmados:
        SDDH_container || SIGN_MAGIC(4) || FINGERPRINT(32) || SIGNATURE(64)

    La firma cubre el contenedor SDDH completo, por lo que cualquier
    modificacion (ciphertext, tag, lista de destinatarios, metadata, nonce)
    invalida la verificacion. Como el AEAD del DEM ya cubre el AAD por
    construccion, el atacante necesita romper Ed25519 ademas de GCM para
    forjar un contenedor.

    Parametros:
        sddh_container : contenedor hibrido producido por encrypt_for_recipients
        signer_priv    : Ed25519PrivateKey del firmante

    Retorna:
        bytes — contenedor SDDH firmado, listo para almacenar/transmitir
    """
    return sign_container(sddh_container, signer_priv)


def verify_hybrid_container(signed_sddh: bytes, signer_pub) -> bytes:
    """
    Verifica la firma de un contenedor SDDH firmado y retorna el SDDH limpio.

    Esta funcion debe llamarse SIEMPRE antes de invocar decrypt_for_recipient.
    Si lanza, no se debe descifrar — esa es la garantia de seguridad de D4.

    Parametros:
        signed_sddh : contenedor SDDH con footer de firma
        signer_pub  : Ed25519PublicKey del firmante esperado

    Retorna:
        bytes — el contenedor SDDH original (sin el footer de firma),
                listo para pasar a decrypt_for_recipient

    Lanza:
        InvalidSignature — firma invalida o llave publica equivocada
        ValueError       — formato del contenedor firmado invalido
    """
    return verify_container(signed_sddh, signer_pub)
