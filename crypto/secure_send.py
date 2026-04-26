"""
crypto/secure_send.py
=====================
API de alto nivel para el flujo D5 completo del SDDV.

Combina D3 (cifrado hibrido multi-destinatario) y D5 (firma digital) en
dos funciones que fuerzan el orden de operaciones correcto:

    Cifrar -> Anadir metadata -> Firmar -> Almacenar
    Leer   -> Verificar firma -> Descifrar

Por que una API combinada en lugar de exponer las primitivas sueltas:

  1. El orden importa. Si la app llama decrypt antes de verify, gasta CPU
     en datos potencialmente forjados y puede filtrar timing al atacante.
     Una API combinada hace imposible saltarse el verify.

  2. Misuse-resistance. El mismo principio detras de NaCl crypto_box: si
     dos primitivas SOLO se deben combinar de una forma, exponer solo la
     combinacion correcta. El que escribe la app no puede equivocarse.

  3. El codigo cliente queda alineado al rubric del entregable D5:
     "Encrypt -> Add metadata -> Sign -> Store" en una linea.

Las primitivas sueltas (encrypt_for_recipients, sign_hybrid_container, etc)
siguen disponibles para casos avanzados o tests; pero el camino feliz pasa
por las dos funciones de aqui.
"""

from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from crypto.aead import Algorithm
from crypto.hybrid import (
    encrypt_for_recipients,
    decrypt_for_recipient,
)
from crypto.signatures import (
    sign_hybrid_container,
    verify_hybrid_container,
)


# ─────────────────────────── flujo de envio ──────────────────────────────────

def secure_encrypt_and_sign(
    plaintext: bytes,
    filename: str,
    recipients: List[X25519PublicKey],
    signer_priv: Ed25519PrivateKey,
    algo: Algorithm = Algorithm.AES_256_GCM,
    timestamp: Optional[int] = None,
) -> bytes:
    """
    Flujo de envio D5 completo: cifra hibridamente y firma el resultado.

    Orden de operaciones (Encrypt-then-Sign):
        1. Genera file_key aleatorio (DEM key).
        2. Para cada destinatario, envuelve file_key con X25519 ECDH + HKDF + AES-GCM.
        3. Cifra el plaintext con file_key; el AAD incluye toda la cabecera
           (metadata + lista de destinatarios).
        4. Firma con Ed25519 el contenedor SDDH completo + identidad del firmante.

    Parametros:
        plaintext   : bytes a proteger
        filename    : nombre del archivo (queda autenticado en el AAD)
        recipients  : lista de claves publicas X25519 de los destinatarios
        signer_priv : clave privada Ed25519 del remitente
        algo        : AES_256_GCM (default) o CHACHA20_POLY1305
        timestamp   : Unix timestamp opcional; None usa time.time()

    Retorna:
        bytes — contenedor SDDH firmado, listo para transmitir o guardar.

    Lanza:
        ValueError — si la lista de destinatarios esta vacia.
    """
    sddh = encrypt_for_recipients(
        plaintext=plaintext,
        filename=filename,
        recipients=recipients,
        algo=algo,
        timestamp=timestamp,
    )
    return sign_hybrid_container(sddh, signer_priv)


# ─────────────────────────── flujo de recepcion ──────────────────────────────

def secure_verify_and_decrypt(
    signed_container: bytes,
    expected_signer_pub: Ed25519PublicKey,
    recipient_priv: X25519PrivateKey,
) -> Tuple[bytes, dict]:
    """
    Flujo de recepcion D5 completo: verifica firma y, solo si pasa, descifra.

    Orden de operaciones (Verify-first):
        1. Verifica la firma Ed25519 con la llave publica esperada.
           Si falla -> InvalidSignature antes de gastar CPU descifrando.
        2. Verificada la firma, busca la entrada del destinatario en el SDDH
           y desenvuelve file_key con X25519 ECDH.
        3. Descifra el contenido con AES-GCM/ChaCha20-Poly1305.
           El AAD del DEM autentica los metadatos y la lista de destinatarios.

    Por que verify-first y no decrypt-first:
        - Si la firma es forjada, no tiene sentido descifrar.
        - Descifrar primero gastaria CPU en datos potencialmente falsos.
        - Algunas implementaciones laxas filtran timing al distinguir
          "ciphertext valido pero firma falsa" vs "ciphertext invalido";
          verificar primero hace que toda firma falsa tarde lo mismo.
        - Si la app procesa el plaintext "tentativo" antes de verificar,
          los efectos secundarios pueden ser irreversibles (ej: enviar email).

    Parametros:
        signed_container    : contenedor SDDH firmado
        expected_signer_pub : llave publica Ed25519 del firmante esperado
        recipient_priv      : llave privada X25519 del destinatario

    Retorna:
        (plaintext, metadata) — bytes originales y diccionario con info del
                                contenedor (filename, algo, timestamp,
                                lista de fingerprints de destinatarios).

    Lanza:
        InvalidSignature — la firma no verifica con expected_signer_pub.
        ValueError       — el destinatario no esta autorizado o el formato
                           del contenedor es invalido.
        InvalidTag       — clave incorrecta o el contenedor fue manipulado
                           DESPUES de la firma (caso muy improbable: la firma
                           ya cubre todo, pero la verificacion AEAD es la
                           segunda capa de defensa).
    """
    # 1. VERIFICAR — si esto falla, abortar ANTES de tocar cripto pesada
    sddh_clean = verify_hybrid_container(signed_container, expected_signer_pub)

    # 2. DESCIFRAR — solo si la firma paso
    plaintext, metadata = decrypt_for_recipient(sddh_clean, recipient_priv)

    return plaintext, metadata
