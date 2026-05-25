#!/usr/bin/env bash
# =============================================================================
# scripts/test_c_keystore_modificado.sh
#
# RUBRIC D6 — Test (c):
#   "Modified keystore → failure"
#
# Verifica que cualquier modificación al keystore (byte a byte, truncado,
# o swap de parámetros KDF) hace que el descifrado falle por AEAD tag.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "Test (c) · Keystore modificado → falla"

info "Tests correspondientes:"
echo "  tests/test_keystore_security.py::test_modified_keystore_byte_a_byte_falla"
echo "  tests/test_keystore_security.py::test_modified_keystore_truncado_falla"
echo "  tests/test_keystore_security.py::test_modified_keystore_swap_de_kdf_params_falla"
echo ""
info "Qué hace:"
echo "  1. Genera un keystore válido."
echo "  2. Aplica 3 tipos de ataque:"
echo "       a) Flipea un byte en cada campo (ciphertext, tag, salt, nonce)."
echo "       b) Trunca el archivo a la mitad."
echo "       c) Intercambia parámetros KDF (n=2^10 → n=2^20)."
echo "  3. Verifica que CADA modificación produce InvalidTag al intentar abrir."

subbanner "Ejecutando"
python3 -m pytest tests/test_keystore_security.py \
  -v --tb=short \
  -k "test_modified_keystore"
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Test (c) PASÓ — toda modificación al keystore es detectada"
  exit 0
else
  fail "Test (c) FALLÓ"
  exit 1
fi
