#!/usr/bin/env bash
# =============================================================================
# scripts/test_e_keystore_robado.sh
#
# RUBRIC D6 — Test (e):
#   "Stolen keystore alone → cannot decrypt"
#
# Verifica el escenario donde un atacante OBTIENE el archivo del keystore
# (por filtración del disco) pero no tiene el password. Debe ser imposible
# extraer la llave privada o firmar como la víctima.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "Test (e) · Keystore robado sin password → no se puede descifrar"

info "Tests correspondientes:"
echo "  tests/test_keystore_security.py::test_stolen_keystore_sin_password_no_puede_descifrar"
echo "  tests/test_keystore_security.py::test_stolen_keystore_no_puede_firmar_como_la_victima"
echo ""
info "Qué hace:"
echo "  1. La víctima crea su keystore con un password fuerte."
echo "  2. Un atacante COPIA literalmente el archivo .json."
echo "  3. El atacante intenta:"
echo "       - Abrir el archivo y leer la llave privada en claro    → no aparece."
echo "       - Probar 7 passwords típicos de diccionario             → todos fallan."
echo "       - Modificar 'status' a 'active' si estaba revocado     → falla por tag."
echo "       - Firmar un mensaje haciéndose pasar por la víctima    → imposible."
echo "  4. Verifica que ninguna estrategia funciona."

subbanner "Ejecutando"
python3 -m pytest tests/test_keystore_security.py \
  -v --tb=short \
  -k "stolen_keystore"
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Test (e) PASÓ — el keystore robado es inútil sin el password"
  exit 0
else
  fail "Test (e) FALLÓ"
  exit 1
fi
