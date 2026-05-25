#!/usr/bin/env bash
# =============================================================================
# scripts/test_b_password_incorrecto.sh
#
# RUBRIC D6 — Test (b):
#   "Wrong password → access denied"
#
# Verifica que con un password incorrecto el sistema rechaza el acceso
# y no devuelve la llave privada. Se prueba con varios passwords malos.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "Test (b) · Password incorrecto → acceso denegado"

info "Test correspondiente:"
echo "  tests/test_keystore_security.py::test_wrong_password_denies_access"
echo "  (parametrizado con 5 variantes de password incorrecto)"
echo ""
info "Qué hace:"
echo "  1. Crea una identidad con password PWD_VALIDO."
echo "  2. Intenta abrir el keystore con 5 passwords distintos a PWD_VALIDO:"
echo "       - off-by-one (un char distinto)"
echo "       - vacío"
echo "       - sin la mayúscula"
echo "       - sin el caracter especial"
echo "       - completamente distinto"
echo "  3. Verifica que TODOS lanzan InvalidTag (no se obtiene la llave)."

subbanner "Ejecutando"
python3 -m pytest tests/test_keystore_security.py::test_wrong_password_denies_access -v --tb=short
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Test (b) PASÓ — todos los passwords incorrectos fueron rechazados"
  exit 0
else
  fail "Test (b) FALLÓ"
  exit 1
fi
