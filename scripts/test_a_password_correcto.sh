#!/usr/bin/env bash
# =============================================================================
# scripts/test_a_password_correcto.sh
#
# RUBRIC D6 — Test (a):
#   "Correct password → access granted"
#
# Verifica que con el password correcto se pueden desbloquear
# las llaves privadas Ed25519 y X25519 del keystore.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "Test (a) · Password correcto → acceso concedido"

info "Test correspondiente:"
echo "  tests/test_keystore_security.py::test_correct_password_grants_access"
echo ""
info "Qué hace:"
echo "  1. Crea una identidad nueva con un password fuerte."
echo "  2. Vuelve a abrir el keystore con ese mismo password."
echo "  3. Verifica que se obtiene el Ed25519PrivateKey real (firma de prueba)."
echo "  4. Verifica que se obtiene el X25519PrivateKey real (deriva shared secret)."

subbanner "Ejecutando"
python3 -m pytest tests/test_keystore_security.py::test_correct_password_grants_access -v --tb=short
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Test (a) PASÓ — el password correcto da acceso a las llaves"
  exit 0
else
  fail "Test (a) FALLÓ"
  exit 1
fi
