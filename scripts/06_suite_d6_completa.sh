#!/usr/bin/env bash
# =============================================================================
# scripts/06_suite_d6_completa.sh
# Corre TODOS los tests del módulo D6 Key Management (no solo los del rubric).
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "06 · Suite completa de tests D6 (Key Management)"

info "Archivos de test cubiertos:"
echo "  tests/test_kdf.py                 — Derivación scrypt"
echo "  tests/test_keystore.py            — API principal del KeyStore"
echo "  tests/test_keystore_format.py     — Validación del formato JSON v1"
echo "  tests/test_keystore_lifecycle.py  — rotate / revoke / expire / delete"
echo "  tests/test_keystore_security.py   — Los 5 tests del rubric (a-e)"

subbanner "Ejecutando"
python3 -m pytest \
  tests/test_kdf.py \
  tests/test_keystore.py \
  tests/test_keystore_format.py \
  tests/test_keystore_lifecycle.py \
  tests/test_keystore_security.py \
  -v --tb=short
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Suite D6 completa: todos los tests pasan"
  exit 0
else
  fail "Algún test de la suite D6 falló"
  exit 1
fi
