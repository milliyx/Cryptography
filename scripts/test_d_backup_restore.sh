#!/usr/bin/env bash
# =============================================================================
# scripts/test_d_backup_restore.sh
#
# RUBRIC D6 — Test (d):
#   "Backup → restore works"
#
# Verifica el ciclo completo de backup y recuperación. El backup
# se re-cifra con un password independiente para NO debilitar la seguridad.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "Test (d) · Backup → restore funciona"

info "Tests correspondientes:"
echo "  tests/test_keystore_security.py::test_backup_export_y_import_roundtrip"
echo "  tests/test_keystore_security.py::test_backup_password_incorrecto_no_descifra_backup"
echo "  tests/test_keystore_security.py::test_backup_archivo_corrupto_falla"
echo ""
info "Qué hace:"
echo "  1. Crea una identidad y la usa para cifrar un mensaje."
echo "  2. Exporta backup con password_backup distinto al operativo."
echo "  3. Borra la identidad del keystore activo."
echo "  4. Restaura desde el backup."
echo "  5. Verifica que los fingerprints Ed25519 y X25519 son IGUALES."
echo "  6. Verifica que la identidad restaurada puede descifrar el mensaje."
echo "  7. Verifica casos de error: backup corrupto, password de backup malo."

subbanner "Ejecutando"
python3 -m pytest tests/test_keystore_security.py \
  -v --tb=short \
  -k "backup"
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Test (d) PASÓ — backup y restore funcionan correctamente"
  exit 0
else
  fail "Test (d) FALLÓ"
  exit 1
fi
