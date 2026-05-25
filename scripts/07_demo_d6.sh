#!/usr/bin/env bash
# =============================================================================
# scripts/07_demo_d6.sh
# Corre la demo end-to-end del ciclo de vida D6: init → unlock → firma →
# rotación → backup → restore.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "07 · Demo end-to-end del ciclo D6"

if [ ! -f demo_d6.py ]; then
  fail "demo_d6.py no encontrado en $(pwd)"
  exit 1
fi

info "Escenarios cubiertos por la demo:"
echo "  1. Crear identidades alice y bob en el keystore."
echo "  2. Mostrar la estructura del JSON en disco."
echo "  3. Verificar que un password incorrecto es rechazado."
echo "  4. Alice firma y cifra un documento para Bob."
echo "  5. Bob verifica y descifra usando su keystore."
echo "  6. Rotar las llaves de Alice (archivar las viejas)."
echo "  7. Backup → borrar → restore con password distinto."

subbanner "Ejecutando demo_d6.py"
python3 demo_d6.py
RESULT=$?

echo ""
if [ "$RESULT" -eq 0 ]; then
  ok "Demo D6 ejecutada sin errores"
  echo ""
  info "Nota: la demo dejó archivos en demo_keystore/ y demo_keystore_backups/"
  echo "  Para limpiarlos: rm -rf demo_keystore demo_keystore_backups"
  exit 0
else
  fail "La demo falló"
  exit 1
fi
