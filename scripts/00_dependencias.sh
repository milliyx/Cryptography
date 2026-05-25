#!/usr/bin/env bash
# =============================================================================
# scripts/00_dependencias.sh
# Verifica que el entorno tenga lo necesario para correr la entrega D6.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "00 · Verificación del entorno"

echo "Directorio:    $(pwd)"
echo "Rama git:      $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'no-git')"
echo "Commit:        $(git rev-parse --short HEAD 2>/dev/null || echo 'no-git')"
echo "Python:        $(python3 --version 2>&1)"
echo "Fecha:         $(date '+%Y-%m-%d %H:%M:%S')"

subbanner "Paquetes Python requeridos"

FAIL=0
for pkg in cryptography pytest; do
  if python3 -c "import $pkg; import sys; v=getattr(sys.modules['$pkg'],'__version__','?'); print(f'  $pkg = {v}')" 2>/dev/null; then
    :
  else
    fail "Falta el paquete '$pkg' (instalar con: pip install -r requirements.txt)"
    FAIL=$((FAIL + 1))
  fi
done

if [ "$FAIL" -eq 0 ]; then
  ok "Todas las dependencias presentes"
  exit 0
else
  fail "$FAIL dependencia(s) faltante(s)"
  exit 1
fi
