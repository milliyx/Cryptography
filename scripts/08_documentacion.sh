#!/usr/bin/env bash
# =============================================================================
# scripts/08_documentacion.sh
# Verifica la presencia de los entregables de documentación D6.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/_common.sh"
cd "$(project_root)"

banner "08 · Verificación de documentación entregable"

DOCS=(
  "docs/D6_Key_Management.md"
  "docs/D6_Key_Management.pdf"
  "docs/D1_Threat_Model.md"
  "docs/D1_Threat_Model.pdf"
)

FALTANTES=0
for doc in "${DOCS[@]}"; do
  if [ -f "$doc" ]; then
    size=$(ls -lh "$doc" | awk '{print $5}')
    ok "$doc  ($size)"
  else
    fail "$doc — FALTA"
    FALTANTES=$((FALTANTES + 1))
  fi
done

echo ""
if [ "$FALTANTES" -eq 0 ]; then
  ok "Todos los documentos están presentes"
  echo ""
  info "Si falta regenerar los PDFs:"
  echo "  pandoc docs/D6_Key_Management.md -o docs/D6_Key_Management.pdf \\"
  echo "    --pdf-engine=xelatex -V mainfont='Arial Unicode MS' \\"
  echo "    -V monofont=Menlo -V geometry:margin=2cm --toc"
  exit 0
else
  fail "$FALTANTES documento(s) faltante(s)"
  exit 1
fi
