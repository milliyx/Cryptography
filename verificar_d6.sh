#!/usr/bin/env bash
# =============================================================================
# verificar_d6.sh — ORQUESTADOR de la verificación de la entrega D6
# SDDV — UNAM 2026-2
#
# Corre, en orden, todos los scripts del directorio scripts/.
# Cada script se puede correr también de forma independiente, por ejemplo:
#     bash scripts/test_a_password_correcto.sh
#     bash scripts/test_d_backup_restore.sh
#
# Salida final: tabla resumen con PASS/FAIL por cada script.
# =============================================================================
set -uo pipefail
source "$(dirname "$0")/scripts/_common.sh"

# Dos arrays paralelos (compatible con bash 3.2 de macOS) ---------------------
SCRIPTS=(
  "scripts/00_dependencias.sh"
  "scripts/test_a_password_correcto.sh"
  "scripts/test_b_password_incorrecto.sh"
  "scripts/test_c_keystore_modificado.sh"
  "scripts/test_d_backup_restore.sh"
  "scripts/test_e_keystore_robado.sh"
  "scripts/06_suite_d6_completa.sh"
  "scripts/07_demo_d6.sh"
  "scripts/08_documentacion.sh"
)

LABELS=(
  "00 · Dependencias"
  "(a) Password correcto    → acceso"
  "(b) Password incorrecto  → denegado"
  "(c) Keystore modificado  → falla"
  "(d) Backup → restore     funciona"
  "(e) Keystore robado      → no descifra"
  "06 · Suite D6 completa"
  "07 · Demo end-to-end"
  "08 · Documentación"
)

# Array de resultados (paralelo) ----------------------------------------------
RESULTS=()
PASS=0
FAIL=0

banner "VERIFICACIÓN COMPLETA DE LA ENTREGA D6"
echo ""
echo "Se ejecutarán ${#SCRIPTS[@]} scripts. Cada uno es ejecutable independientemente."
echo ""

i=0
while [ $i -lt ${#SCRIPTS[@]} ]; do
  script="${SCRIPTS[$i]}"
  if bash "$script"; then
    RESULTS+=("PASS")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL")
    FAIL=$((FAIL + 1))
  fi
  i=$((i + 1))
done

# Tabla resumen ---------------------------------------------------------------
banner "TABLA RESUMEN"
echo ""
printf "  %-46s  %s\n" "SCRIPT" "RESULTADO"
printf "  %-46s  %s\n" "----------------------------------------------" "---------"
i=0
while [ $i -lt ${#SCRIPTS[@]} ]; do
  label="${LABELS[$i]}"
  result="${RESULTS[$i]}"
  if [ "$result" = "PASS" ]; then
    printf "  %-46s  ${GREEN}✓ PASS${NC}\n" "$label"
  else
    printf "  %-46s  ${RED}✗ FAIL${NC}\n" "$label"
  fi
  i=$((i + 1))
done

echo ""
echo "  ────────────────────────────────────────────────────────────"
echo -e "  Total: ${#SCRIPTS[@]}    ${GREEN}PASS: $PASS${NC}    ${RED}FAIL: $FAIL${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✓ TODO OK — la entrega D6 está lista para subir al Classroom${NC}"
  echo ""
  echo "Artefactos a subir:"
  echo "  • docs/D6_Key_Management.pdf      (documento de diseño principal)"
  echo "  • docs/D1_Threat_Model.pdf        (modelo de amenazas con §6 D6)"
  echo "  • Link al repo o a la rama feature/d6-key-management"
  echo "  • Captura de pantalla de esta tabla como evidencia"
  exit 0
else
  echo -e "${RED}${BOLD}✗ Hay $FAIL script(s) fallido(s). Revisar los logs arriba.${NC}"
  exit 1
fi
