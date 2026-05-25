# =============================================================================
# scripts/_common.sh — helpers compartidos por los scripts de verificación D6
# Source desde otros scripts con:   source "$(dirname "$0")/_common.sh"
# =============================================================================

# Colores ----------------------------------------------------------------------
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export BOLD='\033[1m'
export NC='\033[0m'

# Helpers ----------------------------------------------------------------------
banner() {
  local title="$1"
  echo ""
  echo -e "${BLUE}${BOLD}╔════════════════════════════════════════════════════════════════════╗${NC}"
  printf "${BLUE}${BOLD}║  %-66s║${NC}\n" "$title"
  echo -e "${BLUE}${BOLD}╚════════════════════════════════════════════════════════════════════╝${NC}"
}

subbanner() {
  echo ""
  echo -e "${CYAN}── $1 ───────────────────────────────────────────────${NC}"
}

ok()   { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }
info() { echo -e "${YELLOW}▶ $1${NC}"; }

# Asegurar cwd = raíz del proyecto ---------------------------------------------
project_root() {
  cd "$(dirname "$0")/.." && pwd
}
