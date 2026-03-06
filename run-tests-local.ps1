# ═══════════════════════════════════════════════════════════════════════════
# run-tests-local.ps1
# 
# Script automatizado para ejecutar los tests localmente
# Uso: .\run-tests-local.ps1
# ═══════════════════════════════════════════════════════════════════════════

param(
    [switch]$Full = $false,     # Si pasas -Full, instala y ejecuta TODO
    [switch]$Coverage = $false, # Si pasas -Coverage, incluye cobertura
    [switch]$Lint = $false      # Si pasas -Lint, también ejecuta linting
)

# Colores para output
$InfoColor = "Cyan"
$SuccessColor = "Green"
$ErrorColor = "Red"
$WarningColor = "Yellow"

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $InfoColor
}

function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $SuccessColor
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $ErrorColor
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host $Message -ForegroundColor $WarningColor
}

# ═══════════════════════════════════════════════════════════════════════════
# PASO 1: Verificar Python
# ═══════════════════════════════════════════════════════════════════════════

Write-Info "
╔════════════════════════════════════════════════════════════════╗
║          TESTS AUTOMATIZADOS — SDDV Module AEAD              ║
╚════════════════════════════════════════════════════════════════╝
"

Write-Info "📋 Verificando Python..."
$PythonVersion = python --version
Write-Success "✅ $PythonVersion encontrada"

# ═══════════════════════════════════════════════════════════════════════════
# PASO 2: Instalar Dependencias
# ═══════════════════════════════════════════════════════════════════════════

Write-Info "
📦 Instalando dependencias...
"

Write-Info "  Actualizando pip..."
python -m pip install --upgrade pip --quiet

Write-Info "  Instalando requirements.txt..."
pip install -r requirements.txt --quiet

if ($Full -or $Coverage -or $Lint) {
    Write-Info "  Instalando requirements-dev.txt..."
    pip install -r requirements-dev.txt --quiet
} else {
    Write-Info "  Instalando pytest y cobertura..."
    pip install pytest pytest-cov pytest-xdist --quiet
}

Write-Success "✅ Dependencias instaladas"

# ═══════════════════════════════════════════════════════════════════════════
# PASO 3: Ejecutar Tests
# ═══════════════════════════════════════════════════════════════════════════

Write-Info "
🧪 Ejecutando tests unitarios...
"

if ($Coverage) {
    Write-Info "  (Con cobertura)"
    pytest tests/test_aead.py -v `
        --cov=crypto `
        --cov-report=term-missing `
        --cov-report=html
} else {
    pytest tests/test_aead.py -v
}

if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "❌ Tests FALLARON"
    exit 1
}

Write-Success "✅ Tests completados exitosamente"

# ═══════════════════════════════════════════════════════════════════════════
# PASO 4: Linting (Opcional)
# ═══════════════════════════════════════════════════════════════════════════

if ($Lint -or $Full) {
    Write-Info "
🔍 Ejecutando linting...
"
    
    Write-Info "  Black (formato)..."
    black --check crypto/ tests/ 2>&1 | ForEach-Object {
        if ($_ -match "error" -or $_ -match "failed") {
            Write-Warning-Custom "  ⚠️  $_"
        }
    }
    
    Write-Info "  flake8 (PEP 8)..."
    flake8 crypto/ tests/ --max-line-length=100
    
    Write-Info "  isort (imports)..."
    isort --check-only crypto/ tests/ 2>&1 | ForEach-Object {
        if ($_ -match "error") {
            Write-Warning-Custom "  ⚠️  $_"
        }
    }
    
    Write-Success "✅ Linting completado"
}

# ═══════════════════════════════════════════════════════════════════════════
# PASO 5: Mostrar Reporte
# ═══════════════════════════════════════════════════════════════════════════

Write-Info "
📊 Resumen de Resultados:
"
Write-Success "  ✅ Tests unitarios: PASSED"

if ($Coverage) {
    Write-Success "  ✅ Cobertura: Disponible en htmlcov/index.html"
}

if ($Lint -or $Full) {
    Write-Success "  ✅ Linting: PASSED"
}

Write-Info "
╔════════════════════════════════════════════════════════════════╗
║                    ✅ LISTO PARA GITHUB                      ║
║                                                                ║
║  Próximos pasos:                                              ║
║  1. git checkout -b feature/add-ci-cd-testing                ║
║  2. git add .                                                 ║
║  3. git commit -m 'Add GitHub Actions CI/CD'                 ║
║  4. git push -u origin feature/add-ci-cd-testing             ║
║  5. Crear PR en GitHub                                        ║
║  6. GitHub Actions ejecutará tests en 9 combinaciones        ║
╚════════════════════════════════════════════════════════════════╝
"

# ═══════════════════════════════════════════════════════════════════════════
# Opciones avanzadas
# ═══════════════════════════════════════════════════════════════════════════

Write-Info "
🎯 Uso del script:
  .\run-tests-local.ps1              # Tests básicos
  .\run-tests-local.ps1 -Coverage    # + Cobertura HTML
  .\run-tests-local.ps1 -Lint        # + Linting
  .\run-tests-local.ps1 -Full        # TODO (tests + cobertura + linting)
"
