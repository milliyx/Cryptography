# GitHub Actions — CI/CD Automatizado para SDDV

**Archivo**: [.github/workflows/test.yml](.github/workflows/test.yml)

---

## 📋 ¿Qué hace?

El workflow ejecuta automáticamente:

1. **Tests unitarios** en 3 versiones de Python × 3 sistemas operativos
2. **Análisis de código** (linting, formato)
3. **Verificación de seguridad** (Bandit)
4. **Reportes de cobertura** (cuánto código está testeado)

---

## 🚀 Cómo Funciona

### **Triggers (Cuándo se ejecuta)**

```yaml
on:
  pull_request:
    branches: [ main ]  # Se ejecuta SOLO en PRs hacia main
    paths:              # Solo si cambian estos archivos:
      - 'crypto/**'     # Código
      - 'tests/**'      # Tests
      - '.github/workflows/**'
      - 'requirements*.txt'

  push:
    branches:
      - 'feature/**'    # También en pushes a ramas feature/
      - 'develop'       # O rama develop
      - 'test/**'       # O ramas test/
    paths:
      - 'crypto/**'
      - 'tests/**'
      - ...
```

**Significado Importante**:
- ✅ Se ejecuta en **Pull Requests hacia `main`** (SIEMPRE)
- ✅ Se ejecuta en **pushes a ramas feature/** (mientras las trabajas)
- ❌ **NO se ejecuta en push directo a `main`** (mantiene main estable)
- ✅ Solo si los archivos relevantes cambiaron (optimización)
- ✅ Se puede forzar manualmente desde Actions tab

**Workflow recomendado**:
```
1. Crear rama feature/add-ci-cd-testing
2. Ejecutar tests LOCALMENTE
3. Hacer commit y push a feature
4. GitHub Actions ejecuta tests (9 combinaciones)
5. Si todo verde, hacer PR a main
6. GitHub Actions ejecuta tests de nuevo
7. Si todo verde, hacer merge a main
```

---

## 🧪 JOB 1: Tests Unitarios

### Configuración (Matrix Strategy)

```yaml
strategy:
  matrix:
    python-version: ['3.10', '3.11', '3.12']
    os: [ubuntu-latest, windows-latest, macos-latest]
```

**Resultado**: **9 ejecuciones de tests** en paralelo:

```
Python 3.10 + Ubuntu    ✅
Python 3.10 + Windows   ✅
Python 3.10 + macOS     ✅
Python 3.11 + Ubuntu    ✅
Python 3.11 + Windows   ✅
Python 3.11 + macOS     ✅
Python 3.12 + Ubuntu    ✅
Python 3.12 + Windows   ✅
Python 3.12 + macOS     ✅
```

Si uno falla, los otros siguen ejecutándose (`fail-fast: false`).

### Pasos

#### 1️⃣ Descargar código

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0  # Descarga todo el historial (para análisis)
```

#### 2️⃣ Setup Python + Cache

```yaml
- uses: actions/setup-python@v4
  with:
    python-version: ${{ matrix.python-version }}
    cache: 'pip'  # ⚡ Cachea dependencias entre ejecuciones
```

**Beneficio**: Si `cryptography` está en caché, no se baja de nuevo (ahorra ~30 segundos).

#### 3️⃣ Instalar dependencias

```bash
python -m pip install --upgrade pip
pip install cryptography pytest pytest-cov pytest-xdist
```

#### 4️⃣ Ejecutar pytest CON COBERTURA

```bash
pytest tests/test_aead.py \
  -v                                 # Verbose
  --tb=short                         # Reportes cortos
  --cov=crypto                       # Medir cobertura del módulo
  --cov-report=term-missing          # Mostrar líneas no testeadas
  --cov-report=html                  # Generar reporte HTML
  --cov-report=xml                   # Generar XML (para integración)
  -x                                 # Parar en primer fallo
```

#### 5️⃣ Generar badge de cobertura

```bash
coverage-badge -o coverage.svg -f
```

Produce un archivo `coverage.svg` que puedes incrustar en README:

```markdown
![Coverage](coverage.svg)
```

#### 6️⃣ Guardar artifacts

```yaml
- uses: actions/upload-artifact@v3
  with:
    name: coverage-report-py${{ matrix.python-version }}-${{ matrix.os }}
    path: htmlcov/
    retention-days: 30
```

**Beneficio**: Después de que finalizan los tests, puedes descargar el reporte HTML.

---

## 🔍 JOB 2: Linting & Code Quality

Verifica que el código siga estándares de calidad:

### Black (Formateador)

```bash
black --check crypto/ tests/
```

Verifica que el código esté formateado correctamente (sin modificar).

Para arreglarlo localmente:
```bash
black crypto/ tests/
```

### flake8 (PEP 8)

```bash
flake8 crypto/ tests/ \
  --max-line-length=100 \
  --extend-ignore=E203,W503
```

Detecta errores de estilo (variables sin usar, imports duplicados, etc.).

### isort (Organizar imports)

```bash
isort --check-only crypto/ tests/
```

Verifica que los imports estén ordenados alfabéticamente.

Para arreglarlo:
```bash
isort crypto/ tests/
```

---

## 🔐 JOB 3: Seguridad (Bandit)

```bash
bandit -r crypto/
```

**Detecta**:
- ❌ Hardcoded passwords
- ❌ SQL injection
- ❌ Uso de `eval()`
- ❌ Permisos inseguros en archivos
- ❌ Generadores RNG no criptográficos

**Para el módulo AEAD**, esperaría:
- ✅ `os.urandom()` es seguro
- ✅ No hay SQL
- ✅ No hay hardcoded keys

Si encuentra algo sospechoso, lo reporta en `bandit-report.json`.

---

## 📊 JOB 4: Reporte Final

Resume todos los resultados en la pestaña "Summary" de Actions.

---

## 💾 Cómo Usar

### **Local (en tu máquina ahora)**

Para validar los tests ANTES de hacer PR:

```powershell
# 1. Crear rama feature
git checkout main
git pull origin main
git checkout -b feature/add-ci-cd-testing

# 2. Instalar dependencias
pip install -r requirements.txt -r requirements-dev.txt

# 3. Ejecutar tests localmente
pytest tests/test_aead.py -v

# 4. Con cobertura (opcional)
pytest tests/test_aead.py -v --cov=crypto --cov-report=html

# 5. Ver reporte HTML
start htmlcov\index.html  # Windows

# 6. Verificar linting (opcional)
black crypto/ tests/
isort crypto/ tests/
flake8 crypto/ tests/

# 7. Commit y push
git add .
git commit -m "Add GitHub Actions CI/CD"
git push -u origin feature/add-ci-cd-testing
```

### **GitHub (Automático)**

Una vez que hagas push a una rama feature o PR:

1. **GitHub Actions automáticamente**:
   - Descarga tu código
   - Instala dependencias
   - Ejecuta los 27 tests en 9 combinaciones (Python 3.10/3.11/3.12 × Ubuntu/Windows/macOS)
   - Genera reportes de cobertura

2. **Ver resultados en tu PR**:
   - Ve a tu Pull Request
   - Desplázate a "Checks"
   - Verás el status de cada job ✅ o ❌

3. **Hacer merge**:
   - Solo después de que TODOS los checks sean ✅
   - Haz clic en "Merge pull request"

---

**Flujo Completo (Para tu caso específicamente)**:

```powershell
# PASO 1: Setup local (una sola vez)
git checkout main
git pull origin main
pip install -r requirements.txt -r requirements-dev.txt

# PASO 2: Crear rama y validar localmente
git checkout -b feature/add-ci-cd-testing
pytest tests/test_aead.py -v  # Verifica que funcionan

# PASO 3: Hacer commit
git add .
git commit -m "Add CI/CD with GitHub Actions"

# PASO 4: Hacer push a la rama feature
git push -u origin feature/add-ci-cd-testing

# PASO 5: Crear PR en GitHub (interfaz web)
# GitHub → Pull Requests → New pull request
# Base: main, Compare: feature/add-ci-cd-testing
# Create pull request

# PASO 6: Esperar a que los tests pasen (ver en GitHub Actions)
# Si todo está ✅, hacer merge

# PASO 7: Merge (en GitHub)
# Haz clic en "Merge pull request"
```

---

## 📈 Interpretar Resultados

### ✅ Todo Verde

```
✅ test (9 jobs passed)
✅ lint (passed)
✅ security (passed)
```

**Significado**: Código pronto para merge.

### ⚠️ Algunas advertencias en Linting

```
✅ test (9 jobs passed)
⚠️  lint (warnings)
✅ security (passed)
```

**Significado**: Los tests pasan pero el código necesita limpieza. Ejecuta:

```bash
black crypto/ tests/
isort crypto/ tests/
```

### ❌ Tests Fallidos

```
❌ test (2 jobs failed, 7 passed)
```

**Significado**: Hay un bug. El workflow muestra:

1. Cuál test falló
2. En qué versión de Python / SO
3. El traceback del error

---

## 🎯 Salida Esperada en GitHub

Cuando veas el workflow completado:

```
✅ Descargar código
✅ Setup Python 3.10
✅ Instalar dependencias
✅ Ejecutar tests (pytest)
   ✅ test_roundtrip_devuelve_plaintext_identico[AES_256_GCM] PASSED
   ✅ test_roundtrip_devuelve_plaintext_identico[CHACHA20_POLY1305] PASSED
   ✅ test_clave_incorrecta_lanza_invalid_tag PASSED
   ✅ test_ciphertext_modificado_falla PASSED
   ... (18+ tests)
   ========================== 18 passed in 0.45s ==========================
   ========================= coverage: 100% =========================
✅ Generar reporte de cobertura
✅ Guardar reportes

✅ Verificar formato (black)
✅ Linting (flake8)
✅ Verificar orden de imports (isort)

✅ Ejecutar Bandit
```

---

## 🛠️ Personalizar

### Cambiar versiones de Python

Edit `.github/workflows/test.yml`:

```yaml
matrix:
  python-version: ['3.9', '3.10', '3.11', '3.12']  # Agrega o quita
```

### Agregar más tests

Solo crea archivos `test_*.py` en la carpeta `tests/`. El workflow los ejecutará automáticamente.

### Exigir cobertura mínima

En `pytest.ini`, descomenta:

```ini
[coverage:report]
fail_under = 80  # Falla si cobertura < 80%
```

### Cambiar dónde se ejecutan los tests

En `.github/workflows/test.yml`, modifica:

```yaml
on:
  push:
    branches:
      - 'feature/**'   # Ejecutar en ramas feature/
      - 'develop'      # Ejecutar en develop
  pull_request:
    branches: [ main ] # Ejecutar en PRs hacia main
```

**Ejemplos**:
- Solo en PRs a main (actual): ✅
- En todo push incluyendo main: cambia `branches: ['feature/**', 'develop']` a `branches: ['main', 'develop']`
- Solo en pull_requests: elimina la sección `push:`

---

## 📚 Referencias

- [GitHub Actions Docs](https://docs.github.com/actions)
- [pytest Documentation](https://docs.pytest.org/)
- [Coverage.py](https://coverage.readthedocs.io/)
- [Bandit Security](https://bandit.readthedocs.io/)

---

## ✅ Checklist de Configuración

- [ ] Crear `.github/workflows/test.yml`
- [ ] Crear `pytest.ini`
- [ ] Crear `requirements.txt` y `requirements-dev.txt`
- [ ] Hacer push a GitHub
- [ ] Verificar que Actions se ejecuta
- [ ] Todos los tests pasan ✅
