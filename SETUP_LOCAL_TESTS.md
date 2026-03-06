# 🚀 Guía: Tests Locales + Pull Request

**Objetivo**: Validar que los tests unitarios funcionan localmente ANTES de hacer PR a GitHub.

---

## 📝 Resumen del Flujo

```
1. Crear rama feature          (local)
2. Instalar dependencias       (local)
3. Ejecutar tests localmente   (local)
4. Verificar cobertura         (local)
5. Hacer commit                (local)
6. Hacer PR a main en GitHub   (GitHub)
7. Esperar a que GitHub Actions ejecute tests en 9 combinaciones
8. Revisar resultados en GitHub
9. Hacer merge si todo pasó    (GitHub)
```

---

## ⚙️ PASO 1: Crear Rama Feature

Abre PowerShell en tu proyecto:

```powershell
cd C:\Users\sergi\Desktop\Criptografia\Cryptography

# Asegurate de estar en main y tener cambios sincronizados
git checkout main
git pull origin main

# Crear rama feature NUEVA
git checkout -b feature/add-ci-cd-testing
```

**Explicación**:
- `git checkout main` — cambia a rama main
- `git pull origin main` — trae últimos cambios de GitHub
- `git checkout -b feature/add-ci-cd-testing` — crea rama nueva basada en main

**Nota**: El nombre `feature/add-ci-cd-testing` sigue el patrón. Puedes usar otro nombre, pero GitHub Actions SOLO ejecutará en:
- Ramas que empiezan con `feature/`
- Rama `develop`
- Rama `test/`

---

## 📦 PASO 2: Instalar Dependencias Localmente

### Opción A: Instalar SOLO lo necesario para tests

```powershell
# Actualizar pip
python -m pip install --upgrade pip

# Instalar dependencias del módulo
pip install -r requirements.txt

# Instalar herramientas de testing
pip install pytest pytest-cov pytest-xdist
```

### Opción B: Instalar TODO (producción + desarrollo + linting + seguridad)

```powershell
# Instalar todo en una línea
pip install -r requirements.txt -r requirements-dev.txt
```

**Recomendación**: Usa **Opción B** para validar también linting y seguridad localmente.

---

## 🧪 PASO 3: Ejecutar Tests Localmente

### Test Básico (sin cobertura)

```powershell
pytest tests/test_aead.py -v
```

**Salida esperada**:
```
tests/test_aead.py::test_roundtrip_devuelve_plaintext_identico[AES_256_GCM] PASSED
tests/test_aead.py::test_roundtrip_devuelve_plaintext_identico[CHACHA20_POLY1305] PASSED
tests/test_aead.py::test_roundtrip_archivo_vacio PASSED
tests/test_aead.py::test_roundtrip_archivo_grande PASSED
tests/test_aead.py::test_roundtrip_nombre_con_caracteres_unicode PASSED
tests/test_aead.py::test_roundtrip_preserva_timestamp PASSED
tests/test_aead.py::test_clave_incorrecta_lanza_invalid_tag PASSED
tests/test_aead.py::test_clave_de_ceros_falla PASSED
tests/test_aead.py::test_clave_correcta_pero_un_bit_diferente_falla PASSED
tests/test_aead.py::test_ciphertext_modificado_falla PASSED
tests/test_aead.py::test_ciphertext_byte_final_modificado_falla PASSED
tests/test_aead.py::test_contenedor_truncado_falla PASSED
tests/test_aead.py::test_contenedor_con_bytes_extra_falla PASSED
tests/test_aead.py::test_version_en_cabecera_modificada_falla PASSED
tests/test_aead.py::test_algo_id_en_cabecera_modificado_falla PASSED
tests/test_aead.py::test_timestamp_en_cabecera_modificado_falla PASSED
tests/test_aead.py::test_filename_en_cabecera_modificado_falla PASSED
tests/test_aead.py::test_magic_bytes_invalidos_falla PASSED
tests/test_aead.py::test_mismo_plaintext_misma_clave_produce_ciphertexts_distintos PASSED
tests/test_aead.py::test_claves_distintas_producen_ciphertexts_distintos PASSED
tests/test_aead.py::test_nonces_son_unicos_en_100_cifrados PASSED
tests/test_aead.py::test_claves_generadas_son_unicas PASSED
tests/test_aead.py::test_chacha20_roundtrip_completo PASSED
tests/test_aead.py::test_chacha20_ciphertext_modificado_falla PASSED
tests/test_aead.py::test_clave_de_tamano_incorrecto_lanza_error PASSED
tests/test_aead.py::test_roundtrip_datos_binarios_arbitrarios PASSED
tests/test_aead.py::test_tag_modificado_falla PASSED

========================== 27 passed in 0.65s ==========================
```

✅ **Si ves "27 passed"**, los tests funcionan.

---

## 📊 PASO 4: Ejecutar Tests CON COBERTURA

```powershell
pytest tests/test_aead.py -v --cov=crypto --cov-report=term-missing
```

**Salida esperada**:
```
tests/test_aead.py::test_roundtrip_devuelve_plaintext_identico[AES_256_GCM] PASSED
...
========================== 27 passed in 0.78s ==========================
Name                 Stmts   Miss  Cover   Missing
--------------------------------------------------
crypto/__init__.py       0      0   100%
crypto/aead.py         150      0   100%
--------------------------------------------------
TOTAL                  150      0   100%
```

✅ **Si ves "100%"**, todas las líneas están testeadas.

---

## 🎨 PASO 5: Verificar Linting (Opcional pero Recomendado)

Si instalaste `requirements-dev.txt`:

```powershell
# Formatear código con black
black crypto/ tests/

# Verificar flake8
flake8 crypto/ tests/

# Verificar imports
isort crypto/ tests/
```

**Salida esperada**: Sin salida = todo bien ✅

---

## 💾 PASO 6: Hacer Commit en la Rama Feature

Una vez que los tests pasan localmente:

```powershell
# Ver cambios que vas a commitear
git status

# Agregar todos los archivos nuevos/modificados
git add .

# Hacer commit con mensaje descriptivo
git commit -m "Add GitHub Actions CI/CD with automated tests

- Add .github/workflows/test.yml with pytest, linting, and security checks
- Configure pytest.ini with coverage reporting
- Add requirements.txt and requirements-dev.txt for dependency management
- Tests run on Python 3.10, 3.11, 3.12 across Ubuntu, Windows, macOS
- Add CI_CD_GUIDE.md with setup and usage instructions

Tests execute on PRs to main and pushes to feature/* branches.
All 27 unit tests pass with 100% code coverage."
```

**Explicación del commit message**:
- Primera línea: resumen corto
- Línea en blanco
- Bullets: detalles de qué se agregó
- Línea en blanco
- Párrafo: contexto importante

---

## 🚀 PASO 7: Hacer Push a tu Rama Feature en GitHub

```powershell
git push origin feature/add-ci-cd-testing
```

Si es la primera vez que empujas esta rama:
```powershell
git push -u origin feature/add-ci-cd-testing
```

(El `-u` vincula la rama local con la remota para futuros pushes)

---

## 📝 PASO 8: Crear Pull Request en GitHub

Ve a tu repositorio en GitHub:

1. Haz clic en **"Pull requests"** (pestaña superior)
2. Haz clic en **"New pull request"** (botón verde)
3. Selecciona:
   - **Base**: `main`
   - **Compare**: `feature/add-ci-cd-testing`
4. Haz clic en **"Create pull request"**

**Completa el template**:

```markdown
## Descripción
Agrega configuración de CI/CD completa con GitHub Actions para ejecutar tests automatizados en cada PR.

## Cambios
- [x] Workflow de GitHub Actions (.github/workflows/test.yml)
- [x] Configuración de pytest (pytest.ini)
- [x] Archivos de dependencias (requirements.txt, requirements-dev.txt)
- [x] Documentación de CI/CD (CI_CD_GUIDE.md)

## Tests
- [x] Tests ejecutados localmente — 27/27 PASSED ✅
- [x] Cobertura verificada — 100% ✅
- [x] Linting verificado — PASSED ✅

## Comportamiento de este PR
- Tests de GitHub Actions se ejecutarán automáticamente en:
  - Python 3.10, 3.11, 3.12
  - Ubuntu, Windows, macOS
  - Total: 9 combinaciones en paralelo
```

5. Haz clic en **"Create pull request"**

---

## 👀 PASO 9: Esperar a que GitHub Actions Ejecute

Una vez que haces PR, automáticamente:

1. GitHub Actions **dispara el workflow**
2. Los 9 jobs de testing comienzan en paralelo
3. Puedes ver el progreso en tiempo real

**Ve los resultados**:

En tu PR, desplázate hacia abajo. Verás una sección como:

```
✅ test (Python 3.10 on ubuntu-latest) — passed
✅ test (Python 3.10 on windows-latest) — passed
✅ test (Python 3.10 on macos-latest) — passed
✅ test (Python 3.11 on ubuntu-latest) — passed
... (más)
✅ lint — passed
✅ security — passed
```

**Si todo está verde** ✅, significa que los tests pasaron en todas las combinaciones.

---

## 📊 PASO 10: Revisar Reportes Detallados

En la PR, haz clic en **"Checks"** (cerca del botón de merge):

```
test (Python 3.10 on ubuntu-latest)
├─ ✅ Descargar código
├─ ✅ Setup Python 3.10
├─ ✅ Instalar dependencias
├─ ✅ Ejecutar tests (pytest)
│  └─ 27 tests PASSED, 100% coverage
├─ ✅ Generar reporte de cobertura
└─ ✅ Guardar reportes

lint
├─ ✅ Verificar formato (black)
├─ ✅ Linting (flake8)
└─ ✅ Verificar orden de imports (isort)

security
├─ ✅ Ejecutar Bandit
└─ No vulnerabilities detected
```

Puedes descargar los artifacts (reportes HTML de cobertura):

1. En la PR, haz clic en **"Artifacts"**
2. Descarga `coverage-report-py3.11-ubuntu-latest`
3. Extrae el ZIP
4. Abre `htmlcov/index.html` en el navegador
5. Verás un reporte visual de cobertura por archivo

---

## ✅ PASO 11: Hacer Merge (Una vez que todo está Verde)

Una vez que todos los checks pasaron (✅):

1. Haz clic en **"Merge pull request"**
2. Selecciona **"Squash and merge"** (opcional, limpia el historial)
3. Haz clic en **"Confirm squash and merge"**
4. GitHub automáticamente:
   - Mergea tu rama a `main`
   - Cierra la PR
   - Elimina la rama remota (opcional)

---

## 🔄 Comandos Resumen (Copiar y Pegar)

### **Local — Setup y Tests**

```powershell
# 1. Cambiar a main
git checkout main
git pull origin main

# 2. Crear rama feature
git checkout -b feature/add-ci-cd-testing

# 3. Instalar dependencias
pip install -r requirements.txt -r requirements-dev.txt

# 4. Ejecutar tests
pytest tests/test_aead.py -v

# 5. Con cobertura
pytest tests/test_aead.py -v --cov=crypto --cov-report=term-missing

# 6. Linting
black crypto/ tests/
isort crypto/ tests/
flake8 crypto/ tests/

# 7. Commit
git add .
git commit -m "Add GitHub Actions CI/CD"

# 8. Push
git push -u origin feature/add-ci-cd-testing
```

### **GitHub — PR y Merge**

```
1. Ir a GitHub
2. Pull Requests → New pull request
3. Base: main, Compare: feature/add-ci-cd-testing
4. Create pull request
5. Esperar a que los checks pasen (verde)
6. Merge pull request
```

---

## 🎯 Checklist de Validación

- [ ] Rama feature creada: `feature/add-ci-cd-testing`
- [ ] Dependencias instaladas: `pip install -r requirements.txt -r requirements-dev.txt`
- [ ] Tests locales pasan: `pytest tests/test_aead.py -v` → 27 passed ✅
- [ ] Cobertura verificada: 100% ✅
- [ ] Linting pasado: `black`, `isort`, `flake8` ✅
- [ ] Commit hecho: `git commit -m "..."`
- [ ] Push hecho: `git push -u origin feature/add-ci-cd-testing`
- [ ] PR creado en GitHub
- [ ] GitHub Actions ejecutándose (azul) o completado (verde)
- [ ] Todos los 9 jobs pasaron (verde) ✅
- [ ] PR mergeado a main

---

## 🐛 Troubleshooting

### **"pytest: command not found"**

```powershell
# Instalar pytest
pip install pytest pytest-cov
```

### **"27 passed" pero ves errores en GitHub Actions**

Probablemente sea un issue de ambiente. Revisa:
1. Haz clic en "Checks" en la PR
2. Abre el job que falló
3. Lee el error detalladamente
4. Común: versión de Python, dependencia faltante, ruta incorrecta

### **"No se ve nada en GitHub Actions"**

Los tests solo se ejecutan en:
- **Pull Requests** a `main`
- **Pushes** a `feature/*`, `develop`, `test/*`

Si empujaste directamente a `main`, no se ejecutarán. Usa una rama feature.

### **Quiero cancelar la ejecución en GitHub**

En la PR → Checks → workflow en ejecución → botón "Cancel workflow"

---

## 📚 Referencias

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Git Branching Model](https://git-scm.com/book/en/v2/Git-Branching-Basic-Branching-and-Merging)
- [Conventional Commits](https://www.conventionalcommits.org/)

---

## ✅ Resultado Final

Una vez completado, tendrás:

✅ Tests ejecutándose localmente (validez inmediata)  
✅ Tests ejecutándose en GitHub Actions (validez multiplataforma)  
✅ Historial de commits limpio (trazabilidad)  
✅ PR con evidencia de que todo funciona (auditoría)  
✅ Rama `main` siempre estable (calidad garantizada)

---

**Preguntas?** Si algo no funciona, pega el error exacto y te ayudo a debuguearlo.
