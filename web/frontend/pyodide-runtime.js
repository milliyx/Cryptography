// pyodide-runtime.js
// Bootstrap de Pyodide para SDDV: carga el interprete, instala cryptography,
// monta IndexedDB en /keystore para persistencia entre sesiones, y descarga
// los modulos de crypto/ desde la misma ruta donde vive el sitio.
//
// Expone: initRuntime(onProgress) -> Promise<runtime>
//   runtime = { pyodide, runPy(src, opts), persistKeystore() }

const PYODIDE_VERSION = "0.27.2";
const PYODIDE_INDEX_URL = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

// Archivos del paquete crypto/ que necesitamos en el navegador.
// El SO de Pyodide es POSIX-like; cargamos cada .py y lo escribimos al FS virtual.
const CRYPTO_FILES = [
  "__init__.py",
  "aead.py",
  "hybrid.py",
  "kdf.py",
  "keys.py",
  "keystore.py",
  "keystore_backup.py",
  "keystore_format.py",
  "secure_send.py",
  "signatures.py",
];

async function fetchText(url) {
  const r = await fetch(url, { cache: "force-cache" });
  if (!r.ok) throw new Error(`fetch ${url}: HTTP ${r.status}`);
  return r.text();
}

function syncfs(pyodide, fromIDB) {
  return new Promise((res, rej) =>
    pyodide.FS.syncfs(fromIDB, (e) => (e ? rej(e) : res()))
  );
}

export async function initRuntime(onProgress = () => {}) {
  // 1. cargar Pyodide
  onProgress("Cargando Pyodide...");
  // loadPyodide viene del <script> en index.html
  const pyodide = await loadPyodide({ indexURL: PYODIDE_INDEX_URL });

  // 2. instalar cryptography (paquete portado por Pyodide)
  onProgress("Instalando libreria cryptography...");
  await pyodide.loadPackage(["cryptography"]);

  // 3. montar IndexedDB en /keystore para persistir los .json entre visitas
  onProgress("Montando almacenamiento local...");
  pyodide.FS.mkdirTree("/keystore");
  pyodide.FS.mount(pyodide.FS.filesystems.IDBFS, {}, "/keystore");
  await syncfs(pyodide, true); // leer lo que ya hubiera en IndexedDB

  // 4. descargar los modulos crypto/ y escribirlos al FS virtual
  onProgress("Cargando modulos cripto...");
  pyodide.FS.mkdirTree("/crypto");
  // En produccion, crypto/ vive en la misma raiz del sitio gracias al workflow
  // de Pages. En local servimos web/frontend con http.server y dejamos un
  // enlace simbolico o copia; por defecto buscamos en `./crypto/`.
  const base = new URL("./crypto/", document.baseURI).href;
  await Promise.all(
    CRYPTO_FILES.map(async (f) => {
      const text = await fetchText(base + f);
      pyodide.FS.writeFile(`/crypto/${f}`, text);
    })
  );

  // 5. hacer que `import crypto` funcione
  pyodide.runPython(`
import sys
if "/" not in sys.path:
    sys.path.insert(0, "/")
`);

  // 6. cargar sddv_api.py (el wrapper que llamamos desde JS)
  onProgress("Cargando wrapper SDDV...");
  const apiBase = new URL("./", document.baseURI).href;
  const apiSrc = await fetchText(apiBase + "sddv_api.py");
  pyodide.FS.writeFile("/sddv_api.py", apiSrc);
  pyodide.runPython(`import sddv_api`);

  // 7. helper para persistir IDBFS tras escrituras
  async function persistKeystore() {
    await syncfs(pyodide, false);
  }

  function runPy(src) {
    return pyodide.runPython(src);
  }

  return { pyodide, runPy, persistKeystore };
}
