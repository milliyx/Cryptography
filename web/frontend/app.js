// app.js — entrypoint del frontend SDDV.
// Inicializa Pyodide, monta las vistas y conecta los handlers de cada operacion.

import { initRuntime } from "./pyodide-runtime.js";

const $  = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

const bootEl       = $("#boot");
const bootDetail   = $("#boot-detail");
const appEl        = $("#app");

let runtime = null;     // se llena tras initRuntime

// ── utilidades ───────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// Convierte un error (idealmente un PythonError de Pyodide con traceback
// completo) en un mensaje corto y legible. Mapea las excepciones tipicas
// del proyecto a explicaciones en espanol.
function formatError(err) {
  if (!err) return "Error desconocido";
  let msg = err.message || String(err);

  // Pyodide trae el traceback completo en .message. Quedarnos solo con la
  // ultima linea no vacia — tipicamente "ExcType: mensaje".
  if (msg.includes("Traceback")) {
    const lines = msg.split("\n").map(s => s.trim()).filter(Boolean);
    msg = lines[lines.length - 1] || msg;
  }

  const friendly = {
    "InvalidTag":                 "Password incorrecto o el archivo fue modificado.",
    "InvalidSignature":           "La firma no corresponde al firmante esperado.",
    "IdentityNotFoundError":      "Esa identidad no existe en tu keystore.",
    "IdentityAlreadyExistsError": "Ya tienes una identidad con ese nombre.",
    "IdentityRevokedError":       "Esta identidad fue revocada.",
    "IdentityExpiredError":       "Esta identidad ya expiro.",
  };
  for (const [t, nice] of Object.entries(friendly)) {
    if (msg.includes(t)) return nice;
  }

  // Quitar prefijos tipo "ValueError: " que no aportan al usuario.
  const m = msg.match(/^[A-Z]\w*Error:\s*(.+)$/);
  if (m) return m[1];
  return msg;
}

function showMsg(el, text, kind = "info") {
  el.textContent = text;
  el.className = "msg " + kind;
}

function downloadBytes(filename, bytes, mime = "application/octet-stream") {
  const blob = new Blob([bytes], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Convierte el resultado de pyodide.runPython (PyProxy o tipo nativo) a JS.
function pyToJs(val) {
  if (val && typeof val.toJs === "function") {
    const out = val.toJs({ dict_converter: Object.fromEntries });
    val.destroy();
    return out;
  }
  return val;
}

// Llama a una funcion de sddv_api pasando argumentos por posicion.
// Convierte cada argumento JS al equivalente Python adecuado.
async function callPy(funcName, args = []) {
  const { pyodide } = runtime;
  // Subimos los argumentos al namespace global de Python
  const argNames = [];
  for (let i = 0; i < args.length; i++) {
    const n = `__arg_${i}`;
    pyodide.globals.set(n, args[i]);
    argNames.push(n);
  }
  const src = `sddv_api.${funcName}(${argNames.join(", ")})`;
  try {
    const result = pyodide.runPython(src);
    return pyToJs(result);
  } finally {
    for (const n of argNames) pyodide.globals.delete(n);
  }
}

// ── navegacion entre vistas ──────────────────────────────────────────────

function switchView(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === name));
  $$(".view").forEach(v => v.classList.toggle("hidden", v.dataset.view !== name));
}

$$(".tab").forEach(t => t.addEventListener("click", () => switchView(t.dataset.view)));

// ── identidades ──────────────────────────────────────────────────────────

const idEmpty   = $("#identities-empty");
const idTable   = $("#identities-table");
const idRows    = $("#identities-rows");

async function refreshIdentities() {
  idEmpty.classList.add("hidden");
  idTable.classList.add("hidden");
  idRows.innerHTML = "";

  const items = await callPy("list_identities");

  if (!items || items.length === 0) {
    idEmpty.classList.remove("hidden");
    updateSelects([]);
    return;
  }

  for (const it of items) {
    const tr = document.createElement("tr");
    const fpShort = (it.ed25519_fp || "").slice(0, 12) + "..." + (it.ed25519_fp || "").slice(-8);
    tr.innerHTML = `
      <td>${escapeHtml(it.name)}</td>
      <td><span class="badge ${escapeHtml(it.status)}">${escapeHtml(it.status)}</span></td>
      <td class="mono" title="${escapeHtml(it.ed25519_fp)}">${escapeHtml(fpShort)}</td>
      <td class="muted">${escapeHtml((it.created_at || "").slice(0, 19).replace("T", " "))}</td>
      <td class="actions">
        <button data-act="info"   data-name="${escapeHtml(it.name)}">ver</button>
        <button data-act="revoke" data-name="${escapeHtml(it.name)}">revocar</button>
        <button data-act="delete" data-name="${escapeHtml(it.name)}">borrar</button>
      </td>
    `;
    idRows.appendChild(tr);
  }
  idTable.classList.remove("hidden");
  updateSelects(items.map(x => x.name));
}

// llena los <select> de las otras vistas con los nombres disponibles
function updateSelects(names) {
  const targets = $$('select[name="signer"], select[name="recipient"], select[name="name"]');
  for (const sel of targets) {
    const prev = sel.value;
    sel.innerHTML = "";
    if (names.length === 0) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = "— Sin identidades. Crea una en la pestana Identidades —";
      opt.disabled = true;
      opt.selected = true;
      sel.appendChild(opt);
      sel.disabled = true;
      continue;
    }
    sel.disabled = false;
    for (const n of names) {
      const opt = document.createElement("option");
      opt.value = n; opt.textContent = n;
      sel.appendChild(opt);
    }
    if (names.includes(prev)) sel.value = prev;
  }
}

// click handlers de las filas
idRows.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const name = btn.dataset.name;
  const act  = btn.dataset.act;

  if (act === "info") {
    try {
      const info = await callPy("get_public_info", [name]);
      alert([
        `Identidad: ${info.name}`,
        `Estado:    ${info.status}`,
        `Ed25519 fp: ${info.fingerprints.ed25519}`,
        info.fingerprints.x25519 ? `X25519  fp: ${info.fingerprints.x25519}` : null,
        info.ed25519_pub_hex ? `\nEd25519 pub (raw hex):\n${info.ed25519_pub_hex}` : null,
        info.x25519_pub_hex  ? `\nX25519  pub (raw hex):\n${info.x25519_pub_hex}`  : null,
        info.expires_at ? `\nExpira: ${info.expires_at}` : null,
      ].filter(Boolean).join("\n"));
    } catch (err) {
      alert("Error: " + (formatError(err)));
    }
  }
  else if (act === "revoke") {
    const reason = prompt(`Revocar "${name}". Motivo (opcional):`);
    if (reason === null) return;
    try {
      await callPy("revoke_identity", [name, reason || ""]);
      await runtime.persistKeystore();
      await refreshIdentities();
    } catch (err) {
      alert("Error: " + (formatError(err)));
    }
  }
  else if (act === "delete") {
    const pwd = prompt(`Borrar "${name}" requiere el password de la identidad:`);
    if (!pwd) return;
    try {
      await callPy("delete_identity", [name, pwd]);
      await runtime.persistKeystore();
      await refreshIdentities();
    } catch (err) {
      alert("Error: " + (formatError(err)));
    }
  }
});

// ── modal: nueva identidad ───────────────────────────────────────────────

const modal     = $("#modal-new-identity");
const formNew   = $("#form-new-identity");
const newErr    = $("#new-identity-err");

$("#btn-new-identity").addEventListener("click", () => {
  formNew.reset();
  newErr.textContent = "";
  modal.showModal();
});

$("#btn-cancel-new").addEventListener("click", () => modal.close());

formNew.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  newErr.textContent = "";
  const fd = new FormData(formNew);
  const name = (fd.get("name") || "").trim();
  const p1   = fd.get("password");
  const p2   = fd.get("password2");
  const comment = (fd.get("comment") || "").trim();
  if (p1 !== p2) { newErr.textContent = "Los passwords no coinciden"; return; }

  try {
    await callPy("create_identity", [name, p1, comment]);
    await runtime.persistKeystore();
    modal.close();
    await refreshIdentities();
  } catch (err) {
    newErr.textContent = formatError(err);
  }
});

// ── cifrar + firmar ──────────────────────────────────────────────────────

$("#form-send").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#send-result");
  showMsg(out, "Cifrando...", "info");
  const fd = new FormData(ev.currentTarget);
  const file   = fd.get("file");
  const signer = fd.get("signer");
  const pwd    = fd.get("signer_pwd");
  const recipients = String(fd.get("recipients"))
    .split(/[\s,]+/).map(s => s.trim()).filter(Boolean);

  if (recipients.length === 0) { showMsg(out, "Sin destinatarios", "error"); return; }
  if (!file || file.size === 0) { showMsg(out, "Archivo vacio", "error"); return; }

  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const container = await callPy("encrypt_and_sign",
      [signer, pwd, recipients, buf, file.name]);
    const bytes = container instanceof Uint8Array ? container : new Uint8Array(container);
    downloadBytes(file.name + ".sddh", bytes);
    showMsg(out, `Listo. Descargando ${file.name}.sddh (${bytes.byteLength} bytes).`, "info");
  } catch (err) {
    showMsg(out, "Error: " + (formatError(err)), "error");
  }
});

// ── verificar + descifrar ────────────────────────────────────────────────

$("#form-recv").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#recv-result");
  showMsg(out, "Verificando y descifrando...", "info");
  const fd = new FormData(ev.currentTarget);
  const file = fd.get("container");
  const recipient = fd.get("recipient");
  const pwd = fd.get("recipient_pwd");
  const signerFp = fd.get("signer_fp");

  if (!file || file.size === 0) { showMsg(out, "Archivo vacio", "error"); return; }

  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const res = await callPy("verify_and_decrypt", [recipient, pwd, buf, signerFp]);
    const plaintext = res.plaintext instanceof Uint8Array
      ? res.plaintext
      : new Uint8Array(res.plaintext);
    const meta = res.metadata || {};
    const outName = meta.filename || "descifrado.bin";
    downloadBytes(outName, plaintext);
    showMsg(out,
      `Firma valida. Descargando ${outName} (${plaintext.byteLength} bytes).`,
      "info");
  } catch (err) {
    showMsg(out, "Error: " + (formatError(err)), "error");
  }
});

// ── backup ───────────────────────────────────────────────────────────────

$("#form-backup").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#backup-result");
  showMsg(out, "Generando backup...", "info");
  const fd = new FormData(ev.currentTarget);
  const name = fd.get("name");
  try {
    const json = await callPy("backup_export",
      [name, fd.get("active_pwd"), fd.get("backup_pwd")]);
    downloadBytes(`${name}.sddv_backup`, new TextEncoder().encode(json), "application/json");
    showMsg(out, `Backup descargado: ${name}.sddv_backup`, "info");
  } catch (err) {
    showMsg(out, "Error: " + (formatError(err)), "error");
  }
});

$("#form-restore").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#restore-result");
  showMsg(out, "Restaurando...", "info");
  const fd = new FormData(ev.currentTarget);
  const file = fd.get("file");
  if (!file || file.size === 0) { showMsg(out, "Archivo vacio", "error"); return; }
  try {
    const text = await file.text();
    const asName = (fd.get("as_name") || "").trim() || null;
    const info = await callPy("backup_import",
      [text, fd.get("backup_pwd"), fd.get("new_pwd"), asName]);
    await runtime.persistKeystore();
    await refreshIdentities();
    showMsg(out, `Restaurada como "${info.name}".`, "info");
  } catch (err) {
    showMsg(out, "Error: " + (formatError(err)), "error");
  }
});

// ── bootstrap ────────────────────────────────────────────────────────────

// iOS Safari / Chrome (mismo motor) limita la memoria WebAssembly por pestana
// alrededor de 400 MB, lo que rompe la inicializacion de Pyodide en iPhone.
// Mostramos un aviso en vez de colgar la pagina silenciosamente.
function isIPhone() {
  return /iPhone|iPod/.test(navigator.userAgent || "");
}

function showIPhoneWarning() {
  const title  = document.getElementById("boot-title");
  const detail = document.getElementById("boot-detail");
  title.textContent = "iPhone no soportado";
  detail.innerHTML =
    "Esta app ejecuta Python (~10 MB de WebAssembly) en tu navegador para que " +
    "las llaves privadas nunca salgan de tu equipo. " +
    "iOS limita la memoria por pestana y cuelga la pagina durante la carga.<br><br>" +
    "Abrelo desde una computadora o un dispositivo Android.<br><br>" +
    '<a href="https://github.com/sergiocaballeroo/Cryptography" style="color:inherit;text-decoration:underline">' +
    "Repositorio en GitHub</a>";
  detail.classList.remove("error");
}

(async () => {
  if (isIPhone()) {
    showIPhoneWarning();
    return;
  }
  try {
    runtime = await initRuntime((msg) => { bootDetail.textContent = msg; });
    bootEl.classList.add("hidden");
    appEl.classList.remove("hidden");
    await refreshIdentities();
  } catch (err) {
    bootDetail.textContent = "Error: " + (formatError(err));
    bootDetail.classList.add("error");
    console.error(err);
  }
})();
