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

// Toast notifications — reemplazan los alert() nativos del navegador.
function toast(text, kind = "info", ms = 4000) {
  const root = document.getElementById("toasts");
  if (!root) return;
  const el = document.createElement("div");
  el.className = `toast toast-${kind}`;
  el.textContent = text;
  const dismiss = () => {
    el.classList.add("toast-out");
    setTimeout(() => el.remove(), 200);
  };
  el.addEventListener("click", dismiss);
  root.appendChild(el);
  if (ms > 0) setTimeout(dismiss, ms);
}

// Modal generico tipo prompt() del navegador, pero con HTML/CSS.
// Retorna una Promise: resuelve con el valor del input (o "" si no hay input
// y el usuario confirmo), o null si cancelo.
function askPrompt({
  title,
  message      = "",
  input        = null,         // null = solo confirmacion, sin input
  okText       = "OK",
  cancelText   = "Cancelar",
}) {
  return new Promise((resolve) => {
    const modal       = document.getElementById("modal-prompt");
    const form        = document.getElementById("form-prompt");
    const inputEl     = document.getElementById("prompt-input");
    const labelWrap   = document.getElementById("prompt-label");
    const inputLabel  = document.getElementById("prompt-input-label");
    const titleEl     = document.getElementById("prompt-title");
    const msgEl       = document.getElementById("prompt-message");
    const errEl       = document.getElementById("prompt-error");
    const okBtn       = document.getElementById("prompt-ok");
    const cancelBtn   = document.getElementById("prompt-cancel");

    titleEl.textContent = title;
    msgEl.textContent   = message;
    msgEl.classList.toggle("hidden", !message);
    okBtn.textContent     = okText;
    cancelBtn.textContent = cancelText;
    errEl.textContent     = "";

    if (input) {
      labelWrap.classList.remove("hidden");
      inputLabel.textContent = input.label || "";
      inputEl.type           = input.type || "text";
      inputEl.placeholder    = input.placeholder || "";
      inputEl.required       = input.required !== false;
      inputEl.value          = input.value || "";
    } else {
      labelWrap.classList.add("hidden");
      inputEl.required = false;
    }

    function cleanup() {
      form.removeEventListener("submit", onSubmit);
      cancelBtn.removeEventListener("click", onCancel);
      modal.removeEventListener("close", onClose);
      modal.close();
    }
    function onSubmit(ev) {
      ev.preventDefault();
      cleanup();
      resolve(input ? inputEl.value : "");
    }
    function onCancel() { cleanup(); resolve(null); }
    function onClose()  { cleanup(); resolve(null); }

    form.addEventListener("submit", onSubmit);
    cancelBtn.addEventListener("click", onCancel);
    modal.addEventListener("close",   onClose);

    modal.showModal();
    if (input) setTimeout(() => inputEl.focus(), 30);
  });
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

// Envuelve una operacion async con loading state en un boton.
// Util para operaciones bloqueantes (scrypt ~150ms). Restaura el boton
// aunque falle la operacion.
async function withLoading(btn, asyncFn) {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.classList.add("loading");
  btn.innerHTML = `<span class="btn-spinner"></span>${original}`;
  try {
    return await asyncFn();
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
    btn.innerHTML = original;
  }
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
    const fp = it.ed25519_fp || "";
    const fpShort = fp.slice(0, 12) + "..." + fp.slice(-8);
    tr.innerHTML = `
      <td>${escapeHtml(it.name)}</td>
      <td><span class="badge ${escapeHtml(it.status)}">${escapeHtml(it.status)}</span></td>
      <td class="mono fp-cell" title="${escapeHtml(fp)}">
        ${escapeHtml(fpShort)}
        <button class="copy-btn" data-act="copy-fp" data-fp="${escapeHtml(fp)}" title="Copiar fingerprint completo">⧉</button>
      </td>
      <td class="muted">${escapeHtml((it.created_at || "").slice(0, 19).replace("T", " "))}</td>
      <td class="actions">
        <button data-act="info"   data-name="${escapeHtml(it.name)}">ver</button>
        <button data-act="rotate" data-name="${escapeHtml(it.name)}">rotar</button>
        <button data-act="chpwd"  data-name="${escapeHtml(it.name)}">password</button>
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

// panel de detalle de identidad
const detailPanel = $("#identity-detail");
const detailClose = $("#detail-close");

function showIdentityDetail(info) {
  $("#detail-name").textContent  = info.name;
  $("#detail-status").textContent = info.status;
  $("#detail-x-pub").textContent  = info.x25519_pub_hex  || "(sin X25519)";
  $("#detail-ed-pub").textContent = info.ed25519_pub_hex || "";
  $("#detail-x-fp").textContent   = info.fingerprints.x25519  || "(sin X25519)";
  $("#detail-ed-fp").textContent  = info.fingerprints.ed25519 || "";

  const expRow = $("#detail-expires-row");
  if (info.expires_at) {
    $("#detail-expires").textContent = info.expires_at;
    expRow.classList.remove("hidden");
  } else {
    expRow.classList.add("hidden");
  }

  detailPanel.classList.remove("hidden");
  detailPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

detailClose.addEventListener("click", () => detailPanel.classList.add("hidden"));

// botones "copiar" dentro del panel
detailPanel.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button[data-copy]");
  if (!btn) return;
  const target = document.getElementById(btn.dataset.copy);
  if (!target) return;
  const text = target.textContent;
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = "copiado";
    setTimeout(() => { btn.textContent = orig; }, 1200);
  } catch {
    // fallback: seleccionar el texto
    const range = document.createRange();
    range.selectNodeContents(target);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

// click handlers de las filas
idRows.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const name = btn.dataset.name;
  const act  = btn.dataset.act;

  // Copiar fingerprint completo al portapapeles
  if (act === "copy-fp") {
    const fp = btn.dataset.fp;
    try {
      await navigator.clipboard.writeText(fp);
      toast("Fingerprint copiado al portapapeles", "info", 2000);
    } catch (err) {
      toast("No se pudo copiar: " + formatError(err), "error");
    }
    return;
  }

  if (act === "info") {
    try {
      const info = await callPy("get_public_info", [name]);
      showIdentityDetail(info);
    } catch (err) {
      toast(formatError(err), "error");
    }
  }
  else if (act === "rotate") {
    const pwd = await askPrompt({
      title:   `Rotar "${name}"`,
      message: "Genera un nuevo par de llaves. La identidad anterior se archiva con sufijo .rotated-<timestamp>.",
      input: { label: "Password de la identidad", type: "password", required: true },
      okText: "Rotar",
    });
    if (pwd === null || pwd === "") return;
    await withLoading(btn, async () => {
      try {
        const result = await callPy("rotate_identity", [name, pwd]);
        await runtime.persistKeystore();
        await refreshIdentities();
        const newFp = (result.ed25519_fp || "").slice(0, 12);
        toast(`"${name}" rotada. Nuevo fp: ${newFp}...`, "info");
      } catch (err) {
        toast(formatError(err), "error");
      }
    });
  }
  else if (act === "chpwd") {
    const oldPwd = await askPrompt({
      title:   `Cambiar password de "${name}"`,
      message: "Paso 1 de 2: confirma con el password actual.",
      input: { label: "Password actual", type: "password", required: true },
      okText: "Siguiente",
    });
    if (oldPwd === null || oldPwd === "") return;
    const newPwd = await askPrompt({
      title:   `Cambiar password de "${name}"`,
      message: "Paso 2 de 2: nuevo password (minimo 12 caracteres).",
      input: { label: "Password nuevo", type: "password", required: true },
      okText: "Cambiar",
    });
    if (newPwd === null || newPwd === "") return;
    if (newPwd.length < 12) {
      toast("El password nuevo debe tener al menos 12 caracteres", "error");
      return;
    }
    await withLoading(btn, async () => {
      try {
        await callPy("change_password", [name, oldPwd, newPwd]);
        await runtime.persistKeystore();
        toast(`Password de "${name}" actualizado`, "info");
      } catch (err) {
        toast(formatError(err), "error");
      }
    });
  }
  else if (act === "revoke") {
    const reason = await askPrompt({
      title:   `Revocar "${name}"`,
      message: "La identidad quedara marcada como revocada y no podra firmar ni descifrar.",
      input: { label: "Motivo (opcional)", type: "text", required: false, placeholder: "ej: llave comprometida" },
      okText: "Revocar",
    });
    if (reason === null) return;
    try {
      await callPy("revoke_identity", [name, reason || ""]);
      await runtime.persistKeystore();
      await refreshIdentities();
      toast(`Identidad "${name}" revocada.`, "info");
    } catch (err) {
      toast(formatError(err), "error");
    }
  }
  else if (act === "delete") {
    const pwd = await askPrompt({
      title:   `Borrar "${name}"`,
      message: "Esta accion es irreversible. Confirma con el password de la identidad.",
      input: { label: "Password de la identidad", type: "password", required: true },
      okText: "Borrar",
    });
    if (pwd === null || pwd === "") return;
    try {
      await callPy("delete_identity", [name, pwd]);
      await runtime.persistKeystore();
      await refreshIdentities();
      toast(`Identidad "${name}" borrada.`, "info");
    } catch (err) {
      toast(formatError(err), "error");
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
