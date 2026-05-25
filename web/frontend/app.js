// app.js — entrypoint del frontend SDDV.
// Inicializa Pyodide, monta las vistas y conecta los handlers de cada operacion.

import { initRuntime } from "./pyodide-runtime.js";

const $  = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

const bootEl     = $("#boot");
const bootDetail = $("#boot-detail");
const appEl      = $("#app");
const toastsEl   = $("#toasts");

let runtime = null;     // se llena tras initRuntime

// ─── utilidades ──────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
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

// ─── toasts ──────────────────────────────────────────────────────────────

function toast(text, kind = "info", duration = 3500) {
  const t = document.createElement("div");
  t.className = `toast ${kind}`;
  t.textContent = text;
  toastsEl.appendChild(t);
  // forzar reflow para que la transicion arranque
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => {
    t.classList.remove("show");
    setTimeout(() => t.remove(), 250);
  }, duration);
}

// Sanitiza un mensaje de error de Pyodide para mostrar al usuario.
// Quita stack traces enormes y deja solo la primera linea util.
function friendlyError(err) {
  const raw = err?.message || String(err);
  // Pyodide envuelve excepciones Python; busca la ultima linea no vacia
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);
  // Tipico "ValueError: bla" o "InvalidTag" como ultima linea
  const last = lines[lines.length - 1] || raw;
  // Limita longitud
  return last.length > 200 ? last.slice(0, 200) + "..." : last;
}

// ─── loading state ───────────────────────────────────────────────────────

// Envuelve una operacion async: deshabilita el boton y muestra spinner
// mientras dura. Se garantiza re-habilitar aunque falle.
async function withLoading(btn, asyncFn) {
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.classList.add("loading");
  btn.innerHTML = `<span class="btn-spinner"></span> ${original}`;
  try {
    return await asyncFn();
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
    btn.innerHTML = original;
  }
}

// ─── bridge JS -> Python ─────────────────────────────────────────────────

function pyToJs(val) {
  if (val && typeof val.toJs === "function") {
    const out = val.toJs({ dict_converter: Object.fromEntries });
    val.destroy();
    return out;
  }
  return val;
}

async function callPy(funcName, args = []) {
  const { pyodide } = runtime;
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

// ─── modales custom ──────────────────────────────────────────────────────

// Abre un modal nativo <dialog> y retorna una promesa que resuelve con
// el FormData del submit, o null si se cancela.
function openModal(modalId, { reset = true, onShow = null } = {}) {
  return new Promise((resolve) => {
    const dlg  = $(`#${modalId}`);
    const form = dlg.querySelector("form");
    const err  = dlg.querySelector(".modal-err");
    if (reset && form) form.reset();
    if (err) err.textContent = "";

    const cleanup = () => {
      form.removeEventListener("submit", onSubmit);
      dlg.removeEventListener("close",  onCancel);
      dlg.removeEventListener("cancel", onCancel);
      cancelBtn?.removeEventListener("click", onCancelClick);
    };
    const onSubmit = (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      // Validacion custom: passwords coinciden si hay password2
      const p1 = fd.get("password");
      const p2 = fd.get("password2");
      if (p1 && p2 && p1 !== p2) {
        if (err) err.textContent = "Los passwords no coinciden";
        return;
      }
      cleanup();
      dlg.close();
      resolve(fd);
    };
    const onCancel = () => { cleanup(); resolve(null); };
    const cancelBtn = dlg.querySelector(".modal-cancel");
    const onCancelClick = (ev) => { ev.preventDefault(); dlg.close(); onCancel(); };

    form.addEventListener("submit", onSubmit);
    dlg.addEventListener("cancel", onCancel);
    cancelBtn?.addEventListener("click", onCancelClick);

    if (onShow) onShow(dlg);
    dlg.showModal();
  });
}

// ─── navegacion entre vistas ─────────────────────────────────────────────

function switchView(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.view === name));
  $$(".view").forEach(v => v.classList.toggle("hidden", v.dataset.view !== name));
}

$$(".tab").forEach(t => t.addEventListener("click", () => switchView(t.dataset.view)));

// ─── identidades ─────────────────────────────────────────────────────────

const idEmpty = $("#identities-empty");
const idTable = $("#identities-table");
const idRows  = $("#identities-rows");

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
        <button class="copy-btn" data-act="copy" data-fp="${escapeHtml(fp)}" title="Copiar fingerprint completo">⧉</button>
      </td>
      <td class="muted">${escapeHtml((it.created_at || "").slice(0, 19).replace("T", " "))}</td>
      <td class="actions">
        <button data-act="info"     data-name="${escapeHtml(it.name)}">ver</button>
        <button data-act="rotate"   data-name="${escapeHtml(it.name)}">rotar</button>
        <button data-act="chpwd"    data-name="${escapeHtml(it.name)}">password</button>
        <button data-act="revoke"   data-name="${escapeHtml(it.name)}">revocar</button>
        <button data-act="delete"   data-name="${escapeHtml(it.name)}">borrar</button>
      </td>
    `;
    idRows.appendChild(tr);
  }
  idTable.classList.remove("hidden");
  updateSelects(items.map(x => x.name));
}

function updateSelects(names) {
  const targets = $$('select[name="signer"], select[name="recipient"], select[name="name"]');
  for (const sel of targets) {
    const prev = sel.value;
    sel.innerHTML = "";
    for (const n of names) {
      const opt = document.createElement("option");
      opt.value = n; opt.textContent = n;
      sel.appendChild(opt);
    }
    if (names.includes(prev)) sel.value = prev;
  }
}

// ─── handlers de acciones sobre identidades ──────────────────────────────

idRows.addEventListener("click", async (ev) => {
  const btn = ev.target.closest("button[data-act]");
  if (!btn) return;
  const name = btn.dataset.name;
  const act  = btn.dataset.act;

  if (act === "copy") {
    const fp = btn.dataset.fp;
    try {
      await navigator.clipboard.writeText(fp);
      toast("Fingerprint copiado al portapapeles", "info", 2000);
    } catch (err) {
      toast("No se pudo copiar: " + friendlyError(err), "error");
    }
    return;
  }

  if (act === "info") {
    try {
      const info = await callPy("get_public_info", [name]);
      // Llena el modal de info en vez de alert()
      $("#info-title").textContent = `Identidad: ${info.name}`;
      $("#info-body").innerHTML = `
        <dl class="info-list">
          <dt>Estado</dt>          <dd><span class="badge ${escapeHtml(info.status)}">${escapeHtml(info.status)}</span></dd>
          <dt>Ed25519 fp</dt>      <dd class="mono break">${escapeHtml(info.fingerprints.ed25519)}</dd>
          ${info.fingerprints.x25519 ? `
          <dt>X25519 fp</dt>       <dd class="mono break">${escapeHtml(info.fingerprints.x25519)}</dd>
          ` : ""}
          ${info.ed25519_pub_hex ? `
          <dt>Ed25519 pub (raw hex)</dt>
          <dd class="mono break">${escapeHtml(info.ed25519_pub_hex)}</dd>
          ` : ""}
          ${info.x25519_pub_hex ? `
          <dt>X25519 pub (raw hex)</dt>
          <dd class="mono break">${escapeHtml(info.x25519_pub_hex)}</dd>
          ` : ""}
          ${info.expires_at ? `
          <dt>Expira</dt> <dd>${escapeHtml(info.expires_at)}</dd>
          ` : ""}
        </dl>
      `;
      $("#modal-info").showModal();
    } catch (err) {
      toast(friendlyError(err), "error");
    }
  }
  else if (act === "rotate") {
    const fd = await openModal("modal-rotate", {
      onShow: () => $("#rotate-name").textContent = name
    });
    if (!fd) return;
    await withLoading(btn, async () => {
      try {
        const result = await callPy("rotate_identity", [name, fd.get("password")]);
        await runtime.persistKeystore();
        await refreshIdentities();
        toast(`"${name}" rotada. Nuevo fp: ${(result.ed25519_fp || "").slice(0,12)}...`, "info");
      } catch (err) {
        toast(friendlyError(err), "error");
      }
    });
  }
  else if (act === "chpwd") {
    const fd = await openModal("modal-chpwd", {
      onShow: () => $("#chpwd-name").textContent = name
    });
    if (!fd) return;
    await withLoading(btn, async () => {
      try {
        await callPy("change_password",
          [name, fd.get("old_password"), fd.get("password")]);
        await runtime.persistKeystore();
        toast(`Password de "${name}" actualizado`, "info");
      } catch (err) {
        toast(friendlyError(err), "error");
      }
    });
  }
  else if (act === "revoke") {
    const fd = await openModal("modal-revoke", {
      onShow: () => $("#revoke-name").textContent = name
    });
    if (!fd) return;
    try {
      await callPy("revoke_identity", [name, fd.get("reason") || ""]);
      await runtime.persistKeystore();
      await refreshIdentities();
      toast(`"${name}" revocada`, "info");
    } catch (err) {
      toast(friendlyError(err), "error");
    }
  }
  else if (act === "delete") {
    const fd = await openModal("modal-delete", {
      onShow: () => $("#delete-name").textContent = name
    });
    if (!fd) return;
    await withLoading(btn, async () => {
      try {
        await callPy("delete_identity", [name, fd.get("password")]);
        await runtime.persistKeystore();
        await refreshIdentities();
        toast(`"${name}" eliminada`, "info");
      } catch (err) {
        toast(friendlyError(err), "error");
      }
    });
  }
});

// ─── modal: nueva identidad ──────────────────────────────────────────────

const modal   = $("#modal-new-identity");
const formNew = $("#form-new-identity");
const newErr  = $("#new-identity-err");

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

  const submitBtn = formNew.querySelector('button[type="submit"]');
  await withLoading(submitBtn, async () => {
    try {
      await callPy("create_identity", [name, p1, comment]);
      await runtime.persistKeystore();
      modal.close();
      await refreshIdentities();
      toast(`Identidad "${name}" creada`, "info");
    } catch (err) {
      newErr.textContent = friendlyError(err);
    }
  });
});

// cerrar modal-info al hacer click en el boton
$("#info-close")?.addEventListener("click", (ev) => {
  ev.preventDefault();
  $("#modal-info").close();
});

// ─── cifrar + firmar ─────────────────────────────────────────────────────

$("#form-send").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#send-result");
  const submitBtn = ev.currentTarget.querySelector('button[type="submit"]');
  showMsg(out, "Cifrando...", "info");
  const fd = new FormData(ev.currentTarget);
  const file   = fd.get("file");
  const signer = fd.get("signer");
  const pwd    = fd.get("signer_pwd");
  const recipients = String(fd.get("recipients"))
    .split(/[\s,]+/).map(s => s.trim()).filter(Boolean);

  if (recipients.length === 0) { showMsg(out, "Sin destinatarios", "error"); return; }
  if (!file || file.size === 0) { showMsg(out, "Archivo vacio", "error"); return; }

  await withLoading(submitBtn, async () => {
    try {
      const buf = new Uint8Array(await file.arrayBuffer());
      const container = await callPy("encrypt_and_sign",
        [signer, pwd, recipients, buf, file.name]);
      const bytes = container instanceof Uint8Array ? container : new Uint8Array(container);
      downloadBytes(file.name + ".sddh", bytes);
      showMsg(out, `Listo. Descargando ${file.name}.sddh (${bytes.byteLength} bytes).`, "info");
      toast("Archivo cifrado y firmado", "info");
    } catch (err) {
      showMsg(out, friendlyError(err), "error");
      toast(friendlyError(err), "error");
    }
  });
});

// ─── verificar + descifrar ───────────────────────────────────────────────

$("#form-recv").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#recv-result");
  const submitBtn = ev.currentTarget.querySelector('button[type="submit"]');
  showMsg(out, "Verificando y descifrando...", "info");
  const fd = new FormData(ev.currentTarget);
  const file = fd.get("container");
  const recipient = fd.get("recipient");
  const pwd = fd.get("recipient_pwd");
  const signerFp = fd.get("signer_fp");

  if (!file || file.size === 0) { showMsg(out, "Archivo vacio", "error"); return; }

  await withLoading(submitBtn, async () => {
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
      toast("Firma valida — archivo descifrado", "info");
    } catch (err) {
      showMsg(out, friendlyError(err), "error");
      toast(friendlyError(err), "error");
    }
  });
});

// ─── backup ──────────────────────────────────────────────────────────────

$("#form-backup").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#backup-result");
  const submitBtn = ev.currentTarget.querySelector('button[type="submit"]');
  showMsg(out, "Generando backup...", "info");
  const fd = new FormData(ev.currentTarget);
  const name = fd.get("name");
  await withLoading(submitBtn, async () => {
    try {
      const json = await callPy("backup_export",
        [name, fd.get("active_pwd"), fd.get("backup_pwd")]);
      downloadBytes(`${name}.sddv_backup`, new TextEncoder().encode(json), "application/json");
      showMsg(out, `Backup descargado: ${name}.sddv_backup`, "info");
      toast("Backup generado", "info");
    } catch (err) {
      showMsg(out, friendlyError(err), "error");
      toast(friendlyError(err), "error");
    }
  });
});

$("#form-restore").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = $("#restore-result");
  const submitBtn = ev.currentTarget.querySelector('button[type="submit"]');
  showMsg(out, "Restaurando...", "info");
  const fd = new FormData(ev.currentTarget);
  const file = fd.get("file");
  if (!file || file.size === 0) { showMsg(out, "Archivo vacio", "error"); return; }
  await withLoading(submitBtn, async () => {
    try {
      const text = await file.text();
      const asName = (fd.get("as_name") || "").trim() || null;
      const info = await callPy("backup_import",
        [text, fd.get("backup_pwd"), fd.get("new_pwd"), asName]);
      await runtime.persistKeystore();
      await refreshIdentities();
      showMsg(out, `Restaurada como "${info.name}".`, "info");
      toast(`"${info.name}" restaurada`, "info");
    } catch (err) {
      showMsg(out, friendlyError(err), "error");
      toast(friendlyError(err), "error");
    }
  });
});

// ─── bootstrap ───────────────────────────────────────────────────────────

(async () => {
  try {
    runtime = await initRuntime((msg) => { bootDetail.textContent = msg; });
    bootEl.classList.add("hidden");
    appEl.classList.remove("hidden");
    await refreshIdentities();
  } catch (err) {
    bootDetail.textContent = "Error: " + (err.message || err);
    bootDetail.classList.add("error");
    console.error(err);
  }
})();
