// Punto de entrada del frontend. Maneja auth con Appwrite y muestra la vista
// que toca (login si no hay sesion, app si la hay).

import { Client, Account, ID }
  from "https://cdn.jsdelivr.net/npm/appwrite@16.0.2/+esm";

import { APPWRITE_ENDPOINT, APPWRITE_PROJECT_ID } from "./config.js";

const client  = new Client().setEndpoint(APPWRITE_ENDPOINT).setProject(APPWRITE_PROJECT_ID);
const account = new Account(client);

// ---- referencias al DOM ----
const $ = (sel) => document.querySelector(sel);
const authView     = $("#auth-view");
const appView      = $("#app-view");
const loginForm    = $("#login-form");
const registerForm = $("#register-form");
const tabs         = document.querySelectorAll(".tab");
const msg          = $("#auth-msg");
const userName     = $("#user-name");
const userEmail    = $("#user-email");
const logoutBtn    = $("#logout-btn");

// ---- helpers ----
function showError(text)  { msg.textContent = text; msg.className = "msg error"; }
function showInfo(text)   { msg.textContent = text; msg.className = "msg info"; }
function clearMsg()       { msg.textContent = "";   msg.className = "msg"; }

function showAuthView() {
  appView.classList.add("hidden");
  authView.classList.remove("hidden");
}

function showAppView(user) {
  authView.classList.add("hidden");
  appView.classList.remove("hidden");
  userName.textContent  = user.name || "(sin nombre)";
  userEmail.textContent = user.email;
}

// ---- tabs login / register ----
tabs.forEach(t => t.addEventListener("click", () => {
  tabs.forEach(x => x.classList.toggle("active", x === t));
  const which = t.dataset.tab;
  loginForm.classList.toggle("hidden", which !== "login");
  registerForm.classList.toggle("hidden", which !== "register");
  clearMsg();
}));

// ---- login ----
loginForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  clearMsg();
  const fd = new FormData(loginForm);
  try {
    await account.createEmailPasswordSession(fd.get("email"), fd.get("password"));
    const user = await account.get();
    showAppView(user);
  } catch (err) {
    showError(err.message || "No se pudo iniciar sesion");
  }
});

// ---- registro ----
registerForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  clearMsg();
  const fd = new FormData(registerForm);
  try {
    await account.create(ID.unique(), fd.get("email"), fd.get("password"), fd.get("name"));
    await account.createEmailPasswordSession(fd.get("email"), fd.get("password"));
    const user = await account.get();
    showAppView(user);
  } catch (err) {
    showError(err.message || "No se pudo crear la cuenta");
  }
});

// ---- logout ----
logoutBtn.addEventListener("click", async () => {
  try { await account.deleteSession("current"); } catch (_) {}
  showAuthView();
  loginForm.reset();
  registerForm.reset();
  clearMsg();
});

// ---- al cargar: revisar si ya hay sesion ----
(async () => {
  try {
    const user = await account.get();
    showAppView(user);
  } catch {
    showAuthView();
  }
})();
