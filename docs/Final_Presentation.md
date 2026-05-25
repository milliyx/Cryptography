---
title: "Secure Digital Document Vault"
subtitle: "Final Presentation · Equipo 7"
author: "Barrios · Caballero · Contreras · Martínez"
institute: "Criptografía · Dra. Rocío Aldeco Pérez · UNAM 2026-2"
date: "Mayo 2026"
theme: "metropolis"
mainfont: "Helvetica Neue"
sansfont: "Helvetica Neue"
monofont: "Menlo"
fontsize: "11pt"
aspectratio: "169"
---

# 1 · System Overview

## El problema

\vspace*{\fill}

\bigidea{Hoy enviamos archivos sensibles\\por canales que no garantizan nada.}

\vspace{1.5em}

\begin{columns}[T,onlytextwidth]
\column{0.33\textwidth}
\begin{card}
\centering
{\Large\bfseries\color{coral}Correo}\\[0.5em]
\small Sin confidencialidad ni autenticidad
\end{card}
\column{0.33\textwidth}
\begin{card}
\centering
{\Large\bfseries\color{coral}Drive / Dropbox}\\[0.5em]
\small El proveedor puede leer
\end{card}
\column{0.33\textwidth}
\begin{card}
\centering
{\Large\bfseries\color{coral}WhatsApp}\\[0.5em]
\small Cifrado limitado, sin firma verificable
\end{card}
\end{columns}

\vspace*{\fill}

## Nuestra propuesta

\vspace*{\fill}

\begin{center}
{\fontsize{42pt}{50pt}\selectfont\bfseries\color{textmain}La seguridad}

\vspace{0.3em}
{\fontsize{42pt}{50pt}\selectfont\bfseries\color{accent}no se confía,}

\vspace{0.3em}
{\fontsize{42pt}{50pt}\selectfont\bfseries\color{textmain}se demuestra.}
\end{center}

\vspace{1em}

\begin{center}
{\large\color{textmuted}Con criptografía formal, no con promesas.}
\end{center}

\vspace*{\fill}

## ¿Qué construimos?

\subhero{SDDV — Secure Digital Document Vault}

\vspace{0.5em}

\begin{center}
{\large\color{textmuted}CLI en Python para almacenar y compartir archivos de forma segura}
\end{center}

\vspace{1em}

\begin{columns}[T,onlytextwidth]
\column{0.33\textwidth}
\statcard{300}{tests verdes}
\column{0.33\textwidth}
\statcard{32}{commits}
\column{0.33\textwidth}
\statcard{7}{vulns resueltas}
\end{columns}

\vspace{1em}

\begin{center}
\pill{accent}{D2 · AEAD} \quad
\pill{indigo}{D3 · Híbrido} \quad
\pill{amber}{D5 · Firma} \quad
\pill{coral}{D6 · Keystore}
\end{center}

## Arquitectura por capas

\vspace{0.5em}

\begin{center}
\begin{tikzpicture}[
  node distance=0.35cm,
  layer/.style={rectangle, rounded corners=5pt, draw=bgcard2, fill=bgcard,
                minimum width=9cm, minimum height=0.85cm, font=\small, text=textmain},
  trust/.style={rectangle, rounded corners=5pt, draw=accent, fill=bgcard2,
                minimum width=9cm, minimum height=0.85cm, font=\small\bfseries, text=accent}
]
  \node[layer] (app)    {\textbf{Aplicación} · CLI \texttt{python -m crypto}};
  \node[trust, below=of app] (comp)   {\textbf{Composición} · \texttt{secure\_send.py}};
  \node[layer, below=of comp] (sign)  {\textbf{Firma} · Ed25519 sobre SDDH};
  \node[layer, below=of sign] (hyb)   {\textbf{Híbrido} · X25519 KEM + AEAD DEM};
  \node[layer, below=of hyb]  (aead)  {\textbf{Simétrico} · AES-256-GCM / ChaCha20-Poly1305};
  \node[trust, below=of aead] (kstore){\textbf{Llaves} · scrypt + AES-GCM};

  \node[right=0.3cm of comp, font=\scriptsize\itshape, text=accent] {confiable};
  \node[right=0.3cm of kstore, font=\scriptsize\itshape, text=accent] {confiable};
\end{tikzpicture}
\end{center}

\vspace{0.4em}

\begin{center}
\footnotesize\color{textmuted}\itshape
Almacenamiento, red y contenedores cifrados se consideran \textbf{\color{coral}no confiables}.
\end{center}

# 2 · Threat Model

## Activos a proteger

\vspace{0.5em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{accentcard}
{\bfseries\color{accent}Contenido del archivo}\\[0.3em]
\small Información sensible $\rightarrow$ AEAD (D2)
\end{accentcard}
\vspace{0.5em}
\begin{accentcard}
{\bfseries\color{accent}Metadatos}\\[0.3em]
\small Filename, timestamp, destinatarios $\rightarrow$ AAD del DEM
\end{accentcard}
\vspace{0.5em}
\begin{accentcard}
{\bfseries\color{accent}Llaves privadas}\\[0.3em]
\small Ed25519 + X25519 $\rightarrow$ scrypt + AES-GCM (D6)
\end{accentcard}

\column{0.5\textwidth}
\begin{accentcard}
{\bfseries\color{accent}Passwords}\\[0.3em]
\small Solo en memoria · longitud mínima 12
\end{accentcard}
\vspace{0.5em}
\begin{accentcard}
{\bfseries\color{accent}Firmas digitales}\\[0.3em]
\small No-repudio $\rightarrow$ Ed25519 (RFC 8032)
\end{accentcard}
\vspace{0.5em}
\begin{accentcard}
{\bfseries\color{accent}Nonces AEAD}\\[0.3em]
\small Reuso = catastrófico $\rightarrow$ CSPRNG fresco
\end{accentcard}
\end{columns}

## Adversarios considerados

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{card}
\pill{accent}{ADV-1}~~\textbf{Externo}\\[0.2em]
\footnotesize Lee y modifica contenedores
\end{card}
\vspace{0.4em}
\begin{card}
\pill{accent}{ADV-2}~~\textbf{Destinatario malicioso}\\[0.2em]
\footnotesize Lee su archivo legítimamente
\end{card}
\vspace{0.4em}
\begin{card}
\pill{accent}{ADV-3}~~\textbf{Man-in-the-Middle}\\[0.2em]
\footnotesize Sustituye pubkeys
\end{card}

\column{0.5\textwidth}
\begin{card}
\pill{accent}{ADV-4}~~\textbf{Acceso físico}\\[0.2em]
\footnotesize Copia el keystore
\end{card}
\vspace{0.4em}
\begin{card}
\pill{accent}{ADV-5}~~\textbf{Fuerza bruta offline}\\[0.2em]
\footnotesize Prueba passwords
\end{card}
\vspace{0.4em}
\begin{alertcard}
\pill{coral}{ADV-6}~~\textbf{Dispositivo comprometido}\\[0.2em]
\footnotesize Keylogger, RAM dump $\rightarrow$ \textcolor{coral}{fuera de scope}
\end{alertcard}
\end{columns}

## Asunciones explícitas

\vspace*{\fill}

\bigidea{Lo que SDDV asume\\del entorno}

\vspace{1em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{card}
\dotitem{CSPRNG del SO es seguro}\\[0.4em]
\dotitem{Pubkeys distribuidas auténticamente}
\end{card}
\column{0.5\textwidth}
\begin{card}
\dotitem{Usuario elige passwords fuertes}\\[0.4em]
\dotitem{Sin malware en ejecución}
\end{card}
\end{columns}

\vspace*{\fill}

# 3 · D2 — AEAD

## Selección del algoritmo

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{accentcard}
{\Large\bfseries\color{accent}AES-256-GCM}\\[0.5em]
\small Default · NIST SP 800-38D\\[0.3em]
\checkitem{Acelerado por hardware (AES-NI)}\\[0.2em]
\checkitem{Estándar de la industria}\\[0.2em]
\checkitem{TLS 1.3, IPsec}
\end{accentcard}

\column{0.5\textwidth}
\begin{accentcard}
{\Large\bfseries\color{indigo}ChaCha20-Poly1305}\\[0.5em]
\small RFC 7539\\[0.3em]
\checkitem{Sin instrucciones AES}\\[0.2em]
\checkitem{Constant-time por diseño}\\[0.2em]
\checkitem{Ideal para móviles}
\end{accentcard}
\end{columns}

\vspace{0.8em}

\begin{alertcard}
\centering
\textbf{¿Por qué AEAD y no «encrypt + MAC»?}\\[0.3em]
\footnotesize Un solo mecanismo garantiza confidencialidad e integridad. Diseñar a mano es donde surgen POODLE, Lucky13, BEAST.
\end{alertcard}

## El AAD no es opcional

\vspace{0.3em}

```
┌─────────────────────────────────────────────┐
│ MAGIC(4) "SDDV"                             │
│ VERSION(1) = 1                              │  ← Cabecera
│ ALGO_ID(1)                                  │     completa pasa
│ TIMESTAMP(8) Unix UTC big-endian            │     como AAD
│ FNAME_LEN(2) uint16                         │     al DEM
│ FILENAME UTF-8                              │
├─────────────────────────────────────────────┤
│ NONCE(12) · CT_LEN(4) · CIPHERTEXT          │
│ TAG(16)                                     │
└─────────────────────────────────────────────┘
```

\vspace{0.3em}

\begin{accentcard}
\centering
\textbf{Propiedad clave:} modificar 1 bit del filename, timestamp o algoritmo $\Rightarrow$ \texttt{\color{coral}InvalidTag} al descifrar.
\end{accentcard}

## Estrategia de nonce

\vspace*{\fill}

\herostat{96}{bits aleatorios · CSPRNG · fresco por archivo}

\vspace{0.5em}

\begin{center}
\begin{minipage}{0.7\textwidth}
\begin{accentcard}
\centering
\textbf{Nonce reuse en GCM es CATASTRÓFICO}\\[0.3em]
\footnotesize Expone la authentication key.\\
Cada archivo usa clave fresca $\Rightarrow$ el límite es por-clave, no global.
\end{accentcard}
\end{minipage}
\end{center}

\vspace*{\fill}

# 3 · D3 — Cifrado Híbrido

## KEM + DEM en una línea

\vspace*{\fill}

\bigidea{Una llave \textcolor{accent}{efímera} por destinatario.\\Un archivo \textcolor{accent}{cifrado una vez}.}

\vspace{1em}

\begin{center}
\begin{minipage}{0.85\textwidth}
\begin{card}
\textbf{KEM} (Key Encapsulation) — X25519 ECDH:
\begin{itemize}\small
  \item Genera \texttt{file\_key} aleatoria de 256 bits
  \item Por cada destinatario: par X25519 efímero $\rightarrow$ ECDH $\rightarrow$ HKDF $\rightarrow$ wrap \texttt{file\_key}
\end{itemize}

\textbf{DEM} (Data Encapsulation) — AES-256-GCM o ChaCha20:
\begin{itemize}\small
  \item Cifra el archivo \textbf{una sola vez} con \texttt{file\_key}
\end{itemize}
\end{card}
\end{minipage}
\end{center}

\vspace*{\fill}

## Forward secrecy

\vspace*{\fill}

\begin{center}
{\fontsize{36pt}{44pt}\selectfont\bfseries\color{textmain}Las llaves efímeras}

\vspace{0.3em}
{\fontsize{36pt}{44pt}\selectfont\bfseries\color{accent}se destruyen}

\vspace{0.3em}
{\fontsize{36pt}{44pt}\selectfont\bfseries\color{textmain}tras el wrap.}
\end{center}

\vspace{1em}

\begin{center}
\begin{minipage}{0.75\textwidth}
\begin{accentcard}
\centering\footnotesize
Si en el futuro se filtra una \texttt{recipient\_priv}, los mensajes pasados \textbf{quedan protegidos} porque las efímeras ya no existen.
\end{accentcard}
\end{minipage}
\end{center}

\vspace*{\fill}

## Contenedor SDDH

\vspace{0.3em}

```
MAGIC(4) "SDDH" · VERSION · ALGO · TIMESTAMP(8)
FNAME_LEN(2) · FILENAME · RCPT_COUNT(2)

╔═ Por cada destinatario (124 B) ═══════════════════════╗
║  FINGERPRINT(32)  SHA-256(raw X25519 pubkey)          ║
║  EPH_PUB(32)      clave efímera                       ║
║  WRAP_NONCE(12)   nonce del wrap                      ║
║  WRAPPED_KEY(48)  file_key cifrada (32 ct + 16 tag)   ║
╚═══════════════════════════════════════════════════════╝
                                  ← fin del AAD del DEM
NONCE(12) · CT_LEN(4) · CIPHERTEXT · TAG(16)
```

\vspace{0.5em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{card}
\centering
{\large\bfseries\color{accent}Identidad}\\[0.3em]
\footnotesize SHA-256(raw X25519 pubkey) — 32 B\\Sin PKI
\end{card}
\column{0.5\textwidth}
\begin{card}
\centering
{\large\bfseries\color{accent}Hardening}\\[0.3em]
\footnotesize \texttt{MAX\_RECIPIENTS = 1024}\\Mitigación CWE-770
\end{card}
\end{columns}

# 3 · D5 — Firma Digital

## ¿Por qué Ed25519?

\vspace{0.5em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{accentcard}
{\Large\bfseries\color{accent}Propiedades}\\[0.5em]
\checkitem{Curve25519 · 128 bits de seguridad}\\[0.2em]
\checkitem{Llaves de 32 B}\\[0.2em]
\checkitem{Firma de 64 B}\\[0.2em]
\checkitem{Constant-time por diseño}
\end{accentcard}

\column{0.5\textwidth}
\begin{accentcard}
{\Large\bfseries\color{indigo}Determinismo}\\[0.5em]
\small No requiere CSPRNG en cada firma.\\[0.5em]
\footnotesize\color{textmuted}Inmune al ataque PS3 (Sony 2010): reuso de nonce en ECDSA expuso la llave maestra.
\end{accentcard}
\end{columns}

\vspace{0.8em}

\begin{center}
\footnotesize
\texttt{SIGN\_MAGIC(4)~+~SIGNER\_FP(32)~+~SIGNATURE(64) = 100 B}
\end{center}

## Verify-first

\vspace*{\fill}

\begin{center}
\begin{tabular}{lcl}
{\Large\bfseries\color{coral}Patrón ingenuo} & \quad vs. \quad & {\Large\bfseries\color{accent}API SDDV} \\[0.5em]
\small decrypt $\rightarrow$ verify & & \small \textbf{verify $\rightarrow$ decrypt} \\
\small expone plaintext si firma falla & & \small no toca el descifrado \\
\small posible timing oracle & & \small tiempo uniforme \\
\end{tabular}
\end{center}

\vspace{0.8em}

```python
def secure_verify_and_decrypt(signed_container, expected_signer_pub,
                              recipient_priv, max_age_seconds):
    container = verify_hybrid_container(    # ① VERIFY
        signed_container, expected_signer_pub)
                                            #   InvalidSignature → STOP
    return decrypt_for_recipient(           # ② DECRYPT (solo si verify OK)
        container, recipient_priv, max_age_seconds)
```

\vspace*{\fill}

## Binding de identidad

\vspace*{\fill}

\bigidea{El fingerprint del firmante\\está \textcolor{accent}{dentro} de lo firmado.}

\vspace{1.2em}

\begin{center}
\begin{minipage}{0.75\textwidth}
\begin{accentcard}
\centering\footnotesize
Un atacante \textbf{no puede sustituir} el firmante por Eve manteniendo la firma de Alice.

\vspace{0.4em}
\texttt{SIGNATURE = Ed25519(SDDH \texttt{||} "SIGS" \texttt{||} SIGNER\_FP)}
\end{accentcard}
\end{minipage}
\end{center}

\vspace*{\fill}

# 3 · D6 — Key Management

## Protección de llaves

\vspace{0.3em}

\bigidea{scrypt + AES-256-GCM}

\vspace{0.5em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{card}
{\bfseries\color{accent}KDF — scrypt} \pill{indigo}{RFC 7914}\\[0.4em]
\small Memory-hard $\rightarrow$ penaliza GPU/ASIC\\[0.3em]
\begin{tabular}{@{}lr@{}}
$n$    & $2^{15}$ = 32 768 \\
$r$    & 8 \\
$p$    & 1 \\
\texttt{dklen} & 32 B \\
\texttt{salt}  & 16 B CSPRNG \\
\end{tabular}
\end{card}

\column{0.5\textwidth}
\begin{accentcard}
{\bfseries\color{accent}Costo deliberado}\\[0.3em]
\centering
{\Large 150 ms} y {\Large 80 MiB} RAM\\
por intento en laptop\\[0.5em]
\footnotesize\color{textmuted}Con password de 50 bits + 1000 GPUs:\\
\textbf{\color{accent}\large $\approx$ 2 700 años}
\end{accentcard}
\end{columns}

## Keystore JSON

\vspace{0.3em}

```json
{
  "version": 1, "name": "alice", "status": "active",
  "kdf": {
    "algorithm": "scrypt", "salt_b64": "...",
    "n": 32768, "r": 8, "p": 1, "dklen": 32
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "nonce_b64": "...", "tag_b64": "..."
  },
  "encrypted_private_key": "...",
  "public_keys":  {"ed25519_pub_b64": "...", "x25519_pub_b64": "..."},
  "fingerprints": {"ed25519": "...", "x25519": "..."},
  "metadata":     {"expires_at": null, "rotated_from": null}
}
```

## Ciclo de vida

\vspace*{\fill}

\begin{center}
\begin{tikzpicture}[
  every node/.style={font=\small\bfseries, text=textmain},
  op/.style={rectangle, rounded corners=8pt, fill=bgcard, draw=accent, line width=0.5pt,
             minimum height=0.9cm, minimum width=2.4cm, inner sep=4pt}
]
  \node[op] (init)   {init};
  \node[op, right=0.4cm of init]   (unlock) {unlock};
  \node[op, right=0.4cm of unlock] (change) {change-pwd};
  \node[op, right=0.4cm of change] (rotate) {rotate};

  \node[op, below=0.5cm of init]   (revoke) {revoke};
  \node[op, right=0.4cm of revoke] (delete) {delete};
  \node[op, right=0.4cm of delete] (backup) {backup};
  \node[op, right=0.4cm of backup] (restore){restore};
\end{tikzpicture}
\end{center}

\vspace{0.8em}

\begin{center}
\begin{minipage}{0.85\textwidth}
\begin{accentcard}
\centering
\textbf{Política de no-caching:} cada \texttt{unlock} re-deriva con scrypt.\\
\footnotesize La llave privada vive solo en el frame del caller.
\end{accentcard}
\end{minipage}
\end{center}

\vspace*{\fill}

# 4 · Secure Practices

## Las 4 prácticas que aplicamos

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{accentcard}
{\large\bfseries\color{accent}Input validation}\\[0.3em]
\footnotesize
\dotitem{\texttt{validate\_filename} (CWE-22)}\\
\dotitem{\texttt{validate\_timestamp} (CWE-294)}\\
\dotitem{\texttt{ciphertext\_length} 100 MiB (CWE-770)}\\
\dotitem{\texttt{MAX\_RECIPIENTS = 1024}}
\end{accentcard}

\vspace{0.5em}

\begin{accentcard}
{\large\bfseries\color{accent}Fail-closed}\\[0.3em]
\footnotesize
\dotitem{Verify antes de decrypt}\\
\dotitem{\texttt{unlock} bloquea si revoked/expired}\\
\dotitem{AEAD nunca devuelve plaintext si tag falla}
\end{accentcard}

\column{0.5\textwidth}
\begin{accentcard}
{\large\bfseries\color{indigo}Canonicalization}\\[0.3em]
\footnotesize
\dotitem{\texttt{struct.pack(">Q",...)} big-endian}\\
\dotitem{JSON con \texttt{separators=(",",":")} }\\
\dotitem{\texttt{posixpath.normpath} check}
\end{accentcard}

\vspace{0.5em}

\begin{accentcard}
{\large\bfseries\color{indigo}Error handling}\\[0.3em]
\footnotesize
\dotitem{\texttt{InvalidTag} · \texttt{InvalidSignature}}\\
\dotitem{\texttt{IdentityRevokedError}}\\
\dotitem{Sin atrapar excepciones genéricas}
\end{accentcard}
\end{columns}

## Lección clave

\vspace*{\fill}

\bigidea{Si la API es difícil\\de usar mal,}

\vspace{0.5em}

\begin{center}
{\fontsize{28pt}{36pt}\selectfont\bfseries\color{accent}los errores de implementación}
\end{center}

\vspace{0.3em}

\begin{center}
{\fontsize{32pt}{40pt}\selectfont\bfseries\color{textmain}se reducen drásticamente.}
\end{center}

\vspace{1em}

\begin{center}
\footnotesize\color{textmuted}\itshape
Misuse-resistant design · NaCl · libsodium
\end{center}

\vspace*{\fill}

# 5 · Security Audit

## Vulnerabilidades resueltas

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{alertcard}
\pill{coral}{VULN-001 · ALTA}\\[0.3em]
\textbf{Path traversal} en filename\\
\footnotesize CWE-22 · Fix: \texttt{validate\_filename}
\end{alertcard}
\vspace{0.4em}
\begin{accentcard}
\pill{amber}{VULN-002}\\[0.3em]
\textbf{Replay} sin freshness check\\
\footnotesize CWE-294 · Fix: \texttt{validate\_timestamp}
\end{accentcard}
\vspace{0.4em}
\begin{accentcard}
\pill{amber}{VULN-003}\\[0.3em]
\textbf{DoS} por \texttt{ct\_len} sin tope\\
\footnotesize CWE-770 · Fix: 100 MiB cap
\end{accentcard}
\vspace{0.4em}
\begin{accentcard}
\pill{amber}{VULN-004}\\[0.3em]
\textbf{DoS} por \texttt{RCPT\_COUNT} sin tope\\
\footnotesize CWE-770 · Fix: 1024 cap
\end{accentcard}

\column{0.5\textwidth}
\begin{accentcard}
\pill{amber}{VULN-005}\\[0.3em]
\textbf{Type confusion} SDDH$\rightarrow$SDDV\\
\footnotesize Fix: detección de magic
\end{accentcard}
\vspace{0.4em}
\begin{accentcard}
\pill{amber}{VULN-006}\\[0.3em]
\textbf{Path traversal} al unpacking\\
\footnotesize CWE-22 · Fix: \texttt{safe\_path\_join}
\end{accentcard}
\vspace{0.4em}
\begin{accentcard}
\pill{amber}{VULN-007}\\[0.3em]
\textbf{Password débil} en PKCS8\\
\footnotesize CWE-521 · Fix: \texttt{MIN\_LEN=12}
\end{accentcard}
\vspace{0.4em}
\begin{accentcard}
\centering
\textbf{\color{accent}24 tests de regresión}\\
\footnotesize Todos en verde
\end{accentcard}
\end{columns}

## Lo que NO protegemos

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{alertcard}
\xitem{Dispositivo comprometido}\\[0.2em]
\footnotesize Keylogger, RAM dump → requiere HSM
\end{alertcard}
\vspace{0.3em}
\begin{alertcard}
\xitem{Distribución de pubkeys}\\[0.2em]
\footnotesize No hay PKI; canal fuera de scope
\end{alertcard}
\vspace{0.3em}
\begin{alertcard}
\xitem{Revocación distribuida}\\[0.2em]
\footnotesize Sin CRL/OCSP; revoke local
\end{alertcard}

\column{0.5\textwidth}
\begin{alertcard}
\xitem{Side-channel físico}\\[0.2em]
\footnotesize Cold boot, EMI → hardware
\end{alertcard}
\vspace{0.3em}
\begin{alertcard}
\xitem{Pérdida de pwd + backup}\\[0.2em]
\footnotesize Propiedad criptográfica, no bug
\end{alertcard}
\vspace{0.3em}
\begin{alertcard}
\xitem{Quantum adversary}\\[0.2em]
\footnotesize Roadmap: hybrid PQ (RFC 9180)
\end{alertcard}
\end{columns}

\vspace{0.5em}

\begin{center}
\footnotesize\color{textmuted}\itshape
Documentar lo que NO se hace es tan importante como documentar lo que sí.
\end{center}

# 6 · Final Demo

## Lo que vamos a mostrar

\vspace*{\fill}

\begin{center}
\begin{minipage}{0.85\textwidth}
\begin{enumerate}\large
  \setlength{\itemsep}{0.3em}
  \item Init identidades \textbf{alice + bob}
  \item Alice cifra y firma para Bob
  \item Bob \texttt{verify + decrypt} $\rightarrow$ \textcolor{accent}{plaintext}
  \item Password incorrecto $\rightarrow$ \textcolor{coral}{\texttt{InvalidTag}}
  \item Contenedor modificado $\rightarrow$ \textcolor{coral}{\texttt{InvalidSignature}}
  \item Rotate keys de Alice
  \item Backup $\rightarrow$ delete $\rightarrow$ restore
\end{enumerate}
\end{minipage}
\end{center}

\vspace{0.8em}

\begin{center}
\begin{minipage}{0.65\textwidth}
\begin{accentcard}
\centering
\texttt{python demo\_d6.py}\\
\texttt{bash verificar\_d6.sh}
\end{accentcard}
\end{minipage}
\end{center}

\vspace*{\fill}

## Estado final

\herostat{300 / 300}{tests verdes}

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.25\textwidth}
\statcard{4500}{líneas Python}
\column{0.25\textwidth}
\statcard{4}{docs de diseño}
\column{0.25\textwidth}
\statcard{7}{vulns resueltas}
\column{0.25\textwidth}
\statcard{32}{commits}
\end{columns}

\vspace{0.8em}

\begin{center}
\small\color{textmuted}\texttt{github.com/milliyx/Cryptography}
\end{center}

# Referencias

## Estándares y guías

\vspace{0.3em}

\begin{columns}[T,onlytextwidth]
\column{0.5\textwidth}
\begin{accentcard}
{\bfseries\color{accent}Estándares · RFCs}\\[0.4em]
\footnotesize
\dotitem{NIST SP 800-38D — GCM}\\
\dotitem{RFC 7539 — ChaCha20 + Poly1305}\\
\dotitem{RFC 7748 — X25519 (Curve25519)}\\
\dotitem{RFC 7914 — scrypt KDF}\\
\dotitem{RFC 8032 — Ed25519 (EdDSA)}\\
\dotitem{RFC 9180 — HPKE}\\
\dotitem{RFC 5869 — HKDF}
\end{accentcard}

\column{0.5\textwidth}
\begin{accentcard}
{\bfseries\color{indigo}Guías · Librerías}\\[0.4em]
\footnotesize
\dotitem{OWASP Password Storage Cheat Sheet}\\
\dotitem{OWASP Cryptographic Storage}\\
\dotitem{libsodium / NaCl misuse-resistant}\\
\dotitem{\texttt{cryptography} (pyca) — primitivas}\\
\dotitem{\texttt{hashlib.scrypt} — stdlib}\\
\dotitem{\texttt{pytest} — testing}
\end{accentcard}
\end{columns}

## Q\&A

\vspace*{\fill}

\begin{center}
{\fontsize{72pt}{84pt}\selectfont\bfseries\color{accent}¿Preguntas?}
\end{center}

\vspace{2em}

\begin{center}
{\large\color{textmain}\bfseries Equipo 7}\\[0.5em]
{\small\color{textmuted}Barrios · Caballero · Contreras · Martínez}\\[1em]
{\footnotesize\color{textmuted}github.com/milliyx/Cryptography}
\end{center}

\vspace*{\fill}
