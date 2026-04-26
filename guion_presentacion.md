# Guión de Presentación — SDDV D4
**Bóveda Digital Segura de Documentos**
Dr. Rocío Aldeco Pérez · Criptografía · UNAM 2026

---

## Distribución del tiempo (15 min total)

| Sección | Slide | Presentador | Tiempo |
|---------|-------|-------------|--------|
| Portada + intro | 1 | Emilio | ~30 s |
| **A** System Overview | 2 | Emilio | 1.5 min |
| **B** Arquitectura | 3 | Dulce | 2.5 min |
| **C** Modelo de Amenazas | 4 | Evan | 2.5 min |
| **D** Diseño Criptográfico D2 (AEAD) | 5 | Sergio | 2 min |
| **D** Diseño Criptográfico D3 (Híbrido) | 6 | Sergio | 2 min |
| **E** Demo en Vivo | 7 | Dulce | 2.5 min |
| Cierre + preguntas | 8 | Emilio | ~30 s |

---

## Presentadores

- **Emilio** — Contreras Colmenero Emilio Sebastian *(abre y cierra, Overview)*
- **Dulce** — Barrios Aguilar Dulce Michelle *(Arquitectura + Demo)*
- **Evan** — Martínez López Evan Emiliano *(Modelo de Amenazas)*
- **Sergio** — Caballero Martínez Sergio Jair *(Diseño Criptográfico)*

---

## Slide 1 — Portada *(Emilio, ~30 s)*

> "Buenos días. Somos el equipo SDDV — Bóveda Digital Segura de Documentos.
> Vamos a presentar la Entrega D4, que cubre el diseño criptográfico completo
> de nuestro sistema: AEAD, firmas digitales y cifrado híbrido multi-destinatario.
> Tenemos 15 minutos, así que vamos directo al punto."

---

## Slide 2 — A: System Overview *(Emilio, ~1.5 min)*

**Problema:**
> "El problema que resolvemos es simple pero serio: hoy los archivos digitales
> se almacenan sin cifrado. Cualquier persona con acceso al disco puede leerlos.
> No hay forma de verificar si un archivo fue alterado, y compartir con múltiples
> personas implica múltiples canales inseguros."

**Solución:**
> "SDDV resuelve esto con tres propiedades garantizadas criptográficamente:
> Confidencialidad — nadie lee el archivo sin la llave correcta.
> Integridad — cualquier modificación, aunque sea de un solo byte, es detectable.
> Autenticidad — sabemos exactamente quién firmó cada documento."

**Contenedores:**
> "El sistema produce dos tipos de contenedores: SDDV para un solo destinatario
> usando cifrado simétrico, y SDDH para múltiples destinatarios con cifrado híbrido.
> Ambos llevan firma digital incorporada."

---

## Slide 3 — B: Arquitectura del Sistema *(Dulce, ~2.5 min)*

**Diagrama:**
> "Esta es la arquitectura completa. En la zona verde superior tenemos la zona
> de confianza del usuario: el archivo plano, el Keystore con las llaves Ed25519
> y X25519, y la contraseña que cifra las llaves privadas en disco."

> "En el centro está el motor criptográfico. El módulo crypto/aead.py maneja
> AES-256-GCM y ChaCha20. crypto/keys.py gestiona las llaves. signatures.py
> implementa Ed25519, y hybrid.py orquesta todo el flujo KEM+DEM."

**Componentes:**
> "Del lado derecho vemos los componentes principales:
> El Vault es el contenedor cifrado en disco.
> El Keystore almacena las llaves en formato PEM PKCS8.
> El Motor AEAD cifra y autentica cada archivo.
> El Módulo de Firmas garantiza el Encrypt-then-Sign."

**Flujo de datos:**
> "El flujo es: Plaintext entra al módulo AEAD, se cifra, el resultado se empaqueta
> en un contenedor SDDV, y se firma. Todo en una sola llamada encrypt_file()."

**Límites de confianza:**
> "Importante: solo confiamos en lo que está en RAM y en las llaves del usuario.
> El disco, la red, y el servidor de archivos se consideran no confiables."

---

## Slide 4 — C: Modelo de Amenazas *(Evan, ~2.5 min)*

**Atacante:**
> "Definimos un atacante con cinco capacidades:
> Acceso físico al disco — puede leer los archivos cifrados directamente.
> Captura pasiva de red — intercepta tráfico.
> Modificación activa de archivos — puede alterar bytes del contenedor.
> Destinatario no autorizado — alguien que recibió el archivo pero no debería.
> Y servidor de almacenamiento comprometido — el peor caso."

**Activos protegidos:**
> "Lo que protegemos es: el contenido del archivo con AEAD 256 bits, la identidad
> del emisor con firma Ed25519 verificable, la lista de destinatarios en AAD
> protegida por TAG, las llaves privadas en PEM PKCS8 cifradas en disco,
> y los metadatos: filename y timestamp en AAD."

**Suposiciones del sistema:**
> "Y lo que asumimos fuera de scope:
> RAM es confiable — no protegemos contra ataques de memoria en ejecución.
> Las llaves privadas son secretas — el usuario protege su contraseña PEM.
> La distribución de llaves públicas está fuera del alcance del sistema.
> Y asumimos que la biblioteca cryptography de Python es correcta."

---

## Slide 5 — D: Diseño Criptográfico — AEAD *(Sergio, ~2 min)*

**Elección AEAD:**
> "Para el cifrado simétrico elegimos AES-256-GCM como opción principal.
> Es estándar NIST, acelerado por hardware en prácticamente cualquier CPU moderna,
> con clave de 256 bits y tag de 128 bits que autentica tanto el ciphertext como el AAD."

> "Como alternativa ofrecemos ChaCha20-Poly1305, igualmente seguro
> pero más eficiente en software, ideal para dispositivos sin aceleración hardware.
> El usuario puede elegir cuál usar — la interfaz es idéntica."

**Nonce:**
> "El nonce es de 96 bits, exactamente 12 bytes, generado con os.urandom()
> que usa el CSPRNG del sistema operativo. Es único por operación de cifrado —
> nunca reutilizamos la misma combinación clave-nonce, lo que garantiza
> que GCM no se rompa. Se almacena en el contenedor, el receptor no necesita
> ningún canal adicional."

**AAD y metadatos:**
> "El AAD autentica datos que no van cifrados pero sí verificados:
> el nombre del archivo, el timestamp Unix, el algoritmo usado,
> y en el caso de SDDH, la lista de destinatarios.
> Si cualquier byte del AAD cambia, el TAG falla al verificar.
> Esto previene que un atacante renombre el archivo o cambie el timestamp."

---

## Slide 6 — D: Diseño Criptográfico — Híbrido *(Sergio, ~2 min)*

**Flujo KEM+DEM:**
> "Para múltiples destinatarios usamos el esquema KEM+DEM.
> DEM es el Data Encapsulation Mechanism: generamos una file_key aleatoria de 256 bits,
> ciframos el archivo con AES-GCM usando esa clave, y el AAD incluye la lista completa
> de destinatarios."

> "KEM es el Key Encapsulation Mechanism: por cada destinatario, generamos un par
> X25519 efímero, hacemos ECDH con la llave pública permanente del destinatario,
> derivamos una wrapping_key con HKDF-SHA256, y ciframos la file_key con AESGCM.
> Cada destinatario recibe su propio slot de 48 bytes en el contenedor."

**Destinatarios y Forward Secrecy:**
> "La lista de destinatarios va en el AAD: cualquier cambio invalida el TAG.
> Cada slot tiene tamaño fijo de 124 bytes. La seguridad hacia adelante está
> garantizada porque usamos una llave X25519 efímera única por destinatario.
> Aunque en el futuro se comprometa la llave permanente, no se puede reconstruir
> la llave efímera y por lo tanto no se puede descifrar mensajes pasados."

**Identificación de llaves:**
> "Para que cada receptor encuentre su slot sin leer todos, usamos un fingerprint:
> SHA-256 de la llave pública, que produce 64 caracteres hex.
> El receptor busca su fingerprint en el header, y sólo necesita descifrar su slot."

---

## Slide 7 — E: Demo en Vivo *(Dulce, ~2.5 min)*

> "Vamos a ejecutar cuatro escenarios en vivo. Tengo abierta la terminal."

**Escenario 1 — Cifrar un archivo:**
> *(ejecutar)* `python demo.py encrypt documento.txt`
> "encrypt_file() genera el contenedor SDDV. El archivo cifrado es binario puro,
> nada legible. Resultado: Contenedor SDDV creado."

**Escenario 2 — Compartir con otro usuario:**
> *(ejecutar)* `python demo.py share documento.txt alice bob`
> "encrypt_for_recipients() genera un contenedor SDDH con slots para Alice y Bob.
> Alice y Bob aparecen como destinatarios autorizados en el AAD."

**Escenario 3 — Descifrar como usuario autorizado:**
> *(ejecutar)* `python demo.py decrypt contenedor.sddh alice`
> "decrypt_for_recipient() busca el fingerprint de Alice, descifra su slot,
> obtiene la file_key, descifra el contenido. Alice descifra correctamente.
> Lo mismo funciona para Bob."

**Escenario 4 — Fallo: no autorizado y tamper:**
> *(ejecutar)* `python demo.py tamper contenedor.sddh`
> "Eve intenta descifrar — InvalidTag, acceso denegado.
> Modificamos un byte del ciphertext — InvalidTag en ambos casos.
> El sistema detecta cualquier alteración."

---

## Slide 8 — Cierre *(Emilio, ~30 s)*

> "En resumen: SDDV implementa confidencialidad con AES-256-GCM,
> integridad y autenticidad con Ed25519 y Encrypt-then-Sign,
> y cifrado híbrido multi-destinatario con X25519 KEM+DEM y HKDF-SHA256.
> 94 tests, cero fallos, 966 líneas en 4 módulos."

> "Estamos listos para preguntas."

---

## Preguntas frecuentes anticipadas

**¿Por qué AES-256-GCM y no solo ChaCha20?**
> "Ambos son seguros. AES-256-GCM es más rápido con aceleración hardware (AES-NI),
> presente en casi todos los CPUs modernos. ChaCha20 es mejor en dispositivos
> sin esa aceleración. Por eso ofrecemos ambos."

**¿Cómo evitan la reutilización del nonce?**
> "Generamos el nonce con os.urandom(12) en cada operación de cifrado.
> Con 96 bits aleatorios, la probabilidad de colisión es negligible
> incluso con 2^32 mensajes — dentro del margen de seguridad de GCM."

**¿Qué pasa si se compromete la llave privada de X25519?**
> "Forward Secrecy: usamos llaves X25519 efímeras, una distinta por destinatario
> y por mensaje. La llave efímera nunca se guarda. Comprometer la llave permanente
> no permite descifrar mensajes pasados porque no se puede reconstruir el secreto ECDH."

**¿Por qué Encrypt-then-Sign y no Sign-then-Encrypt?**
> "Encrypt-then-Sign garantiza que la firma cubre el ciphertext completo.
> Con Sign-then-Encrypt, un atacante podría quitar el cifrado y reutilizar la firma
> sobre el plaintext en otro contexto. Encrypt-then-Sign evita eso."

**¿Cómo se distribuyen las llaves públicas?**
> "Está fuera del scope — es una suposición de seguridad explícita. En la práctica
> se usaría un directorio de llaves o PKI. SDDV asume que el usuario ya tiene
> las llaves públicas de sus destinatarios."

---

*Tiempo total estimado: 13–15 minutos · Margen para preguntas: 2–5 minutos*
