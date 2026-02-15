# Boveda Digital Segura de Documentos (Secure Digital Document Vault)

## Que es

Es una aplicacion de linea de comandos que sirve para proteger documentos sensibles con criptografia. La idea es que si alguien tiene archivos importantes (contratos, expedientes medicos, reportes financieros, etc.) pueda cifrarlos, firmarlos y compartirlos de forma segura sin depender de herramientas como el correo o la nube que no dan garantias reales de seguridad.

## Que problema resuelve

Las herramientas normales para compartir archivos no garantizan que nadie mas pueda leer el contenido, ni que el archivo no haya sido modificado, ni que el remitente sea realmente quien dice ser. Este sistema busca cubrir esos tres aspectos: confidencialidad, integridad y autenticidad.

## Que hace

| Operacion | Descripcion |
|---|---|
| **Cifrar** | Protege el archivo con cifrado autenticado (AEAD) usando AES-GCM o ChaCha20-Poly1305 |
| **Compartir** | Manda el archivo cifrado a alguien especifico usando cifrado hibrido (clave simetrica por archivo + clave publica del destinatario) |
| **Verificar** | Firma digitalmente el archivo con Ed25519 o RSA-PSS para comprobar quien lo mando y que no fue alterado |
| **Gestionar claves** | Las claves privadas se guardan cifradas en un Key Store protegido con Argon2id. Nunca en texto plano |

## Primitivas criptograficas

| Funcion | Algoritmo |
|---|---|
| Cifrado simetrico (AEAD) | AES-256-GCM o ChaCha20-Poly1305 |
| Cifrado asimetrico | RSA-OAEP / X25519 ECDH |
| Firmas digitales | Ed25519 / RSA-PSS |
| Derivacion de claves (KDF) | Argon2id / PBKDF2 |
| Aleatoriedad | CSPRNG (os.urandom) |

## Stack tecnologico

| Componente | Tecnologia |
|---|---|
| Lenguaje | Python 3.10+ |
| Libreria criptografica | cryptography (pyca) |
| Formato | CLI / Aplicacion de escritorio |

## Equipo

| Nombre | GitHub |
|---|---|
| Barrios Aguilar Dulce Michelle | @milliyx |
| Contreras Colmenero Emilio Sebastian | @SEBASTIANCONTRERAS35 |
| Martinez Lopez Evan Emiliano | @EvanEmi |
| Pulido Vazquez Rodrigo | @rothd123 |

## Referencias

- Ferguson, Schneier, Kohno. *Cryptography Engineering*. Wiley.
- RFC 4107 / BCP 107: Guidelines for Cryptographic Key Management.
- BCP 86 / RFC 4086: Randomness Requirements for Security.
- Menezes, van Oorschot, Vanstone. *Handbook of Applied Cryptography*. CRC Press.