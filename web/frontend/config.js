// Configuracion publica del proyecto Appwrite.
// Project ID y endpoint NO son secretos — viven en el frontend y se envian en
// cada request. Lo unico secreto serian las API Keys (esas se quedan en server).
// La proteccion real viene del CORS por "Platforms" configurado en Appwrite.

export const APPWRITE_ENDPOINT   = "https://sfo.cloud.appwrite.io/v1";
export const APPWRITE_PROJECT_ID = "6a0768fb000a8c5a630f";

// Bucket donde cada usuario guarda sus keystores (<name>.json).
// Permisos a nivel de bucket: solo "Users" puede crear. Lectura/escritura/borrado
// se setean por archivo en el momento de subirlo (solo el dueno tiene acceso).
export const KEYSTORE_BUCKET_ID  = "6a076dd60035a715ea1a";
