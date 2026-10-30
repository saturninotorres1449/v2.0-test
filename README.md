# EGO BAR Backend v2.0

Backend preparado para el proyecto EGO BAR con Node.js 20+, Express y PostgreSQL de Neon. El servicio se despliega en Render y puede probarse desde Hoppscotch. No contiene ni configura dominio o página pública QR.

## Importante antes de desplegar

- El servicio actual de Render y la base Neon no se modifican automáticamente con este paquete.
- Revisar `server/.env.example` y cargar los secretos en Render, nunca en GitHub.
- `ADMIN_EMAIL` debe ser el correo principal existente. No cambiarlo sin plan de recuperación.
- Resend sandbox solo entrega a destinatarios verificados; para iniciar sesión con otros administradores hace falta un remitente/dominio validado o un proveedor de correo habilitado.
- La primera inicialización agrega columnas/tablas con `IF NOT EXISTS`. Probar primero contra una base Neon de pruebas o un branch de Neon.
- Los códigos de activación de Controlador son de 8 caracteres hexadecimales para mantener compatibilidad con la app v2.0; expiran en 30 minutos, se invalidan al emitir otro y admiten hasta 5 intentos.

## Render

Configuración compatible con el servicio existente:

- Root Directory: `server`
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/health`
- Runtime: Node 20 o superior

Variables: `DATABASE_URL`, `JWT_SECRET`, `ADMIN_EMAIL`, `RESEND_API_KEY`, `RESEND_FROM`, `CORS_ORIGIN`. `PORT` lo asigna Render.

## Hoppscotch

Crear un Environment:

- `baseUrl` = `https://ego-bar-backend.onrender.com`
- `adminToken` = token devuelto por `POST /auth/verify-code`
- `controllerToken` = token devuelto por `POST /auth/activate-controller`

En requests protegidos usar header `Authorization: Bearer {{adminToken}}` o `Bearer {{controllerToken}}`.

### Flujo administrador

1. `GET {{baseUrl}}/health`
2. `POST {{baseUrl}}/auth/request-code` JSON `{ "email": "correo-admin-autorizado" }`
3. `POST {{baseUrl}}/auth/verify-code` JSON `{ "email": "correo-admin-autorizado", "code": "123456" }`
4. `GET {{baseUrl}}/auth/me`
5. `GET {{baseUrl}}/admin/users`
6. `POST {{baseUrl}}/admin/controllers` JSON `{ "firstName":"Nombre", "lastName":"Apellido", "email":"controlador@correo.com" }`
7. Guardar `activationCode` de la respuesta y probar `POST {{baseUrl}}/auth/activate-controller` JSON `{ "email":"controlador@correo.com", "code":"CODIGO8" }`.
8. `POST {{baseUrl}}/admin/credentials` para registrar credencial.
9. `GET {{baseUrl}}/admin/statistics` y `GET {{baseUrl}}/admin/entries`.

### Flujo Controlador

1. Activar con el código entregado por un Administrador.
2. `GET {{baseUrl}}/auth/me` con `controllerToken`.
3. `GET {{baseUrl}}/private/credentials/TOKEN_QR`.
4. `POST {{baseUrl}}/private/credentials/TOKEN_QR/scan` JSON `{}`.
5. `GET {{baseUrl}}/controller/entries`.
6. Confirmar que `GET /admin/users` y `GET /admin/statistics` responden `403`.

## Rutas

- `GET /health`
- `POST /auth/request-code`, `POST /auth/verify-code`, `POST /auth/activate-controller`, `GET /auth/me`
- `GET /admin/users`, `POST /admin/users`, `PATCH /admin/users/:email/role`, `POST /admin/users/:email/active`
- `GET /admin/controllers`, `POST /admin/controllers`, `POST /admin/controllers/:email/code`
- `POST /admin/credentials`
- `GET /private/credentials/:token`, `POST /private/credentials/:token/scan`
- `GET /controller/entries`
- `GET /admin/statistics`, `GET /admin/entries`
- `GET /public/credentials/:token` se conserva por compatibilidad interna, pero no se debe publicar ni configurar en esta etapa.

## Seguridad aplicada

- JWT con issuer y vencimiento; cada request consulta el usuario vigente en PostgreSQL.
- Cambios de rol/activación incrementan `session_version` e invalidan sesiones anteriores.
- Middleware de administrador en rutas administrativas.
- Los Controladores no pueden usar login de Administrador y solo ven datos mínimos de credencial y su historial de escaneos.
- Códigos de email con vencimiento y límite de intentos; activaciones de Controlador de un solo uso, 30 minutos, máximo 5 intentos y rate limit por IP/correo.
- Escaneo con transacción y `SELECT ... FOR UPDATE` para impedir doble ingreso concurrente.
- Credenciales usadas o revocadas no se pueden reactivar mediante upsert.
- PostgreSQL es el único almacenamiento; no hay SQLite ni archivos de base locales.

Los límites de rate limit en memoria son por instancia; para despliegues con varias instancias se recomienda moverlos a Redis.

Se incluye `hoppscotch/EGO_BAR_v2.0_API.postman_collection.json`, una colección Postman v2.1 que puede importarse en Hoppscotch. Después de cada login/activación, copiar manualmente el token de la respuesta al Environment correspondiente. El código de activación también se copia de la respuesta de alta del Controlador.


## Acceso de Administradores (actualización v2.0)

- El `ADMIN_EMAIL` principal es el único que puede solicitar y verificar códigos por Resend (`POST /auth/request-code` y `POST /auth/verify-code`).
- Los demás Administradores se crean desde una sesión Admin con `POST /admin/administrators`. La respuesta incluye un token aleatorio de 128 bits, de un solo uso y válido durante 24 horas; la app puede compartir `shareText` por WhatsApp.
- La persona invitada activa su cuenta con `POST /auth/activate-admin` enviando `email`, `token` y una contraseña de al menos 10 caracteres. El token se invalida al activarse y la contraseña se almacena con bcrypt.
- Los accesos posteriores usan `POST /auth/admin-login` con correo y contraseña. El administrador principal no puede usar esta ruta.
- Para reemplazar una invitación pendiente: `POST /admin/administrators/:email/token`.
- Los códigos de activación se guardan como hash, expiran a las 24 horas, admiten hasta cinco intentos y se invalidan al generar uno nuevo.

**Importante:** las rutas nuevas requieren desplegar esta versión y ejecutar la inicialización/migración sobre una base de pruebas antes de producción. No ejecutar cambios en Neon productivo hasta aprobar las pruebas.
