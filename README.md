# Servicio B2B de contratos y firma electrónica

Implementación en Python del documento de propuesta conceptual. Genera contratos
desde plantillas versionadas, los envía a firma, recopila evidencias, custodia el
documento final y notifica por webhook.

**Stack:** Python · FastAPI · SQLAlchemy 2 · Alembic · SQLite (o PostgreSQL) ·
Jinja2 · cryptography · ReportLab. Redis opcional. Sin dependencias de sistema:
arranca con `pip install`, también en Windows.

---

## Arrancar en tres minutos

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print('CLAVE_APP=' + secrets.token_hex(32))"   # pega el valor en .env

python -m scripts.sembrar          # empresa, credencial, plantilla y admin de ejemplo
python -m uvicorn app.main:app --reload
python -m scripts.tareas           # en otra terminal: vencimientos y reintentos
```

No hace falta instalar PostgreSQL: si `URL_BASE_DATOS` está vacía se usa SQLite en
`contratos.db`. Para pasar a PostgreSQL basta poner la URL; el modelo y las
consultas son los mismos.

La documentación interactiva de la API queda en <http://localhost:8000/docs> y el
portal administrativo en <http://localhost:8000/admin>.

En Windows sin rutas largas habilitadas, deja `CARPETA_ALMACEN` en una ruta corta
(la de por defecto, `./almacen`, sirve): cada documento se guarda en
`empresa/contrato/clave.html` y el sistema no admite rutas de más de 260
caracteres.

### Ver el flujo completo

```bash
python -m scripts.demo_flujo <client_id> <client_secret>
```

Crea un contrato, te deja firmar como cliente y como empresa, y guarda el
documento final en `contrato-final.html`. El código OTP y los enlaces de
invitación aparecen en la consola del servidor (solo en desarrollo, con
`PROVEEDOR_CORREO=consola` y `MOSTRAR_SECRETOS_EN_LOG=true`).

### Pruebas

```bash
python -m pytest -v
```

166 pruebas. `test_aceptacion.py` recorre los criterios de aceptación de la
sección 14 del documento: aislamiento entre empresas, rechazo de variables no
declaradas, escapado de XSS, idempotencia, firma HMAC de webhooks, bloqueo de
destinos SSRF, integridad de la cadena de auditoría y detección de documentos
alterados. El resto cubre vencimiento, rechazo, notificaciones (SMTP y Twilio
contra servidores simulados), la cola de avisos, la cola de webhooks y la IP
fijada contra DNS rebinding, el limitador, el listado, el PDF, el portal
administrativo con TOTP (incluidos los vectores del RFC 6238) y las migraciones.
No necesitan red ni Redis.

---

## Cómo se siente para quien integra

```
POST /v1/contratos          ->  { contract_id, status, signing_url, document_hash }
   (esperar el webhook contract.completed)
GET  /v1/contratos/{id}/documento   ->  documento final con su constancia
```

Crear contrato, obtener URL de firma, esperar webhook, descargar documento. Toda
la complejidad vive dentro del servicio.

### Endpoints

| Método | Ruta | Para qué |
|---|---|---|
| POST | `/v1/plantillas` | Crear plantilla y publicar una versión inmutable |
| POST | `/v1/contratos` | Crear contrato (acepta `Idempotency-Key`) |
| GET | `/v1/contratos` | Listar con filtros (`estado`, `referencia_externa`, fechas) y cursor |
| GET | `/v1/contratos/{id}` | Estado y firmantes |
| POST | `/v1/contratos/{id}/reenviar` | Nueva invitación para la parte pendiente |
| POST | `/v1/contratos/{id}/anular` | Anular (falla si ya está completado) |
| GET | `/v1/contratos/{id}/documento` | Documento presentado o final; `?formato=pdf` para el PDF |
| GET | `/v1/contratos/{id}/auditoria` | Eventos y verificación de la cadena |
| POST | `/v1/webhooks` | Registrar endpoint (devuelve el secreto una sola vez) |
| GET | `/v1/webhooks` | Endpoints registrados y su estado |
| GET | `/v1/webhooks/{id}/entregas` | Historial de entregas |
| POST | `/v1/webhooks/{id}/reactivar` | Reactivar un endpoint suspendido |
| POST | `/v1/webhooks/entregas/{id}/reintentar` | Volver a mandar un evento |
| GET | `/.well-known/clave-de-firma` | Clave pública para verificar firmas |

Autenticación HTTP Basic con `client_id` y `client_secret`. Cada endpoint exige
un permiso concreto de la credencial.

### Portal de firma

`/firma/{token}` → identificación con OTP → lectura del documento →
consentimiento expreso → firma (o rechazo, con un motivo opcional). Todo en el
dominio del servicio, para controlar cookies, cabeceras y aislamiento sin que el
integrador implemente nada.

Cada firmante recibe su enlace por correo, o por SMS si solo tiene teléfono. El
código OTP sale por el canal que pide la política de la plantilla (`canal_otp`).
Si el integrador prefiere entregar el enlace en su propia app, la política
acepta `"notificar_invitaciones": false`.

### Portal administrativo

`/admin` es la interfaz web de cada empresa: la bandeja de contratos por estado,
el detalle de cada uno con su línea de auditoría y la verificación de la cadena,
la descarga del documento y del PDF, reenviar y anular, publicar plantillas y
crear o revocar credenciales de la API.

Se entra con correo y clave, y el segundo factor es obligatorio: la primera vez
se registra una app autenticadora (Google Authenticator, Microsoft
Authenticator, 1Password...) con un código QR. Para dar de alta a alguien:

```bash
python -m scripts.crear_admin --empresa acme --email ana@acme.com --nombre "Ana Gomez"
```

### Tareas periódicas

`python -m scripts.tareas` corre aparte de la API y, cada 30 segundos, vence los
contratos que nadie firmó a tiempo y reintenta los avisos y webhooks pendientes. Con
`--una-vez` hace una sola pasada, para programarlo con cron. Puede haber varias
copias a la vez: cada aviso y cada entrega de webhook se reclama antes de
enviarse.

### Base de datos en producción

```bash
alembic upgrade head        # aplica las migraciones pendientes
```

En producción el servicio no crea tablas al arrancar; el esquema lo gestiona
Alembic. Una base creada antes con `create_all` se marca con
`alembic stamp 0001`.

### Verificar un webhook que recibes

```python
import hmac, hashlib
esperada = "sha256=" + hmac.new(
    secreto.encode(), f"{cabecera_timestamp}.{cuerpo_crudo}".encode(), hashlib.sha256
).hexdigest()
assert hmac.compare_digest(esperada, cabecera_signature)
```

Rechaza marcas de tiempo viejas y usa `compare_digest`, no `==`.

---

## Decisiones y por qué

**Monolito modular.** Como pide el documento. Un solo proceso con módulos
separados: `dominio/` no sabe nada de HTTP, `api/` y `portal/` no saben nada de
SQL. Partirlo en servicios se puede después; al revés es mucho más caro.

**Aislamiento por empresa.** Toda tabla lleva `tenant_id` y toda consulta filtra
por él. Un contrato de otra empresa responde 404, no 403: no confirmamos ni que
exista.

**Lista blanca de variables.** Lo que no está declarado en el schema de la
plantilla se rechaza, con el detalle de todos los problemas de una vez. Se aplica
dos veces: en Pydantic (`extra="forbid"`) y en el dominio.

**Plantillas sin lógica.** La única sintaxis es `{{ variable }}`. No hay bucles ni
expresiones, así que no hay nada que inyectar. Las etiquetas HTML pasan por una
lista blanca y se rechaza lo que no esté en ella, en vez de intentar limpiarlo.

**Generación determinista.** El mismo contrato produce siempre los mismos bytes.
Sin eso, el hash no serviría como evidencia.

**Auditoría encadenada.** Cada evento incluye el hash del anterior. Alterar uno
intermedio rompe la cadena, y `/auditoria` lo detecta. En producción el usuario
de la aplicación no debería tener UPDATE ni DELETE sobre esa tabla.

**Proveedor de firma intercambiable.** Hoy firma con Ed25519 desde el propio
servicio. Cambiar a un proveedor acreditado es implementar tres métodos en
`app/dominio/firma.py`; nada más del sistema se entera.

**Defensa anti-SSRF en webhooks.** La URL la elige el tenant, así que se valida al
registrarla y otra vez antes de cada entrega: HTTPS obligatorio, sin credenciales
en la URL, y se rechazan loopback, redes privadas, link-local (incluido
`169.254.169.254`) y reservadas. No se siguen redirecciones. La entrega se
conecta a la IP que pasó la validación y no vuelve a consultar el DNS, así que un
dominio que cambia de IP entre la validación y la conexión (DNS rebinding) no
desvía la petición; el nombre original viaja en `Host` y en el SNI de TLS.

**Webhooks al menos una vez.** La API entrega después de responder, y el proceso
de tareas reintenta con espera creciente. Cada entrega se reclama con un
`UPDATE` condicional, así que varios procesos no mandan la misma; si uno muere a
mitad, otro la retoma. El receptor debe ignorar un `X-Event-Id` repetido. Tras
15 fallos seguidos el endpoint se suspende.

**Avisos con outbox.** El aviso con el enlace de firma se guarda en la misma
transacción que la invitación: existe si y solo si ella existe. Sale después de
responder y, si el proveedor falla, se reintenta hasta cinco veces; si se pierde,
queda en la auditoría del contrato. El texto lleva el token de firma, así que se
guarda cifrado y se borra en cuanto sale. Los códigos OTP no pasan por la cola:
el firmante está esperando, y un código que llega tarde ya venció.

**El PDF es una representación.** El documento de referencia es el HTML
congelado, sobre el que se calculan los hashes y se firma. El PDF se genera al
completar, de forma determinista, y deja su propio hash en el contrato, en la
auditoría y en el webhook. Si fallara, el contrato se completa igual.

**Segundo factor obligatorio en el portal.** Un mismo mensaje para todo fallo de
acceso y un hash señuelo cuando el correo no existe, para no revelar qué cuentas
hay. Cinco claves malas bloquean la cuenta quince minutos; un código TOTP ya
usado no sirve otra vez. Sesión de 30 minutos sin uso y 8 horas como máximo,
cookie `HttpOnly` y `SameSite=Strict`, CSRF en todos los formularios y una CSP
que no admite ningún script.

**Vencimiento doble.** La tarea periódica vence los contratos, y el portal
también lo hace en el momento en que alguien abre un enlace caducado. Así el
vencimiento no depende de cada cuánto corra la tarea.

**Secretos.** El secreto de la credencial solo existe hasheado con scrypt. Los
tokens de invitación solo existen hasheados. El secreto de webhook se guarda
cifrado con AES-GCM. Los códigos OTP se guardan hasheados y se comparan en tiempo
constante. La clave de los administradores también va con scrypt, y su secreto
TOTP, cifrado.

---

## Lo que falta

Esto es la base funcional, no un sistema listo para producción.

- **Roles en el portal.** Todo administrador puede hacer todo dentro de su
  empresa. Separar quién publica plantillas de quién gestiona credenciales es el
  siguiente paso.
- **Recuperar el segundo factor.** Si alguien pierde el teléfono, hoy hay que
  borrar su secreto TOTP a mano para que lo registre de nuevo. Faltan códigos de
  recuperación.
- **Alfabetos en el PDF.** Usa las fuentes estándar de PDF, que cubren el español
  pero no otros alfabetos (chino, árabe...). Para eso hay que incrustar una
  fuente TrueType.
- **Probar sobre PostgreSQL.** El código y las migraciones están pensados para
  PostgreSQL, pero las pruebas corren sobre SQLite.
- **Proveedor de firma acreditado.** `ProveedorExterno` sigue siendo un
  esqueleto.
- **Validación legal.** Hay que revisar con un abogado qué contratos requieren una
  entidad de certificación autorizada bajo la Ley 126-02, y qué obliga la Ley
  172-13 sobre los datos personales que aquí se recopilan.

## Mapa del código

```
app/
  config.py          configuración por entorno
  db.py              motor, sesión y fechas siempre en UTC
  models.py          las 18 tablas, todas con tenant_id
  seguridad.py       hashes, HMAC, JSON canónico, cifrado, tokens, OTP
  almacenamiento.py  documentos fuera de la base, con claves impredecibles
  schemas.py         entrada y salida de la API (extra="forbid")
  dependencias.py    autenticación B2B, permisos, IP observada, límites (memoria o Redis)
  notificaciones.py  correo (SMTP) y SMS (Twilio) detrás de un mismo puerto
  tareas.py          ciclo de vencimientos y reintentos de avisos y webhooks
  dominio/
    variables.py     lista blanca y validación (cédula, RNC, dinero, fechas)
    plantillas.py    motor sin lógica + lista blanca de HTML
    documentos.py    generación, hashes y constancia de firma
    estados.py       máquina de estados del contrato
    politica.py      política de firma congelada en el contrato
    auditoria.py     eventos append-only encadenados
    firma.py         puerto de firma + implementación Ed25519
    webhooks.py      entrega firmada con guardia anti-SSRF e IP fijada, cola y gestión
    avisos.py        outbox de avisos a firmantes, cifrado y con reintentos
    pdf.py           HTML de la lista blanca a PDF determinista
    administradores.py  acceso al portal: clave, TOTP, bloqueos y sesiones
    credenciales.py  alta y revocación de credenciales B2B
    contratos.py     el flujo completo, vencimiento, rechazo y listado
  api/v1_contratos.py   API B2B
  portal/firma.py       portal de firma alojado
  admin/rutas.py        portal administrativo
  main.py               montaje, cabeceras de seguridad y errores
migraciones/            Alembic: env.py y versiones del esquema
scripts/                sembrar, demo_flujo, tareas y crear_admin
```
