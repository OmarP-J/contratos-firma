# Servicio B2B de contratos y firma electrónica

Implementación en Python del documento de propuesta conceptual. Genera contratos
desde plantillas versionadas, los envía a firma, recopila evidencias, custodia el
documento final y notifica por webhook.

**Stack:** Python · FastAPI · SQLAlchemy 2 · SQLite (o PostgreSQL) · Jinja2 ·
cryptography. Sin dependencias de sistema: arranca con `pip install`.

---

## Arrancar en tres minutos

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print('CLAVE_APP=' + secrets.token_hex(32))"   # pega el valor en .env

python -m scripts.sembrar          # crea empresa, credencial y plantilla de ejemplo
python -m uvicorn app.main:app --reload
```

No hace falta instalar PostgreSQL: si `URL_BASE_DATOS` está vacía se usa SQLite en
`contratos.db`. Para pasar a PostgreSQL basta poner la URL; el modelo y las
consultas son los mismos.

La documentación interactiva de la API queda en <http://localhost:8000/docs>.

### Ver el flujo completo

```bash
python -m scripts.demo_flujo <client_id> <client_secret>
```

Crea un contrato, te deja firmar como cliente y como empresa, y guarda el
documento final en `contrato-final.html`. El código OTP aparece en la consola
del servidor (solo en desarrollo, con `MOSTRAR_SECRETOS_EN_LOG=true`).

### Pruebas

```bash
python -m pytest -v
```

31 pruebas que recorren los criterios de aceptación de la sección 14 del
documento: aislamiento entre empresas, rechazo de variables no declaradas,
escapado de XSS, idempotencia, firma HMAC de webhooks, bloqueo de destinos
SSRF, integridad de la cadena de auditoría y detección de documentos alterados.

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
| GET | `/v1/contratos/{id}` | Estado y firmantes |
| POST | `/v1/contratos/{id}/reenviar` | Nueva invitación para la parte pendiente |
| POST | `/v1/contratos/{id}/anular` | Anular (falla si ya está completado) |
| GET | `/v1/contratos/{id}/documento` | Documento presentado o final |
| GET | `/v1/contratos/{id}/auditoria` | Eventos y verificación de la cadena |
| POST | `/v1/webhooks` | Registrar endpoint (devuelve el secreto una sola vez) |
| GET | `/.well-known/clave-de-firma` | Clave pública para verificar firmas |

Autenticación HTTP Basic con `client_id` y `client_secret`. Cada endpoint exige
un permiso concreto de la credencial.

### Portal de firma

`/firma/{token}` → identificación con OTP → lectura del documento →
consentimiento expreso → firma. Todo en el dominio del servicio, para controlar
cookies, cabeceras y aislamiento sin que el integrador implemente nada.

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
`169.254.169.254`) y reservadas. No se siguen redirecciones.

**Secretos.** El secreto de la credencial solo existe hasheado con scrypt. Los
tokens de invitación solo existen hasheados. El secreto de webhook se guarda
cifrado con AES-GCM. Los códigos OTP se guardan hasheados y se comparan en tiempo
constante.

---

## Lo que falta

Esto es la base funcional, no un sistema listo para producción.

- **Portal administrativo.** Hoy la gestión de plantillas y credenciales va por
  API. Falta la interfaz web con login, MFA y bandeja de pendientes.
- **PDF.** El documento se genera en HTML. Añadir WeasyPrint o un servicio de
  conversión es un adaptador nuevo detrás de `documentos.generar`.
- **Correo y SMS reales.** El OTP y las invitaciones se imprimen en consola.
  Falta conectar un proveedor transaccional.
- **Migraciones.** Hoy las tablas se crean con `create_all`. Para producción hace
  falta Alembic.
- **Cola de webhooks.** Los reintentos se procesan en el mismo proceso. Con
  volumen real hace falta una tarea periódica o una cola.
- **Límites de peticiones distribuidos.** El limitador es en memoria; con varias
  instancias hay que moverlo a Redis.
- **Vencimiento automático.** `expira_en` se guarda pero falta el proceso que
  marca los contratos vencidos.
- **Validación legal.** Hay que revisar con un abogado qué contratos requieren una
  entidad de certificación autorizada bajo la Ley 126-02, y qué obliga la Ley
  172-13 sobre los datos personales que aquí se recopilan.

## Mapa del código

```
app/
  config.py          configuración por entorno
  db.py              motor, sesión y fechas siempre en UTC
  models.py          las 15 tablas, todas con tenant_id
  seguridad.py       hashes, HMAC, JSON canónico, cifrado, tokens, OTP
  almacenamiento.py  documentos fuera de la base, con claves impredecibles
  schemas.py         entrada y salida de la API (extra="forbid")
  dependencias.py    autenticación B2B, permisos, IP observada, límites
  dominio/
    variables.py     lista blanca y validación (cédula, RNC, dinero, fechas)
    plantillas.py    motor sin lógica + lista blanca de HTML
    documentos.py    generación, hashes y constancia de firma
    estados.py       máquina de estados del contrato
    politica.py      política de firma congelada en el contrato
    auditoria.py     eventos append-only encadenados
    firma.py         puerto de firma + implementación Ed25519
    webhooks.py      entrega firmada con guardia anti-SSRF
    contratos.py     el flujo completo
  api/v1_contratos.py   API B2B
  portal/firma.py       portal de firma alojado
  main.py               montaje, cabeceras de seguridad y errores
```
