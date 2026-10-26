"""Portal administrativo: acceso con segundo factor, bandeja, acciones y gestion."""
from __future__ import annotations

import base64
import time
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import FabricaSesion, ahora_utc
from app.dominio import administradores
from app.models import CredencialApi, EventoAuditoria, SesionAdmin, UsuarioAdmin
from app.seguridad import codigo_totp, descifrar, token_aleatorio, verificar_totp
from tests.ayudas import crear_contrato, crear_plantilla, csrf_de, firmar_como, token_de

CLAVE = "una-clave-larga-de-prueba"


def _tenant_de(auth) -> str:
    with FabricaSesion() as sesion:
        return sesion.scalars(
            select(CredencialApi.tenant_id).where(CredencialApi.client_id == auth[0])
        ).one()


@pytest.fixture
def admin(empresa):
    tenant_id = _tenant_de(empresa)
    email = f"admin-{token_aleatorio(4).lower()}@acme.test"
    with FabricaSesion() as sesion:
        usuario = administradores.crear_usuario(
            sesion, tenant_id=tenant_id, email=email, nombre="Ana Admin", clave=CLAVE
        )
        sesion.commit()
        return {"email": email, "clave": CLAVE, "id": usuario.id, "tenant_id": tenant_id}


def _secreto(usuario_id: str) -> str:
    with FabricaSesion() as sesion:
        return descifrar(sesion.get(UsuarioAdmin, usuario_id).totp_secreto_cifrado)


def _codigo(usuario_id: str, desfase: int = 0) -> str:
    return codigo_totp(_secreto(usuario_id), int(time.time() // 30) + desfase)


def _clave(cliente, admin, clave=None):
    return cliente.post(
        "/admin/entrar", data={"email": admin["email"], "clave": clave or admin["clave"]},
        follow_redirects=True,
    )


def entrar(cliente, admin, desfase: int = 0):
    """Clave y segundo factor. Devuelve la pagina a la que se llega."""
    pagina = _clave(cliente, admin)
    assert pagina.status_code == 200, pagina.text
    return cliente.post(
        "/admin/mfa", data={"csrf": csrf_de(pagina.text), "codigo": _codigo(admin["id"], desfase)},
        follow_redirects=True,
    )


# --- TOTP -------------------------------------------------------------------

def test_totp_coincide_con_los_vectores_del_rfc_6238():
    secreto = base64.b32encode(b"12345678901234567890").decode()
    for instante, esperado in [(59, "287082"), (1111111109, "081804"), (1234567890, "005924")]:
        assert codigo_totp(secreto, instante // 30) == esperado


def test_un_codigo_usado_no_sirve_otra_vez():
    secreto = base64.b32encode(b"12345678901234567890").decode()
    paso = verificar_totp(secreto, "287082", instante=59, ultimo_paso=None)
    assert paso == 1
    assert verificar_totp(secreto, "287082", instante=59, ultimo_paso=paso) is None
    assert verificar_totp(secreto, "abc", instante=59, ultimo_paso=None) is None


# --- Acceso -----------------------------------------------------------------

def test_sin_sesion_se_va_a_entrar(cliente):
    respuesta = cliente.get("/admin/contratos", follow_redirects=False)
    assert respuesta.status_code == 303
    assert respuesta.headers["location"] == "/admin/entrar"


def test_el_mismo_mensaje_para_clave_mala_y_correo_inexistente(cliente, admin):
    mala = _clave(cliente, admin, clave="otra-clave-cualquiera")
    inexistente = cliente.post(
        "/admin/entrar", data={"email": "nadie@acme.test", "clave": CLAVE}
    )
    assert mala.status_code == inexistente.status_code == 401
    assert administradores.MENSAJE_ACCESO in mala.text
    assert administradores.MENSAJE_ACCESO in inexistente.text


def test_cinco_claves_malas_bloquean_la_cuenta(cliente, admin):
    for _ in range(administradores.MAX_FALLOS_CLAVE):
        _clave(cliente, admin, clave="equivocada-una-y-otra-vez")
    assert _clave(cliente, admin).status_code == 401  # ni con la clave buena


def test_la_cookie_es_httponly_samesite_y_solo_para_admin(cliente, admin):
    respuesta = cliente.post(
        "/admin/entrar", data={"email": admin["email"], "clave": CLAVE}, follow_redirects=False
    )
    cookie = respuesta.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/admin" in cookie


def test_la_primera_vez_hay_que_registrar_el_segundo_factor(cliente, admin):
    pagina = _clave(cliente, admin)
    assert "Registra tu app autenticadora" in pagina.text
    assert "<svg" in pagina.text  # el codigo QR
    # Sin el segundo factor no se ve nada mas.
    respuesta = cliente.get("/admin/contratos", follow_redirects=False)
    assert respuesta.headers["location"] == "/admin/mfa"

    llegada = cliente.post(
        "/admin/mfa", data={"csrf": csrf_de(pagina.text), "codigo": _codigo(admin["id"])},
        follow_redirects=True,
    )
    assert llegada.url.path == "/admin/contratos"
    with FabricaSesion() as sesion:
        assert sesion.get(UsuarioAdmin, admin["id"]).mfa_activo is True


def test_un_codigo_ya_usado_no_sirve_para_entrar_de_nuevo(cliente, admin):
    entrar(cliente, admin)
    pagina = cliente.get("/admin/contratos")
    cliente.post("/admin/salir", data={"csrf": csrf_de(pagina.text)})

    pagina = _clave(cliente, admin)
    assert "Codigo de verificacion" in pagina.text
    repetido = cliente.post(
        "/admin/mfa", data={"csrf": csrf_de(pagina.text), "codigo": _codigo(admin["id"])}
    )
    assert repetido.status_code == 400


def test_cinco_codigos_malos_cierran_la_sesion(cliente, admin):
    pagina = _clave(cliente, admin)
    csrf = csrf_de(pagina.text)
    for _ in range(administradores.MAX_FALLOS_MFA):
        respuesta = cliente.post("/admin/mfa", data={"csrf": csrf, "codigo": "000000"})
    assert respuesta.status_code == 401
    assert cliente.get("/admin/mfa", follow_redirects=False).headers["location"] == "/admin/entrar"


def test_la_sesion_vence_por_inactividad(cliente, admin):
    entrar(cliente, admin)
    with FabricaSesion() as sesion:
        for s in sesion.scalars(select(SesionAdmin).where(SesionAdmin.usuario_id == admin["id"])):
            s.ultimo_uso_en = ahora_utc() - administradores.INACTIVIDAD - timedelta(seconds=1)
        sesion.commit()
    assert cliente.get("/admin/contratos", follow_redirects=False).headers["location"] == "/admin/entrar"


def test_salir_invalida_la_cookie(cliente, admin):
    pagina = entrar(cliente, admin)
    cookie = cliente.cookies.get("admin_sesion")
    cliente.post("/admin/salir", data={"csrf": csrf_de(pagina.text)})
    cliente.cookies.set("admin_sesion", cookie, path="/admin")
    assert cliente.get("/admin/contratos", follow_redirects=False).status_code == 303


def test_cabeceras_de_seguridad_del_portal(cliente):
    respuesta = cliente.get("/admin/entrar")
    assert "default-src 'none'" in respuesta.headers["content-security-policy"]
    assert respuesta.headers["cache-control"] == "no-store"


# --- Contratos --------------------------------------------------------------

def test_la_bandeja_muestra_solo_los_contratos_de_la_empresa(cliente, empresa, otra_empresa, admin):
    crear_plantilla(cliente, empresa)
    propio = crear_contrato(cliente, empresa, referencia_externa="PROPIO-1").json()
    crear_plantilla(cliente, otra_empresa)
    ajeno = crear_contrato(cliente, otra_empresa, referencia_externa="AJENO-1").json()

    bandeja = entrar(cliente, admin)
    assert "PROPIO-1" in bandeja.text
    assert "AJENO-1" not in bandeja.text

    detalle = cliente.get(f"/admin/contratos/{propio['contract_id']}")
    assert detalle.status_code == 200
    assert "Cadena integra" in detalle.text
    assert cliente.get(f"/admin/contratos/{ajeno['contract_id']}").status_code == 404


def test_anular_desde_el_portal_exige_csrf_y_queda_en_la_auditoria(cliente, empresa, admin):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    entrar(cliente, admin)
    ruta = f"/admin/contratos/{contrato['contract_id']}"

    sin_csrf = cliente.post(f"{ruta}/anular", data={"motivo": "x"})
    assert sin_csrf.status_code == 400

    detalle = cliente.get(ruta)
    anulado = cliente.post(
        f"{ruta}/anular", data={"csrf": csrf_de(detalle.text), "motivo": "Pedido cancelado"},
        follow_redirects=True,
    )
    assert "quedo anulado" in anulado.text

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "ANULADO"
    with FabricaSesion() as sesion:
        evento = sesion.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.contrato_id == contrato["contract_id"],
                EventoAuditoria.tipo == "ANULADO",
            )
        ).one()
        assert (evento.actor_tipo, evento.actor_id) == ("ADMIN", admin["id"])


def test_reenviar_da_un_enlace_nuevo_que_funciona(cliente, empresa, admin):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    entrar(cliente, admin)
    ruta = f"/admin/contratos/{contrato['contract_id']}"

    respuesta = cliente.post(f"{ruta}/reenviar", data={"csrf": csrf_de(cliente.get(ruta).text)})
    assert respuesta.status_code == 200
    enlace = respuesta.text.split('id="enlace-nuevo">')[1].split("<")[0]
    assert cliente.get(f"/firma/{token_de(enlace)}", follow_redirects=True).status_code == 200
    # El enlace original quedo revocado.
    assert cliente.get(f"/firma/{token_de(contrato['signing_url'])}").status_code == 400


def test_documento_y_pdf_desde_el_portal(cliente, empresa, admin, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)
    entrar(cliente, admin)

    html = cliente.get(f"/admin/contratos/{contrato['contract_id']}/documento")
    assert "Constancia de firma electronica" in html.text
    assert html.headers["content-security-policy"].startswith("sandbox")
    pdf = cliente.get(f"/admin/contratos/{contrato['contract_id']}/documento?formato=pdf")
    assert pdf.content.startswith(b"%PDF")


# --- Plantillas y credenciales ---------------------------------------------

def test_publicar_una_plantilla_desde_el_portal(cliente, empresa, admin):
    pagina = entrar(cliente, admin)
    datos = {
        "csrf": csrf_de(pagina.text), "codigo": "acuerdo_simple", "nombre": "Acuerdo simple",
        "titulo": "Acuerdo", "cuerpo": "<p>Acuerdo con {{ cliente.nombre }}.</p>",
        "schema_variables": '{"cliente.nombre": {"tipo": "texto", "requerido": true}}',
        "politica": "",
    }
    publicada = cliente.post("/admin/plantillas", data=datos, follow_redirects=True)
    assert "quedo publicada" in publicada.text
    assert "acuerdo_simple" in publicada.text

    contrato = crear_contrato(
        cliente, empresa, plantilla="acuerdo_simple", variables={"cliente": {"nombre": "Luis"}}
    )
    assert contrato.status_code == 201, contrato.text


@pytest.mark.parametrize(
    "cambio, esperado",
    [
        ({"schema_variables": "{no es json"}, "no son JSON valido"),
        ({"codigo": "Con Espacios"}, '<span class="mono">codigo</span>'),
        ({"cuerpo": "<p>Hola {{ cliente.nombre }}<script>x</script></p>"},
         "Etiqueta no permitida: &lt;script&gt;"),
    ],
)
def test_plantilla_invalida_muestra_el_error(cliente, admin, cambio, esperado):
    pagina = entrar(cliente, admin)
    datos = {
        "csrf": csrf_de(pagina.text), "codigo": "otra", "nombre": "Otra", "titulo": "Otra",
        "cuerpo": "<p>Hola {{ cliente.nombre }}.</p>",
        "schema_variables": '{"cliente.nombre": {"tipo": "texto", "requerido": true}}',
        "politica": "",
    }
    datos.update(cambio)
    respuesta = cliente.post("/admin/plantillas", data=datos)
    assert respuesta.status_code == 400
    bloque_de_error = respuesta.text.split('<div class="error">')[1].split("</div>")[0]
    assert esperado in bloque_de_error


def test_crear_y_revocar_una_credencial_desde_el_portal(cliente, admin):
    pagina = entrar(cliente, admin)
    creada = cliente.post(
        "/admin/credenciales",
        data={"csrf": csrf_de(pagina.text), "nombre": "CRM", "permisos": ["contratos:leer"]},
    )
    assert creada.status_code == 200
    client_id = creada.text.split('id="client-id">')[1].split("<")[0]
    secreto = creada.text.split('id="client-secret">')[1].split("<")[0]
    assert cliente.get("/v1/contratos", auth=(client_id, secreto)).status_code == 200

    # El listado nunca vuelve a mostrar el secreto.
    listado = cliente.get("/admin/credenciales")
    assert secreto not in listado.text

    with FabricaSesion() as sesion:
        credencial_id = sesion.scalars(
            select(CredencialApi.id).where(CredencialApi.client_id == client_id)
        ).one()
    cliente.post(f"/admin/credenciales/{credencial_id}/revocar", data={"csrf": csrf_de(listado.text)})
    assert cliente.get("/v1/contratos", auth=(client_id, secreto)).status_code == 401


def test_las_acciones_de_empresa_quedan_auditadas(cliente, admin):
    pagina = entrar(cliente, admin)
    cliente.post(
        "/admin/credenciales",
        data={"csrf": csrf_de(pagina.text), "nombre": "ERP", "permisos": ["contratos:leer"]},
    )
    with FabricaSesion() as sesion:
        tipos = sesion.scalars(
            select(EventoAuditoria.tipo).where(
                EventoAuditoria.tenant_id == admin["tenant_id"],
                EventoAuditoria.contrato_id.is_(None),
            )
        ).all()
    assert "ADMIN_MFA_REGISTRADO" in tipos
    assert "CREDENCIAL_CREADA" in tipos
