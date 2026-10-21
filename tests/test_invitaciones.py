"""El firmante recibe su enlace de firma por correo o SMS."""
from __future__ import annotations

from sqlalchemy import select

from app import notificaciones
from app.db import FabricaSesion
from app.dominio import contratos as servicio
from app.models import CredencialApi
from app.notificaciones import ErrorDeEnvio
from tests.ayudas import VARIABLES, crear_contrato, crear_plantilla, firmar_como, token_de

DOS_FIRMANTES = [
    {"rol": "CLIENTE", "nombre": "Juan Perez", "email": "juan@example.com"},
    {"rol": "EMPRESA", "nombre": "Ana Gomez", "email": "ana@acme.com"},
]


def _invitaciones(buzon) -> list:
    return [m for m in buzon.enviados if m.asunto.startswith("Documento para firmar")]


def test_el_cliente_recibe_el_mismo_enlace_que_devuelve_la_api(cliente, empresa, buzon):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()

    [aviso] = _invitaciones(buzon)
    assert aviso.canal == "EMAIL"
    assert aviso.destino == "juan@example.com"
    assert contrato["signing_url"] in aviso.texto


def test_la_empresa_recibe_su_enlace_cuando_firma_el_cliente(cliente, empresa, buzon, otp_fijo):
    crear_plantilla(
        cliente, empresa, politica={"requiere_otp": True, "requiere_firma_empresa": True}
    )
    contrato = crear_contrato(cliente, empresa, firmantes=DOS_FIRMANTES).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    aviso = _invitaciones(buzon)[-1]
    assert aviso.destino == "ana@acme.com"

    # Con ese enlace la empresa firma sin que el integrador tenga que reenviar nada.
    enlace = next(linea for linea in aviso.texto.splitlines() if "/firma/" in linea)
    firmar_como(cliente, token_de(enlace.strip()), otp_fijo)
    final = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert final["status"] == "COMPLETADO"


def test_la_politica_puede_apagar_los_avisos(cliente, empresa, buzon):
    crear_plantilla(
        cliente, empresa,
        politica={"requiere_otp": True, "requiere_firma_empresa": False,
                  "notificar_invitaciones": False},
    )
    crear_contrato(cliente, empresa)
    assert _invitaciones(buzon) == []


def test_sin_correo_el_aviso_va_por_sms(cliente, empresa, buzon):
    crear_plantilla(cliente, empresa)
    crear_contrato(
        cliente, empresa,
        firmantes=[{"rol": "CLIENTE", "nombre": "Juan Perez", "telefono": "8095551234"}],
    )
    [aviso] = _invitaciones(buzon)
    assert (aviso.canal, aviso.destino) == ("SMS", "8095551234")


def test_si_la_transaccion_se_deshace_no_sale_ningun_aviso(cliente, empresa, buzon):
    crear_plantilla(cliente, empresa)
    with FabricaSesion() as sesion:
        credencial = sesion.scalars(
            select(CredencialApi).where(CredencialApi.client_id == empresa[0])
        ).one()
        servicio.crear_contrato(
            sesion,
            servicio.Contexto(tenant_id=credencial.tenant_id, actor_tipo="CREDENCIAL"),
            plantilla="contrato_servicio",
            firmantes=DOS_FIRMANTES[:1],
            variables=VARIABLES,
        )
        sesion.rollback()
        # Un commit posterior en la misma sesion no debe rescatar el aviso.
        sesion.commit()
    assert _invitaciones(buzon) == []


def test_si_el_aviso_falla_el_contrato_igual_se_crea(cliente, empresa):
    class Caido:
        def enviar(self, mensaje):
            raise ErrorDeEnvio("proveedor caido")

    crear_plantilla(cliente, empresa)
    anterior = notificaciones.instalar(Caido())
    try:
        respuesta = crear_contrato(cliente, empresa)
    finally:
        notificaciones.instalar(anterior)
    assert respuesta.status_code == 201
    assert respuesta.json()["signing_url"]


def test_el_aviso_queda_en_la_auditoria(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    invitacion = next(e for e in auditoria["events"] if e["type"] == "INVITACION_CREADA")
    assert invitacion["data"]["aviso"] == "EMAIL"
