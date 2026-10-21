"""Vencimiento automatico de contratos que nadie firmo a tiempo."""
from __future__ import annotations

from datetime import timedelta

from app.db import FabricaSesion, ahora_utc
from app.dominio import webhooks
from app.dominio.contratos import vencer_pendientes
from app.models import Contrato
from tests.ayudas import crear_contrato, crear_plantilla, firmar_como, token_de


def _caducar(contrato_id: str) -> None:
    """Mueve la vigencia al pasado, como si hubieran pasado los dias."""
    with FabricaSesion() as sesion:
        contrato = sesion.get(Contrato, contrato_id)
        contrato.expira_en = ahora_utc() - timedelta(minutes=1)
        sesion.commit()


def _vencer() -> int:
    with FabricaSesion() as sesion:
        cuantos = vencer_pendientes(sesion)
        sesion.commit()
    return cuantos


def test_la_tarea_marca_vencidos_los_contratos_caducados(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    _caducar(contrato["contract_id"])

    assert _vencer() >= 1

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "VENCIDO"

    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    assert auditoria["events"][-1]["type"] == "VENCIDO"
    assert auditoria["chain"]["integra"] is True


def test_un_contrato_vigente_no_vence(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    _vencer()
    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "PENDIENTE_CLIENTE"


def test_el_enlace_vence_aunque_la_tarea_no_haya_pasado(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    _caducar(contrato["contract_id"])

    pagina = cliente.get(f"/firma/{token_de(contrato['signing_url'])}")
    assert pagina.status_code == 400
    assert "vencio" in pagina.json()["mensaje"]

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "VENCIDO"


def test_no_se_reenvia_un_contrato_vencido(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    _caducar(contrato["contract_id"])
    reenvio = cliente.post(f"/v1/contratos/{contrato['contract_id']}/reenviar", auth=empresa)
    assert reenvio.status_code == 409


def test_si_el_cliente_ya_firmo_no_vence(cliente, empresa, otp_fijo):
    crear_plantilla(
        cliente, empresa, politica={"requiere_otp": True, "requiere_firma_empresa": True}
    )
    contrato = crear_contrato(
        cliente, empresa,
        firmantes=[
            {"rol": "CLIENTE", "nombre": "Juan Perez", "email": "juan@example.com"},
            {"rol": "EMPRESA", "nombre": "Ana Gomez", "email": "ana@acme.com"},
        ],
    ).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)
    _caducar(contrato["contract_id"])
    _vencer()

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "PENDIENTE_EMPRESA"


def test_el_vencimiento_avisa_por_webhook(cliente, empresa):
    from tests.receptor import receptor_webhook

    with receptor_webhook() as receptor:
        cliente.post(
            "/v1/webhooks", auth=empresa,
            json={"url": receptor.url, "eventos": ["contract.expired"]},
        )
        crear_plantilla(cliente, empresa)
        contrato = crear_contrato(cliente, empresa).json()
        _caducar(contrato["contract_id"])
        _vencer()
        webhooks.procesar_pendientes()
        receptor.esperar(1)

    vencidos = [e for e in receptor.entregas if e["cuerpo"]["event"] == "contract.expired"]
    assert [e["cuerpo"]["contract_id"] for e in vencidos] == [contrato["contract_id"]]
