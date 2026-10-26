"""Cola de avisos salientes: cifrado en reposo, reintentos y avisos perdidos."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app import notificaciones, tareas
from app.db import FabricaSesion, ahora_utc
from app.dominio import avisos
from app.models import AvisoSaliente
from app.notificaciones import ErrorDeEnvio
from tests.ayudas import crear_contrato, crear_plantilla


class Caido:
    def enviar(self, mensaje):
        raise ErrorDeEnvio("proveedor caido")


@pytest.fixture
def proveedor_caido():
    anterior = notificaciones.instalar(Caido())
    yield
    notificaciones.instalar(anterior)


def _avisos_de(contrato_id: str) -> list[AvisoSaliente]:
    with FabricaSesion() as sesion:
        return list(
            sesion.scalars(select(AvisoSaliente).where(AvisoSaliente.contrato_id == contrato_id))
        )


def _adelantar_reloj(aviso_id: str) -> None:
    """Como si ya hubiera pasado la espera hasta el siguiente intento."""
    with FabricaSesion() as sesion:
        sesion.get(AvisoSaliente, aviso_id).proximo_intento_en = ahora_utc() - timedelta(seconds=1)
        sesion.commit()


def _contrato(cliente, empresa) -> dict:
    crear_plantilla(cliente, empresa)
    return crear_contrato(cliente, empresa).json()


def test_el_enlace_no_queda_en_claro_en_la_base(cliente, empresa, proveedor_caido):
    contrato = _contrato(cliente, empresa)
    [aviso] = _avisos_de(contrato["contract_id"])

    assert aviso.estado == "PENDIENTE"
    assert "/firma/" not in aviso.contenido_cifrado
    assert contrato["signing_url"].rsplit("/", 1)[-1] not in aviso.contenido_cifrado


def test_un_aviso_que_fallo_se_reintenta_y_luego_se_borra(cliente, empresa, buzon):
    anterior = notificaciones.instalar(Caido())
    try:
        contrato = _contrato(cliente, empresa)
    finally:
        notificaciones.instalar(anterior)

    [aviso] = _avisos_de(contrato["contract_id"])
    assert (aviso.estado, aviso.intentos) == ("PENDIENTE", 1)
    assert aviso.ultimo_error
    assert aviso.proximo_intento_en > ahora_utc()

    _adelantar_reloj(aviso.id)
    resultado = tareas.ejecutar_ciclo()
    assert resultado["avisos_enviados"] >= 1

    [aviso] = _avisos_de(contrato["contract_id"])
    assert aviso.estado == "ENVIADO"
    assert aviso.contenido_cifrado == ""  # ya no hace falta guardarlo
    assert any(contrato["signing_url"] in m.texto for m in buzon.enviados)


def test_tras_agotar_los_intentos_queda_en_la_auditoria(cliente, empresa, proveedor_caido):
    contrato = _contrato(cliente, empresa)
    [aviso] = _avisos_de(contrato["contract_id"])
    for _ in range(avisos.MAX_INTENTOS - 1):
        _adelantar_reloj(aviso.id)
        avisos.procesar_pendientes()

    [aviso] = _avisos_de(contrato["contract_id"])
    assert (aviso.estado, aviso.intentos) == ("FALLIDO", avisos.MAX_INTENTOS)
    assert aviso.contenido_cifrado == ""

    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    perdido = [e for e in auditoria["events"] if e["type"] == "AVISO_NO_ENVIADO"]
    assert len(perdido) == 1
    assert perdido[0]["data"]["destino"] != "juan@example.com"  # enmascarado
    assert auditoria["chain"]["integra"] is True


def test_dos_procesos_no_envian_el_mismo_aviso(cliente, empresa, proveedor_caido):
    contrato = _contrato(cliente, empresa)
    [aviso] = _avisos_de(contrato["contract_id"])
    _adelantar_reloj(aviso.id)

    assert avisos.reclamar(aviso.id) is True
    assert avisos.reclamar(aviso.id) is False


def test_un_aviso_enviado_no_se_vuelve_a_enviar(cliente, empresa, buzon):
    contrato = _contrato(cliente, empresa)
    [aviso] = _avisos_de(contrato["contract_id"])
    assert aviso.estado == "ENVIADO"

    antes = len(buzon.enviados)
    _adelantar_reloj(aviso.id)
    avisos.procesar_pendientes()
    assert len(buzon.enviados) == antes
