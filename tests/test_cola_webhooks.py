"""Cola de entregas de webhooks: reclamo atomico, reservas y entrega diferida."""
from __future__ import annotations

import socket
import time
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import tareas
from app.config import ajustes
from app.db import FabricaSesion, ahora_utc
from app.dominio import webhooks
from app.models import EntregaWebhook
from tests.ayudas import crear_contrato, crear_plantilla
from tests.receptor import receptor_webhook


@pytest.fixture
def sin_entrega_en_linea(monkeypatch):
    """La API solo encola; entrega el proceso de tareas."""
    monkeypatch.setattr(ajustes(), "entregar_webhooks_en_linea", False)


def _entregas(contrato_id: str) -> list[EntregaWebhook]:
    with FabricaSesion() as sesion:
        return list(
            sesion.scalars(
                select(EntregaWebhook).where(EntregaWebhook.contrato_id == contrato_id)
            )
        )


def _puerto_cerrado() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _contrato_con_webhook(cliente, empresa, url: str) -> str:
    cliente.post("/v1/webhooks", auth=empresa, json={"url": url, "eventos": ["contract.sent"]})
    crear_plantilla(cliente, empresa)
    return crear_contrato(cliente, empresa).json()["contract_id"]


def test_dos_procesos_no_reclaman_la_misma_entrega(cliente, empresa, sin_entrega_en_linea):
    contrato_id = _contrato_con_webhook(cliente, empresa, "http://127.0.0.1:9/hook")
    [entrega] = _entregas(contrato_id)

    assert webhooks.reclamar(entrega.id) is True
    assert webhooks.reclamar(entrega.id) is False
    assert _entregas(contrato_id)[0].estado == "EN_CURSO"


def test_una_reserva_vencida_se_retoma(cliente, empresa, sin_entrega_en_linea):
    contrato_id = _contrato_con_webhook(cliente, empresa, "http://127.0.0.1:9/hook")
    [entrega] = _entregas(contrato_id)
    assert webhooks.reclamar(entrega.id) is True

    # El proceso que la tenia murio y su reserva ya vencio.
    with FabricaSesion() as sesion:
        sesion.get(EntregaWebhook, entrega.id).proximo_intento_en = ahora_utc() - timedelta(seconds=1)
        sesion.commit()
    assert webhooks.reclamar(entrega.id) is True


def test_sin_entrega_en_linea_solo_entrega_el_proceso_de_tareas(
    cliente, empresa, sin_entrega_en_linea
):
    with receptor_webhook() as receptor:
        _contrato_con_webhook(cliente, empresa, receptor.url)
        time.sleep(0.2)
        assert receptor.entregas == []

        tareas.ejecutar_ciclo()
        receptor.esperar(1)

    assert [e["cuerpo"]["event"] for e in receptor.entregas] == ["contract.sent"]


def test_un_receptor_caido_deja_la_entrega_para_despues(cliente, empresa, sin_entrega_en_linea):
    contrato_id = _contrato_con_webhook(
        cliente, empresa, f"http://127.0.0.1:{_puerto_cerrado()}/hook"
    )
    webhooks.procesar_pendientes()

    [entrega] = _entregas(contrato_id)
    assert entrega.estado == "PENDIENTE"
    assert entrega.intentos == 1
    assert entrega.ultimo_error
    assert entrega.proximo_intento_en > ahora_utc() + timedelta(seconds=20)


def test_con_entrega_en_linea_llega_sin_proceso_de_tareas(cliente, empresa):
    with receptor_webhook() as receptor:
        contrato_id = _contrato_con_webhook(cliente, empresa, receptor.url)
        receptor.esperar(1)
    assert len(receptor.entregas) == 1
    assert _entregas(contrato_id)[0].estado == "ENTREGADA"
