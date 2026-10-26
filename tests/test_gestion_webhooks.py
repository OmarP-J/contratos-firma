"""Gestion de webhooks por el integrador: listado, historial, suspension y reintentos."""
from __future__ import annotations

import socket

import pytest

from app.config import ajustes
from app.dominio import webhooks
from tests.ayudas import crear_contrato, crear_plantilla
from tests.receptor import receptor_webhook


@pytest.fixture
def sin_entrega_en_linea(monkeypatch):
    monkeypatch.setattr(ajustes(), "entregar_webhooks_en_linea", False)


def _url_caida() -> str:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{s.getsockname()[1]}/hook"


def _registrar(cliente, empresa, url: str) -> str:
    respuesta = cliente.post(
        "/v1/webhooks", auth=empresa, json={"url": url, "eventos": ["contract.sent"]}
    )
    assert respuesta.status_code == 201
    return respuesta.json()["endpoint_id"]


def test_el_listado_no_muestra_el_secreto(cliente, empresa):
    endpoint_id = _registrar(cliente, empresa, "http://127.0.0.1:9/hook")
    listado = cliente.get("/v1/webhooks", auth=empresa)
    assert listado.status_code == 200
    [endpoint] = [e for e in listado.json()["data"] if e["endpoint_id"] == endpoint_id]
    assert endpoint["status"] == "ACTIVO"
    assert "secret" not in endpoint
    assert "whsec_" not in listado.text


def test_el_historial_muestra_los_fallos(cliente, empresa, sin_entrega_en_linea):
    endpoint_id = _registrar(cliente, empresa, _url_caida())
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    webhooks.procesar_pendientes()

    historial = cliente.get(f"/v1/webhooks/{endpoint_id}/entregas", auth=empresa).json()
    [entrega] = historial["data"]
    assert entrega["contract_id"] == contrato["contract_id"]
    assert entrega["event"] == "contract.sent"
    assert entrega["attempts"] == 1
    assert entrega["status"] == "PENDIENTE"
    assert entrega["last_error"]


def test_tras_muchos_fallos_se_suspende_y_se_puede_reactivar(
    cliente, empresa, sin_entrega_en_linea, monkeypatch
):
    monkeypatch.setattr(webhooks, "FALLOS_PARA_SUSPENDER", 1)
    endpoint_id = _registrar(cliente, empresa, _url_caida())
    crear_plantilla(cliente, empresa)
    crear_contrato(cliente, empresa)
    webhooks.procesar_pendientes()

    historial = cliente.get(f"/v1/webhooks/{endpoint_id}/entregas", auth=empresa).json()
    assert historial["endpoint"]["status"] == "SUSPENDIDO"

    reactivado = cliente.post(f"/v1/webhooks/{endpoint_id}/reactivar", auth=empresa).json()
    assert reactivado["status"] == "ACTIVO"
    assert reactivado["consecutive_failures"] == 0


def test_reintentar_vuelve_a_mandar_el_mismo_evento(cliente, empresa):
    with receptor_webhook() as receptor:
        endpoint_id = _registrar(cliente, empresa, receptor.url)
        crear_plantilla(cliente, empresa)
        crear_contrato(cliente, empresa)
        receptor.esperar(1)

        [entrega] = cliente.get(
            f"/v1/webhooks/{endpoint_id}/entregas", auth=empresa
        ).json()["data"]
        assert entrega["status"] == "ENTREGADA"

        respuesta = cliente.post(
            f"/v1/webhooks/entregas/{entrega['delivery_id']}/reintentar", auth=empresa
        )
        assert respuesta.status_code == 202
        receptor.esperar(2)

    assert len(receptor.entregas) == 2
    # Mismo X-Event-Id: el receptor puede reconocer que es el mismo evento.
    assert receptor.entregas[0]["evento_id"] == receptor.entregas[1]["evento_id"]


def test_no_se_reintenta_hacia_un_endpoint_suspendido(
    cliente, empresa, sin_entrega_en_linea, monkeypatch
):
    monkeypatch.setattr(webhooks, "FALLOS_PARA_SUSPENDER", 1)
    endpoint_id = _registrar(cliente, empresa, _url_caida())
    crear_plantilla(cliente, empresa)
    crear_contrato(cliente, empresa)
    webhooks.procesar_pendientes()

    [entrega] = cliente.get(f"/v1/webhooks/{endpoint_id}/entregas", auth=empresa).json()["data"]
    respuesta = cliente.post(
        f"/v1/webhooks/entregas/{entrega['delivery_id']}/reintentar", auth=empresa
    )
    assert respuesta.status_code == 409


def test_otra_empresa_no_ve_ni_toca_los_webhooks_ajenos(
    cliente, empresa, otra_empresa, sin_entrega_en_linea
):
    endpoint_id = _registrar(cliente, empresa, "http://127.0.0.1:9/hook")
    crear_plantilla(cliente, empresa)
    crear_contrato(cliente, empresa)
    [entrega] = cliente.get(f"/v1/webhooks/{endpoint_id}/entregas", auth=empresa).json()["data"]

    assert endpoint_id not in cliente.get("/v1/webhooks", auth=otra_empresa).text
    for metodo, ruta in [
        ("get", f"/v1/webhooks/{endpoint_id}/entregas"),
        ("post", f"/v1/webhooks/{endpoint_id}/reactivar"),
        ("post", f"/v1/webhooks/entregas/{entrega['delivery_id']}/reintentar"),
    ]:
        assert getattr(cliente, metodo)(ruta, auth=otra_empresa).status_code == 404, ruta
