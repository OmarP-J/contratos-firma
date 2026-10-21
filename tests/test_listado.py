"""Listado de contratos con filtros y paginacion por cursor."""
from __future__ import annotations

from tests.ayudas import crear_contrato, crear_plantilla


def _listar(cliente, auth, **parametros):
    respuesta = cliente.get("/v1/contratos", auth=auth, params=parametros)
    assert respuesta.status_code == 200, respuesta.text
    return respuesta.json()


def test_solo_lista_los_contratos_de_la_propia_empresa(cliente, empresa, otra_empresa):
    crear_plantilla(cliente, empresa)
    propio = crear_contrato(cliente, empresa).json()

    assert [c["contract_id"] for c in _listar(cliente, empresa)["data"]] == [propio["contract_id"]]
    assert _listar(cliente, otra_empresa)["data"] == []


def test_filtra_por_estado_y_referencia(cliente, empresa):
    crear_plantilla(cliente, empresa)
    vigente = crear_contrato(cliente, empresa, referencia_externa="SOL-1").json()
    anulado = crear_contrato(cliente, empresa, referencia_externa="SOL-2").json()
    cliente.post(f"/v1/contratos/{anulado['contract_id']}/anular", auth=empresa, json={})

    por_estado = _listar(cliente, empresa, estado="ANULADO")["data"]
    assert [c["contract_id"] for c in por_estado] == [anulado["contract_id"]]

    por_referencia = _listar(cliente, empresa, referencia_externa="SOL-1")["data"]
    assert [c["contract_id"] for c in por_referencia] == [vigente["contract_id"]]


def test_recorre_todas_las_paginas_sin_repetir_ni_saltar(cliente, empresa):
    crear_plantilla(cliente, empresa)
    creados = [crear_contrato(cliente, empresa).json()["contract_id"] for _ in range(5)]

    vistos, paginas, cursor = [], 0, None
    while True:
        parametros = {"limite": 2}
        if cursor:
            parametros["cursor"] = cursor
        respuesta = _listar(cliente, empresa, **parametros)
        vistos += [c["contract_id"] for c in respuesta["data"]]
        paginas += 1
        cursor = respuesta["next_cursor"]
        if cursor is None:
            break

    assert paginas == 3
    assert vistos == list(reversed(creados))  # del mas nuevo al mas viejo


def test_filtra_por_fecha_de_creacion(cliente, empresa):
    crear_plantilla(cliente, empresa)
    crear_contrato(cliente, empresa)
    assert _listar(cliente, empresa, creado_desde="2999-01-01T00:00:00Z")["data"] == []
    assert len(_listar(cliente, empresa, creado_hasta="2999-01-01T00:00:00Z")["data"]) == 1


def test_el_listado_no_trae_datos_de_los_firmantes(cliente, empresa):
    crear_plantilla(cliente, empresa)
    crear_contrato(cliente, empresa)
    [resumen] = _listar(cliente, empresa)["data"]
    assert "signers" not in resumen
    assert resumen["status"] == "PENDIENTE_CLIENTE"


def test_parametros_invalidos_responden_400(cliente, empresa):
    casos = [
        {"estado": "INVENTADO"},
        {"cursor": "no-es-un-cursor"},
        {"creado_desde": "2026-10-01T00:00:00"},  # sin zona horaria
    ]
    for parametros in casos:
        respuesta = cliente.get("/v1/contratos", auth=empresa, params=parametros)
        assert respuesta.status_code == 400, parametros


def test_el_limite_tiene_tope(cliente, empresa):
    assert cliente.get("/v1/contratos", auth=empresa, params={"limite": 1000}).status_code == 422
