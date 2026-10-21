"""El proceso de tareas periodicas, que corre aparte de la API."""
from __future__ import annotations

import threading
from datetime import timedelta

from app import tareas
from app.db import FabricaSesion, ahora_utc
from app.models import Contrato
from tests.ayudas import crear_contrato, crear_plantilla


def test_un_ciclo_vence_contratos_y_devuelve_el_resumen(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    with FabricaSesion() as sesion:
        sesion.get(Contrato, contrato["contract_id"]).expira_en = ahora_utc() - timedelta(hours=1)
        sesion.commit()

    resultado = tareas.ejecutar_ciclo()
    assert resultado["contratos_vencidos"] >= 1
    assert "webhooks_entregados" in resultado

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "VENCIDO"


def test_un_ciclo_que_falla_no_detiene_el_proceso(monkeypatch):
    llamadas = []
    detener = threading.Event()

    def ciclo_que_falla():
        llamadas.append(1)
        if len(llamadas) >= 2:
            detener.set()
        raise RuntimeError("base caida")

    monkeypatch.setattr(tareas, "ejecutar_ciclo", ciclo_que_falla)
    tareas.ejecutar_siempre(0, detener)
    assert len(llamadas) == 2
