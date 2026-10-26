"""
Tareas periodicas del servicio.

Son el trabajo que no nace de una peticion: vencer contratos que nadie firmo a
tiempo y reintentar avisos y webhooks que fallaron. Corren en un proceso aparte
(python -m scripts.tareas), asi la API no depende de que llegue trafico para
que estas cosas ocurran.
"""
from __future__ import annotations

import logging
import threading

from app.db import FabricaSesion
from app.dominio import avisos, webhooks
from app.dominio.contratos import vencer_pendientes

registro = logging.getLogger("tareas")


def despachar_en_linea() -> None:
    """
    Lo que la API intenta mandar justo despues de responder: los avisos a los
    firmantes y, si la configuracion lo permite, los webhooks. Lo que falle
    aqui lo retoma el proceso de tareas.
    """
    avisos.procesar_pendientes()
    webhooks.entregar_en_linea()


def ejecutar_ciclo() -> dict[str, int]:
    """Una pasada completa. Cada tarea va en su propia transaccion."""
    with FabricaSesion() as sesion:
        vencidos = vencer_pendientes(sesion)
        sesion.commit()

    enviados = avisos.procesar_pendientes()
    entregados = webhooks.procesar_pendientes()
    return {
        "contratos_vencidos": vencidos,
        "avisos_enviados": enviados,
        "webhooks_entregados": entregados,
    }


def ejecutar_siempre(intervalo_s: float, detener: threading.Event | None = None) -> None:
    """
    Repite el ciclo hasta que se pida parar.

    Un fallo en una pasada se registra y no detiene el proceso: la siguiente
    vuelve a intentarlo. Nada de lo que hace un ciclo se pierde si falla a
    medias, porque todo queda pendiente en la base.
    """
    detener = detener or threading.Event()
    while not detener.is_set():
        try:
            resultado = ejecutar_ciclo()
            if any(resultado.values()):
                registro.info("ciclo completado: %s", resultado)
        except Exception:
            registro.exception("fallo un ciclo de tareas periodicas")
        detener.wait(intervalo_s)
