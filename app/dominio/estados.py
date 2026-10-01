"""
Maquina de estados del contrato.

Se mantiene pequena a proposito: solo los estados que hoy tienen un caso real
detras. Anadir estados intermedios sin necesidad complica para siempre la API
publica y los webhooks.
"""
from __future__ import annotations

from enum import Enum


class Estado(str, Enum):
    CREADO = "CREADO"
    PENDIENTE_CLIENTE = "PENDIENTE_CLIENTE"
    PENDIENTE_EMPRESA = "PENDIENTE_EMPRESA"
    COMPLETADO = "COMPLETADO"
    RECHAZADO = "RECHAZADO"
    VENCIDO = "VENCIDO"
    ANULADO = "ANULADO"


TRANSICIONES: dict[Estado, set[Estado]] = {
    Estado.CREADO: {Estado.PENDIENTE_CLIENTE, Estado.ANULADO, Estado.VENCIDO},
    Estado.PENDIENTE_CLIENTE: {
        Estado.PENDIENTE_EMPRESA, Estado.COMPLETADO, Estado.RECHAZADO,
        Estado.VENCIDO, Estado.ANULADO,
    },
    Estado.PENDIENTE_EMPRESA: {Estado.COMPLETADO, Estado.RECHAZADO, Estado.ANULADO},
    # Estados finales. Un contrato completado no se modifica ni se elimina.
    Estado.COMPLETADO: set(),
    Estado.RECHAZADO: set(),
    Estado.VENCIDO: set(),
    Estado.ANULADO: set(),
}

EVENTO_WEBHOOK = {
    Estado.PENDIENTE_CLIENTE: "contract.sent",
    Estado.COMPLETADO: "contract.completed",
    Estado.RECHAZADO: "contract.declined",
    Estado.VENCIDO: "contract.expired",
    Estado.ANULADO: "contract.voided",
}


class TransicionInvalida(Exception):
    pass


def es_final(estado: Estado) -> bool:
    return not TRANSICIONES[estado]


def puede_transitar(desde: Estado, hacia: Estado) -> bool:
    return hacia in TRANSICIONES[desde]


def exigir_transicion(desde: Estado, hacia: Estado) -> None:
    if not puede_transitar(desde, hacia):
        extra = " El contrato ya esta en un estado final." if es_final(desde) else ""
        raise TransicionInvalida(f"No se puede pasar de {desde.value} a {hacia.value}.{extra}")
