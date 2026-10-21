"""
Notificaciones al firmante: codigos de un solo uso e invitaciones.

El resto del servicio solo conoce enviar(Mensaje). Que el mensaje salga por
SMTP, por un proveedor de SMS o a la consola en desarrollo es una decision de
configuracion, igual que con el proveedor de firma o el almacen.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from app.config import ajustes
from app.seguridad import enmascarar

registro = logging.getLogger("notificaciones")


@dataclass(frozen=True)
class Mensaje:
    canal: str  # EMAIL | SMS
    destino: str
    asunto: str
    texto: str


class ErrorDeEnvio(Exception):
    """El proveedor no acepto el mensaje. Se le dice al usuario, no se oculta."""


@runtime_checkable
class Notificador(Protocol):
    def enviar(self, mensaje: Mensaje) -> None: ...


class NotificadorConsola:
    """
    Desarrollo: imprime el mensaje para poder recorrer el flujo sin proveedor.

    Con MOSTRAR_SECRETOS_EN_LOG apagado solo deja constancia de que hubo un
    envio, sin el contenido: un codigo OTP en un log es un codigo filtrado.
    """

    def enviar(self, mensaje: Mensaje) -> None:
        destino = enmascarar(mensaje.destino)
        if not ajustes().mostrar_secretos_en_log:
            registro.info("mensaje %s a %s (contenido oculto)", mensaje.canal, destino)
            return
        print(f"[DESARROLLO] {mensaje.canal} a {destino}: {mensaje.asunto}\n{mensaje.texto}")


class NotificadorMemoria:
    """Para pruebas: guarda lo enviado en vez de mandarlo."""

    def __init__(self) -> None:
        self.enviados: list[Mensaje] = []

    def enviar(self, mensaje: Mensaje) -> None:
        self.enviados.append(mensaje)


class PorCanal:
    """Despacha cada mensaje al notificador de su canal."""

    def __init__(self, correo: Notificador, sms: Notificador) -> None:
        self.correo = correo
        self.sms = sms

    def enviar(self, mensaje: Mensaje) -> None:
        (self.sms if mensaje.canal == "SMS" else self.correo).enviar(mensaje)


def construir() -> Notificador:
    return PorCanal(correo=NotificadorConsola(), sms=NotificadorConsola())


_actual: Notificador = construir()


def enviar(mensaje: Mensaje) -> None:
    _actual.enviar(mensaje)


def instalar(nuevo: Notificador) -> Notificador:
    """Sustituye el notificador en uso y devuelve el anterior."""
    global _actual
    anterior, _actual = _actual, nuevo
    return anterior
