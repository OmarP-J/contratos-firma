"""
Notificaciones al firmante: codigos de un solo uso e invitaciones.

El resto del servicio solo conoce enviar(Mensaje). Que el mensaje salga por
SMTP, por un proveedor de SMS o a la consola en desarrollo es una decision de
configuracion, igual que con el proveedor de firma o el almacen.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
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


class CorreoSmtp:
    """
    Correo por SMTP, con TLS por defecto. Sirve con cualquier proveedor
    transaccional que ofrezca SMTP (SES, Mailgun, Postmark, SendGrid...).

    Solo texto plano: un correo con un codigo o un enlace de firma no
    necesita HTML, y sin HTML no hay nada que inyectar.
    """

    def __init__(
        self, *, host: str, puerto: int, remitente: str, usuario: str = "",
        clave: str = "", tls: str = "starttls", timeout_s: float = 10.0,
    ) -> None:
        if not host or not remitente:
            raise RuntimeError("SMTP_HOST y SMTP_REMITENTE son obligatorios con PROVEEDOR_CORREO=smtp")
        if tls not in {"starttls", "ssl", "ninguno"}:
            raise RuntimeError("SMTP_TLS debe ser starttls, ssl o ninguno")
        self.host = host
        self.puerto = puerto
        self.remitente = remitente
        self.usuario = usuario
        self.clave = clave
        self.tls = tls
        self.timeout_s = timeout_s

    def _componer(self, mensaje: Mensaje) -> EmailMessage:
        # EmailMessage rechaza saltos de linea en las cabeceras, asi que un
        # destino como "a@b.com\nBcc: otro@x.com" no puede colar destinatarios.
        correo = EmailMessage()
        correo["From"] = self.remitente
        correo["To"] = mensaje.destino
        correo["Subject"] = mensaje.asunto
        correo.set_content(mensaje.texto)
        return correo

    def enviar(self, mensaje: Mensaje) -> None:
        try:
            correo = self._componer(mensaje)
            contexto = ssl.create_default_context()
            if self.tls == "ssl":
                conexion = smtplib.SMTP_SSL(
                    self.host, self.puerto, timeout=self.timeout_s, context=contexto
                )
            else:
                conexion = smtplib.SMTP(self.host, self.puerto, timeout=self.timeout_s)
            with conexion:
                if self.tls == "starttls":
                    conexion.starttls(context=contexto)
                if self.usuario:
                    conexion.login(self.usuario, self.clave)
                conexion.send_message(correo)
        except (smtplib.SMTPException, OSError, ValueError) as error:
            # El detalle va al log; al llamador solo le importa que fallo.
            registro.warning("fallo el envio SMTP a %s: %r", enmascarar(mensaje.destino), error)
            raise ErrorDeEnvio(f"SMTP: {error.__class__.__name__}") from error


class PorCanal:
    """Despacha cada mensaje al notificador de su canal."""

    def __init__(self, correo: Notificador, sms: Notificador) -> None:
        self.correo = correo
        self.sms = sms

    def enviar(self, mensaje: Mensaje) -> None:
        (self.sms if mensaje.canal == "SMS" else self.correo).enviar(mensaje)


def _correo_configurado() -> Notificador:
    config = ajustes()
    if config.proveedor_correo == "smtp":
        return CorreoSmtp(
            host=config.smtp_host,
            puerto=config.smtp_puerto,
            remitente=config.smtp_remitente,
            usuario=config.smtp_usuario,
            clave=config.smtp_clave,
            tls=config.smtp_tls,
        )
    if config.proveedor_correo == "consola":
        return NotificadorConsola()
    raise RuntimeError(f"PROVEEDOR_CORREO desconocido: {config.proveedor_correo}")


def construir() -> Notificador:
    return PorCanal(correo=_correo_configurado(), sms=NotificadorConsola())


_actual: Notificador = construir()


def enviar(mensaje: Mensaje) -> None:
    _actual.enviar(mensaje)


def instalar(nuevo: Notificador) -> Notificador:
    """Sustituye el notificador en uso y devuelve el anterior."""
    global _actual
    anterior, _actual = _actual, nuevo
    return anterior
