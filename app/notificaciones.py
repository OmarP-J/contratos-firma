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

import httpx

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


def a_e164(telefono: str) -> str:
    """
    Normaliza un telefono al formato internacional que exigen los proveedores.

    Un numero de 10 digitos se toma como del plan de numeracion de Norteamerica,
    que es el de la Republica Dominicana (809, 829, 849): 809-555-1234 pasa a
    +18095551234. Lo que no se pueda interpretar con seguridad se rechaza en
    vez de adivinar a quien mandarle un codigo.
    """
    crudo = telefono.strip()
    digitos = "".join(c for c in crudo if c.isdigit())
    if crudo.startswith("+") and 8 <= len(digitos) <= 15:
        return f"+{digitos}"
    if len(digitos) == 10:
        return f"+1{digitos}"
    if len(digitos) == 11 and digitos.startswith("1"):
        return f"+{digitos}"
    raise ValueError("Telefono en un formato que no se puede interpretar")


class SmsTwilio:
    """SMS por la API REST de Twilio."""

    URL = "https://api.twilio.com/2010-04-01/Accounts/{cuenta}/Messages.json"

    def __init__(
        self, *, cuenta: str, token: str, remitente: str, timeout_s: float = 10.0,
        transporte: httpx.BaseTransport | None = None,
    ) -> None:
        if not cuenta or not token or not remitente:
            raise RuntimeError(
                "TWILIO_CUENTA, TWILIO_TOKEN y TWILIO_REMITENTE son obligatorios con PROVEEDOR_SMS=twilio"
            )
        self.cuenta = cuenta
        self.token = token
        self.remitente = remitente
        self.timeout_s = timeout_s
        self.transporte = transporte

    def enviar(self, mensaje: Mensaje) -> None:
        try:
            datos = {"To": a_e164(mensaje.destino), "Body": mensaje.texto}
            # Un Messaging Service elige el numero emisor por su cuenta.
            clave = "MessagingServiceSid" if self.remitente.startswith("MG") else "From"
            datos[clave] = self.remitente
            with httpx.Client(transport=self.transporte, timeout=self.timeout_s) as http:
                respuesta = http.post(
                    self.URL.format(cuenta=self.cuenta), data=datos, auth=(self.cuenta, self.token)
                )
        except (httpx.HTTPError, ValueError) as error:
            registro.warning("fallo el envio SMS a %s: %r", enmascarar(mensaje.destino), error)
            raise ErrorDeEnvio(f"SMS: {error.__class__.__name__}") from error
        if not 200 <= respuesta.status_code < 300:
            registro.warning(
                "Twilio rechazo el SMS a %s: HTTP %s", enmascarar(mensaje.destino),
                respuesta.status_code,
            )
            raise ErrorDeEnvio(f"SMS: HTTP {respuesta.status_code}")


class SinCanal:
    """Para despliegues sin SMS: falla de forma explicita en vez de callar."""

    def __init__(self, canal: str) -> None:
        self.canal = canal

    def enviar(self, mensaje: Mensaje) -> None:
        raise ErrorDeEnvio(f"No hay proveedor configurado para {self.canal}")


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


def _sms_configurado() -> Notificador:
    config = ajustes()
    if config.proveedor_sms == "twilio":
        return SmsTwilio(
            cuenta=config.twilio_cuenta,
            token=config.twilio_token,
            remitente=config.twilio_remitente,
        )
    if config.proveedor_sms == "ninguno":
        return SinCanal("SMS")
    if config.proveedor_sms == "consola":
        return NotificadorConsola()
    raise RuntimeError(f"PROVEEDOR_SMS desconocido: {config.proveedor_sms}")


def construir() -> Notificador:
    return PorCanal(correo=_correo_configurado(), sms=_sms_configurado())


_actual: Notificador = construir()


def enviar(mensaje: Mensaje) -> None:
    _actual.enviar(mensaje)


def instalar(nuevo: Notificador) -> Notificador:
    """Sustituye el notificador en uso y devuelve el anterior."""
    global _actual
    anterior, _actual = _actual, nuevo
    return anterior
