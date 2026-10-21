"""Envio de correo por SMTP, contra un servidor simulado."""
from __future__ import annotations

import smtplib

import pytest

from app import notificaciones
from app.notificaciones import CorreoSmtp, ErrorDeEnvio, Mensaje


class ServidorFalso:
    """Imita smtplib.SMTP y guarda lo que se le pidio."""

    instancias: list["ServidorFalso"] = []

    def __init__(self, host, puerto, timeout=None, context=None):
        self.host, self.puerto = host, puerto
        self.pasos: list[str] = []
        self.enviados = []
        ServidorFalso.instancias.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.pasos.append("quit")

    def starttls(self, context=None):
        self.pasos.append("starttls")

    def login(self, usuario, clave):
        self.pasos.append(f"login:{usuario}")

    def send_message(self, correo):
        self.pasos.append("send")
        self.enviados.append(correo)


@pytest.fixture
def servidor(monkeypatch):
    ServidorFalso.instancias = []
    monkeypatch.setattr(notificaciones.smtplib, "SMTP", ServidorFalso)
    monkeypatch.setattr(notificaciones.smtplib, "SMTP_SSL", ServidorFalso)
    return ServidorFalso


def _correo(**extra) -> CorreoSmtp:
    datos = dict(host="smtp.ejemplo.com", puerto=587, remitente="firmas@ejemplo.com",
                 usuario="api", clave="secreto")
    datos.update(extra)
    return CorreoSmtp(**datos)


def _mensaje(**extra) -> Mensaje:
    datos = dict(canal="EMAIL", destino="juan@example.com", asunto="Tu codigo",
                 texto="Tu codigo es 123456")
    datos.update(extra)
    return Mensaje(**datos)


def test_envia_con_starttls_y_autenticacion(servidor):
    _correo().enviar(_mensaje())
    conexion = servidor.instancias[0]
    assert (conexion.host, conexion.puerto) == ("smtp.ejemplo.com", 587)
    assert conexion.pasos == ["starttls", "login:api", "send", "quit"]

    correo = conexion.enviados[0]
    assert correo["To"] == "juan@example.com"
    assert correo["From"] == "firmas@ejemplo.com"
    assert "123456" in correo.get_content()


def test_sin_usuario_no_intenta_autenticarse(servidor):
    _correo(usuario="", clave="").enviar(_mensaje())
    assert servidor.instancias[0].pasos == ["starttls", "send", "quit"]


def test_un_destino_con_salto_de_linea_no_cuela_cabeceras(servidor):
    with pytest.raises(ErrorDeEnvio):
        _correo().enviar(_mensaje(destino="juan@example.com\nBcc: espia@example.com"))
    assert servidor.instancias == []


def test_un_fallo_del_servidor_se_convierte_en_error_de_envio(monkeypatch):
    def rechaza(*_args, **_kwargs):
        raise smtplib.SMTPConnectError(421, b"ocupado")

    monkeypatch.setattr(notificaciones.smtplib, "SMTP", rechaza)
    with pytest.raises(ErrorDeEnvio):
        _correo().enviar(_mensaje())


def test_la_configuracion_incompleta_se_detecta_al_arrancar():
    with pytest.raises(RuntimeError):
        CorreoSmtp(host="", puerto=587, remitente="")
    with pytest.raises(RuntimeError):
        _correo(tls="quizas")


def test_la_configuracion_elige_smtp(monkeypatch):
    from app.config import ajustes

    monkeypatch.setattr(ajustes(), "proveedor_correo", "smtp")
    monkeypatch.setattr(ajustes(), "smtp_host", "smtp.ejemplo.com")
    monkeypatch.setattr(ajustes(), "smtp_remitente", "firmas@ejemplo.com")
    construido = notificaciones.construir()
    assert isinstance(construido.correo, CorreoSmtp)
