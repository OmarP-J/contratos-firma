"""Envio de SMS por Twilio, contra un transporte HTTP simulado."""
from __future__ import annotations

import base64
from urllib.parse import parse_qs

import httpx
import pytest

from app import notificaciones
from app.notificaciones import ErrorDeEnvio, Mensaje, SinCanal, SmsTwilio, a_e164


def _capturar(codigo: int = 201):
    peticiones: list[httpx.Request] = []

    def manejar(peticion: httpx.Request) -> httpx.Response:
        peticiones.append(peticion)
        return httpx.Response(codigo, json={"sid": "SM123"})

    return peticiones, httpx.MockTransport(manejar)


def _sms(transporte, remitente="+18095550000") -> SmsTwilio:
    return SmsTwilio(cuenta="AC123", token="tok", remitente=remitente, transporte=transporte)


def _mensaje(destino="809-555-1234") -> Mensaje:
    return Mensaje(canal="SMS", destino=destino, asunto="", texto="Tu codigo es 123456")


@pytest.mark.parametrize(
    "entrada, esperado",
    [
        ("809-555-1234", "+18095551234"),
        ("(829) 555 1234", "+18295551234"),
        ("1 849 555 1234", "+18495551234"),
        ("+34 612 345 678", "+34612345678"),
    ],
)
def test_normaliza_telefonos(entrada, esperado):
    assert a_e164(entrada) == esperado


@pytest.mark.parametrize("entrada", ["5551234", "abc", "+12", "00000000000000000"])
def test_rechaza_telefonos_que_no_se_pueden_interpretar(entrada):
    with pytest.raises(ValueError):
        a_e164(entrada)


def test_envia_a_twilio_con_autenticacion_y_numero_normalizado():
    peticiones, transporte = _capturar()
    _sms(transporte).enviar(_mensaje())

    peticion = peticiones[0]
    assert str(peticion.url) == "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json"
    esperado = base64.b64encode(b"AC123:tok").decode()
    assert peticion.headers["authorization"] == f"Basic {esperado}"

    formulario = parse_qs(peticion.content.decode())
    assert formulario["To"] == ["+18095551234"]
    assert formulario["From"] == ["+18095550000"]
    assert formulario["Body"] == ["Tu codigo es 123456"]


def test_con_messaging_service_no_manda_from():
    peticiones, transporte = _capturar()
    _sms(transporte, remitente="MG999").enviar(_mensaje())
    formulario = parse_qs(peticiones[0].content.decode())
    assert formulario["MessagingServiceSid"] == ["MG999"]
    assert "From" not in formulario


def test_un_rechazo_de_twilio_es_error_de_envio():
    _, transporte = _capturar(codigo=400)
    with pytest.raises(ErrorDeEnvio):
        _sms(transporte).enviar(_mensaje())


def test_un_telefono_invalido_no_llega_a_twilio():
    peticiones, transporte = _capturar()
    with pytest.raises(ErrorDeEnvio):
        _sms(transporte).enviar(_mensaje(destino="12"))
    assert peticiones == []


def test_sin_canal_falla_de_forma_explicita():
    with pytest.raises(ErrorDeEnvio):
        SinCanal("SMS").enviar(_mensaje())


def test_la_configuracion_elige_el_proveedor_de_sms(monkeypatch):
    from app.config import ajustes

    monkeypatch.setattr(ajustes(), "proveedor_sms", "twilio")
    monkeypatch.setattr(ajustes(), "twilio_cuenta", "AC123")
    monkeypatch.setattr(ajustes(), "twilio_token", "tok")
    monkeypatch.setattr(ajustes(), "twilio_remitente", "+18095550000")
    assert isinstance(notificaciones.construir().sms, SmsTwilio)

    monkeypatch.setattr(ajustes(), "proveedor_sms", "ninguno")
    assert isinstance(notificaciones.construir().sms, SinCanal)
