"""Las entregas se conectan a la IP que se valido, no a lo que diga el DNS despues."""
from __future__ import annotations

import socket

import httpx
import pytest

from app.config import ajustes
from app.dominio import webhooks
from app.seguridad import cifrar
from tests.ayudas import crear_contrato, crear_plantilla
from tests.receptor import receptor_webhook

_getaddrinfo_real = socket.getaddrinfo


def _respuesta_dns(ip: str, puerto: int) -> list:
    familia = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(familia, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, puerto))]


def test_un_cambio_de_dns_entre_validar_y_conectar_no_desvia_la_entrega(
    cliente, empresa, monkeypatch
):
    """
    Simula DNS rebinding: el nombre resuelve a la IP buena mientras se valida,
    y despues a otra. La entrega tiene que llegar a la primera.
    """
    monkeypatch.setattr(ajustes(), "entregar_webhooks_en_linea", False)
    consultas = []

    def dns_cambiante(host, puerto, *args, **kwargs):
        if host != "receptor.ejemplo.test":
            return _getaddrinfo_real(host, puerto, *args, **kwargs)
        consultas.append(host)
        # Las dos primeras consultas son las validaciones (al registrar y al
        # entregar). Cualquier consulta posterior recibe otra IP.
        ip = "127.0.0.1" if len(consultas) <= 2 else "203.0.113.7"
        return _respuesta_dns(ip, puerto)

    monkeypatch.setattr(socket, "getaddrinfo", dns_cambiante)

    with receptor_webhook() as receptor:
        url = f"http://receptor.ejemplo.test:{receptor.puerto}/hook"
        registro = cliente.post(
            "/v1/webhooks", auth=empresa, json={"url": url, "eventos": ["contract.sent"]}
        )
        assert registro.status_code == 201, registro.text
        crear_plantilla(cliente, empresa)
        crear_contrato(cliente, empresa)

        webhooks.procesar_pendientes()
        receptor.esperar(1)

    assert len(consultas) == 2, "la entrega volvio a resolver el nombre"
    [entrega] = receptor.entregas
    assert entrega["host"] == f"receptor.ejemplo.test:{receptor.puerto}"


@pytest.fixture
def transporte(monkeypatch):
    peticiones: list[httpx.Request] = []
    rechazar: set[str] = set()

    def manejar(peticion: httpx.Request) -> httpx.Response:
        if peticion.url.host in rechazar:
            raise httpx.ConnectError("conexion rechazada", request=peticion)
        peticiones.append(peticion)
        return httpx.Response(200)

    monkeypatch.setattr(webhooks, "_transporte", httpx.MockTransport(manejar))
    monkeypatch.setattr(ajustes(), "permitir_webhook_privado", False)
    return peticiones, rechazar


def _dns_fijo(monkeypatch, *ips: str) -> None:
    def resolver(host, puerto, *args, **kwargs):
        resultado = []
        for ip in ips:
            resultado += _respuesta_dns(ip, puerto)
        return resultado

    monkeypatch.setattr(socket, "getaddrinfo", resolver)


def test_https_conserva_el_nombre_en_host_y_sni(transporte, monkeypatch):
    peticiones, _ = transporte
    _dns_fijo(monkeypatch, "93.184.216.34")

    codigo, error = webhooks._enviar(
        "https://hooks.ejemplo.com/recibir", cifrar("whsec_x"), {"event": "contract.sent"},
        "evt_1", "contract.sent",
    )
    assert (codigo, error) == (200, None)

    [peticion] = peticiones
    assert str(peticion.url) == "https://93.184.216.34/recibir"
    assert peticion.headers["host"] == "hooks.ejemplo.com"
    # El certificado se verifica contra este nombre, no contra la IP.
    assert peticion.extensions["sni_hostname"] == "hooks.ejemplo.com"


def test_si_una_ip_no_responde_prueba_la_siguiente(transporte, monkeypatch):
    peticiones, rechazar = transporte
    _dns_fijo(monkeypatch, "2606:2800:220:1::1", "93.184.216.34")
    rechazar.add("2606:2800:220:1::1")

    codigo, error = webhooks._enviar(
        "https://hooks.ejemplo.com/recibir", cifrar("whsec_x"), {}, "evt_2", "contract.sent",
    )
    assert (codigo, error) == (200, None)
    assert [p.url.host for p in peticiones] == ["93.184.216.34"]


def test_si_cualquier_ip_resuelta_es_privada_no_se_envia(transporte, monkeypatch):
    peticiones, _ = transporte
    _dns_fijo(monkeypatch, "93.184.216.34", "10.0.0.5")

    codigo, error = webhooks._enviar(
        "https://hooks.ejemplo.com/recibir", cifrar("whsec_x"), {}, "evt_3", "contract.sent",
    )
    assert codigo is None and "no permitida" in error
    assert peticiones == []


@pytest.mark.parametrize(
    "url, ip, esperada",
    [
        ("https://h.com/x?y=1", "93.184.216.34", "https://93.184.216.34/x?y=1"),
        ("https://h.com:8443/x", "2001:db8::1", "https://[2001:db8::1]:8443/x"),
    ],
)
def test_url_hacia_una_ip(url, ip, esperada):
    assert webhooks._url_hacia(url, ip) == esperada
