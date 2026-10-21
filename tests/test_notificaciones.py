"""Envio de codigos e invitaciones a traves del puerto de notificaciones."""
from __future__ import annotations

from app import notificaciones
from app.notificaciones import ErrorDeEnvio, Mensaje, NotificadorConsola
from tests.ayudas import crear_contrato, crear_plantilla, csrf_de, token_de


def _pedir_codigo(cliente, token: str):
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True)
    return cliente.post(f"/firma/{token}/codigo", data={"csrf": csrf_de(pagina.text)})


def test_el_codigo_sale_por_el_notificador(cliente, empresa, otp_fijo, buzon):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    _pedir_codigo(cliente, token_de(contrato["signing_url"]))

    codigos = [m for m in buzon.enviados if otp_fijo in m.texto]
    assert len(codigos) == 1
    assert codigos[0].canal == "EMAIL"
    assert codigos[0].destino == "juan@example.com"


def test_si_el_proveedor_falla_se_avisa_y_el_codigo_no_sirve(cliente, empresa, otp_fijo):
    class Caido:
        def enviar(self, mensaje):
            raise ErrorDeEnvio("proveedor caido")

    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])

    anterior = notificaciones.instalar(Caido())
    try:
        respuesta = _pedir_codigo(cliente, token)
    finally:
        notificaciones.instalar(anterior)

    assert respuesta.status_code == 502
    assert "No pudimos enviarte el codigo" in respuesta.text

    # Aunque alguien adivinara el codigo, ese desafio no quedo pendiente.
    verificacion = cliente.post(
        f"/firma/{token}/verificar", data={"csrf": csrf_de(respuesta.text), "codigo": otp_fijo}
    )
    assert verificacion.status_code == 400

    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    assert "OTP_NO_ENVIADO" in [e["type"] for e in auditoria["events"]]


def test_la_consola_no_muestra_el_contenido_si_no_se_permite(capsys, monkeypatch):
    from app.config import ajustes

    monkeypatch.setattr(ajustes(), "mostrar_secretos_en_log", False)
    NotificadorConsola().enviar(
        Mensaje(canal="EMAIL", destino="ana@acme.com", asunto="Codigo", texto="Tu codigo es 999111")
    )
    assert "999111" not in capsys.readouterr().out


def test_la_consola_muestra_el_contenido_en_desarrollo(capsys, monkeypatch):
    from app.config import ajustes

    monkeypatch.setattr(ajustes(), "mostrar_secretos_en_log", True)
    NotificadorConsola().enviar(
        Mensaje(canal="SMS", destino="8095551234", asunto="Codigo", texto="Tu codigo es 999111")
    )
    salida = capsys.readouterr().out
    assert "999111" in salida
    assert "8095551234" not in salida  # el destino sale enmascarado
