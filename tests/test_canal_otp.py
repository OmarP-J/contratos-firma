"""El codigo de un solo uso sale por el canal que pide la politica de la plantilla."""
from __future__ import annotations

import pytest

from tests.ayudas import crear_contrato, crear_plantilla, csrf_de, token_de


def _codigo_enviado(cliente, empresa, buzon, otp, *, canal_politica, email, telefono):
    crear_plantilla(
        cliente, empresa,
        politica={"requiere_otp": True, "requiere_firma_empresa": False,
                  "canal_otp": canal_politica},
    )
    firmante = {"rol": "CLIENTE", "nombre": "Juan Perez", "email": email, "telefono": telefono}
    contrato = crear_contrato(cliente, empresa, firmantes=[firmante]).json()
    token = token_de(contrato["signing_url"])
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True)
    respuesta = cliente.post(f"/firma/{token}/codigo", data={"csrf": csrf_de(pagina.text)})
    assert respuesta.status_code == 200, respuesta.text
    return [m for m in buzon.enviados if otp in m.texto][-1]


@pytest.mark.parametrize(
    "canal_politica, email, telefono, canal, destino",
    [
        # La politica manda cuando el firmante tiene ese dato.
        ("SMS", "juan@example.com", "8095551234", "SMS", "8095551234"),
        ("EMAIL", "juan@example.com", "8095551234", "EMAIL", "juan@example.com"),
        # Si le falta, se usa el otro en vez de dejarlo sin poder firmar.
        ("SMS", "juan@example.com", None, "EMAIL", "juan@example.com"),
        ("EMAIL", None, "8095551234", "SMS", "8095551234"),
    ],
)
def test_canal_del_codigo(
    cliente, empresa, buzon, otp_fijo, canal_politica, email, telefono, canal, destino
):
    mensaje = _codigo_enviado(
        cliente, empresa, buzon, otp_fijo,
        canal_politica=canal_politica, email=email, telefono=telefono,
    )
    assert (mensaje.canal, mensaje.destino) == (canal, destino)


def test_el_canal_usado_queda_en_la_evidencia(cliente, empresa, buzon, otp_fijo):
    from tests.ayudas import firmar_como

    crear_plantilla(
        cliente, empresa,
        politica={"requiere_otp": True, "requiere_firma_empresa": False, "canal_otp": "SMS"},
    )
    contrato = crear_contrato(
        cliente, empresa,
        firmantes=[{"rol": "CLIENTE", "nombre": "Juan Perez", "email": "juan@example.com",
                    "telefono": "8095551234"}],
    ).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    documento = cliente.get(f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa)
    assert "OTP_SMS" in documento.text
