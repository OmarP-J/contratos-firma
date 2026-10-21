"""El firmante puede negarse a firmar desde el portal."""
from __future__ import annotations

from tests.ayudas import (
    crear_contrato,
    crear_plantilla,
    csrf_de,
    firmar_como,
    identificarse,
    token_de,
)


def _rechazar(cliente, token: str, pagina: str, motivo: str = ""):
    return cliente.post(
        f"/firma/{token}/rechazar",
        data={"csrf": csrf_de(pagina), "motivo": motivo},
        follow_redirects=True,
    )


def test_el_cliente_rechaza_y_el_contrato_se_cierra(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])

    respuesta = _rechazar(cliente, token, identificarse(cliente, token), "El precio no es el acordado")
    assert respuesta.status_code == 200
    assert "rechazaste" in respuesta.text

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "RECHAZADO"
    assert estado["signers"][0]["status"] == "RECHAZADA"
    assert estado["signers"][0]["decline_reason"] == "El precio no es el acordado"

    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    assert auditoria["events"][-1]["type"] == "RECHAZADO"
    assert auditoria["chain"]["integra"] is True

    # El enlace ya no sirve para nada.
    assert cliente.get(f"/firma/{token}").status_code == 400


def test_sin_identificarse_no_se_puede_rechazar(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True)

    respuesta = cliente.post(f"/firma/{token}/rechazar", data={"csrf": csrf_de(pagina.text)})
    assert respuesta.status_code == 403
    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "PENDIENTE_CLIENTE"


def test_rechazar_exige_csrf(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    identificarse(cliente, token)
    respuesta = cliente.post(f"/firma/{token}/rechazar", data={"csrf": "inventado"})
    assert respuesta.status_code == 400


def test_la_empresa_tambien_puede_rechazar(cliente, empresa, otp_fijo):
    crear_plantilla(
        cliente, empresa, politica={"requiere_otp": True, "requiere_firma_empresa": True}
    )
    contrato = crear_contrato(
        cliente, empresa,
        firmantes=[
            {"rol": "CLIENTE", "nombre": "Juan Perez", "email": "juan@example.com"},
            {"rol": "EMPRESA", "nombre": "Ana Gomez", "email": "ana@acme.com"},
        ],
    ).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    reenvio = cliente.post(f"/v1/contratos/{contrato['contract_id']}/reenviar", auth=empresa)
    token = token_de(reenvio.json()["signing_url"])
    _rechazar(cliente, token, identificarse(cliente, token))

    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "RECHAZADO"
    assert [f["status"] for f in estado["signers"]] == ["FIRMADA", "RECHAZADA"]


def test_el_rechazo_llega_por_webhook_con_el_motivo(cliente, empresa, otp_fijo):
    from tests.receptor import receptor_webhook

    with receptor_webhook() as receptor:
        cliente.post(
            "/v1/webhooks", auth=empresa,
            json={"url": receptor.url, "eventos": ["contract.declined"]},
        )
        crear_plantilla(cliente, empresa)
        contrato = crear_contrato(cliente, empresa).json()
        token = token_de(contrato["signing_url"])
        _rechazar(cliente, token, identificarse(cliente, token), "No lo pedi")
        receptor.esperar(1)

    assert len(receptor.entregas) == 1
    cuerpo = receptor.entregas[0]["cuerpo"]
    assert cuerpo["event"] == "contract.declined"
    assert cuerpo["declined_by"] == "CLIENTE"
    assert cuerpo["reason"] == "No lo pedi"
