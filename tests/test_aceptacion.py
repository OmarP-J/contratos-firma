"""
Criterios de aceptacion del documento de la propuesta (seccion 14).

Cada prueba nombra el criterio que comprueba.
"""
from __future__ import annotations

import pytest

from tests.ayudas import (
    SCHEMA,
    VARIABLES,
    crear_contrato,
    crear_plantilla,
    csrf_de,
    firmar_como,
    token_de,
)


# 1. Una empresa puede crear varias plantillas y publicar versiones nuevas sin
#    alterar contratos historicos.
def test_versiones_nuevas_no_tocan_contratos_ya_emitidos(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    primero = crear_contrato(cliente, empresa).json()
    assert primero["template_version"] == 1

    segunda = crear_plantilla(
        cliente, empresa,
        cuerpo="<p>Version nueva para {{ cliente.nombre }} por {{ servicio.precio }}.</p>",
    )
    assert segunda["version"] == 2

    de_nuevo = cliente.get(f"/v1/contratos/{primero['contract_id']}", auth=empresa).json()
    assert de_nuevo["template_version"] == 1
    assert de_nuevo["document_hash"] == primero["document_hash"]

    nuevo = crear_contrato(cliente, empresa).json()
    assert nuevo["template_version"] == 2


# 2. Una integracion B2B puede crear un contrato con plantilla, variables y
#    firmantes, sin enviar un PDF final.
def test_creacion_desde_plantilla_y_variables(cliente, empresa):
    crear_plantilla(cliente, empresa)
    respuesta = crear_contrato(cliente, empresa)
    assert respuesta.status_code == 201, respuesta.text
    cuerpo = respuesta.json()
    assert cuerpo["status"] == "PENDIENTE_CLIENTE"
    assert cuerpo["signing_url"].startswith("http://testserver/firma/")
    assert cuerpo["external_reference"] == "SOL-839291"


# 3. El backend rechaza variables desconocidas o invalidas y genera el
#    documento en servidor.
def test_rechaza_variables_no_declaradas(cliente, empresa):
    crear_plantilla(cliente, empresa)
    variables = {**VARIABLES, "salario_secreto": 999999}
    respuesta = crear_contrato(cliente, empresa, variables=variables)
    assert respuesta.status_code == 400
    assert "salario_secreto" in respuesta.json()["detalles"]


def test_rechaza_variable_invalida(cliente, empresa):
    crear_plantilla(cliente, empresa)
    variables = {"cliente": {"nombre": "Juan", "cedula": "123"},
                 "servicio": {"nombre": "Plan", "precio": "-5"}}
    respuesta = crear_contrato(cliente, empresa, variables=variables)
    assert respuesta.status_code == 400
    detalles = respuesta.json()["detalles"]
    assert "cliente.cedula" in detalles and "servicio.precio" in detalles


def test_rechaza_campos_no_declarados_en_el_propio_payload(cliente, empresa):
    crear_plantilla(cliente, empresa)
    respuesta = crear_contrato(cliente, empresa, campo_inventado="x")
    assert respuesta.status_code == 422  # lo para Pydantic antes del dominio


# 4. El contenido enviado a firma queda congelado y asociado a hashes verificables.
def test_documento_congelado_con_hashes(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    assert len(contrato["document_hash"]) == 64
    assert len(contrato["variables_hash"]) == 64

    documento = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa
    )
    assert documento.status_code == 200
    assert documento.headers["x-document-hash"] == contrato["document_hash"]
    assert documento.headers["x-document-kind"] == "presentado"
    assert "12,500.00" in documento.text


def test_el_documento_escapa_lo_que_manda_el_integrador(cliente, empresa):
    crear_plantilla(cliente, empresa)
    variables = {
        "cliente": {"nombre": "<script>alert(1)</script>", "cedula": "402-2118261-7"},
        "servicio": {"nombre": "Plan", "precio": "100"},
    }
    contrato = crear_contrato(cliente, empresa, variables=variables).json()
    documento = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa
    ).text
    assert "<script>alert(1)</script>" not in documento
    assert "&lt;script&gt;" in documento


# 5. Un cliente puede abrir una invitacion segura, autenticarse, aceptar y firmar.
def test_flujo_de_firma_del_cliente(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    final = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert final["status"] == "COMPLETADO"
    assert final["signers"][0]["status"] == "FIRMADA"
    assert final["final_document_hash"] is not None


def test_sin_identificarse_no_se_ve_el_documento(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    # Abre el enlace (se crea la sesion) pero salta el codigo e intenta ir
    # directo al documento y a su contenido.
    cliente.get(f"/firma/{token}", follow_redirects=True)
    assert cliente.get(f"/firma/{token}/documento").status_code == 403
    assert cliente.get(f"/firma/{token}/contrato.html").status_code == 403


def test_codigo_equivocado_no_autentica(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True)
    envio = cliente.post(f"/firma/{token}/codigo", data={"csrf": csrf_de(pagina.text)})
    fallo = cliente.post(
        f"/firma/{token}/verificar", data={"csrf": csrf_de(envio.text), "codigo": "000000"}
    )
    assert fallo.status_code == 400
    assert cliente.get(f"/firma/{token}/documento").status_code == 403


def test_sin_consentimiento_no_se_firma(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True)
    envio = cliente.post(f"/firma/{token}/codigo", data={"csrf": csrf_de(pagina.text)})
    verif = cliente.post(
        f"/firma/{token}/verificar",
        data={"csrf": csrf_de(envio.text), "codigo": otp_fijo},
        follow_redirects=True,
    )
    sin_aceptar = cliente.post(
        f"/firma/{token}/firmar", data={"csrf": csrf_de(verif.text)}
    )
    assert sin_aceptar.status_code == 400


def test_csrf_invalido_se_rechaza(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    cliente.get(f"/firma/{token}", follow_redirects=True)
    respuesta = cliente.post(f"/firma/{token}/codigo", data={"csrf": "inventado"})
    assert respuesta.status_code == 400


# 6. Un firmante empresarial autorizado puede completar su parte.
def test_firma_de_la_empresa(cliente, empresa, otp_fijo):
    crear_plantilla(
        cliente, empresa,
        politica={"requiere_otp": True, "requiere_firma_empresa": True},
    )
    contrato = crear_contrato(
        cliente, empresa,
        firmantes=[
            {"rol": "CLIENTE", "nombre": "Juan Perez", "documento": "40221182617",
             "email": "juan@example.com"},
            {"rol": "EMPRESA", "nombre": "Ana Gomez", "documento": "40221182617",
             "email": "ana@acme.com"},
        ],
    ).json()

    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)
    intermedio = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert intermedio["status"] == "PENDIENTE_EMPRESA"

    reenvio = cliente.post(
        f"/v1/contratos/{contrato['contract_id']}/reenviar", auth=empresa
    ).json()
    firmar_como(cliente, token_de(reenvio["signing_url"]), otp_fijo)

    final = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert final["status"] == "COMPLETADO"
    assert all(f["status"] == "FIRMADA" for f in final["signers"])


# 7. Un usuario de otro tenant no puede acceder al contrato aunque conozca el ID.
def test_aislamiento_entre_empresas(cliente, empresa, otra_empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    identificador = contrato["contract_id"]

    for metodo, ruta in [
        ("get", f"/v1/contratos/{identificador}"),
        ("get", f"/v1/contratos/{identificador}/documento"),
        ("get", f"/v1/contratos/{identificador}/auditoria"),
    ]:
        respuesta = getattr(cliente, metodo)(ruta, auth=otra_empresa)
        assert respuesta.status_code == 404, f"{ruta} filtro datos de otra empresa"

    anulacion = cliente.post(
        f"/v1/contratos/{identificador}/anular", auth=otra_empresa, json={"motivo": "x"}
    )
    assert anulacion.status_code == 404


def test_sin_credencial_no_se_entra(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    assert cliente.get(f"/v1/contratos/{contrato['contract_id']}").status_code == 401
    assert cliente.get(
        f"/v1/contratos/{contrato['contract_id']}", auth=("cli_falso", "secreto")
    ).status_code == 401


# 8. El documento final y la evidencia quedan disponibles tras completarse.
def test_documento_final_y_constancia(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    documento = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa
    )
    assert documento.headers["x-document-kind"] == "final"
    assert "Constancia de firma electronica" in documento.text
    assert "Linea de auditoria" in documento.text
    assert contrato["document_hash"] in documento.text


def test_cadena_de_auditoria_integra(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    assert auditoria["chain"]["integra"] is True
    tipos = [e["type"] for e in auditoria["events"]]
    for esperado in [
        "CONTRATO_CREADO", "INVITACION_CREADA", "CONTRATO_ABIERTO", "OTP_SOLICITADO",
        "OTP_VERIFICADO", "DOCUMENTO_VISTO", "CONSENTIMIENTO_ACEPTADO", "FIRMADO",
        "COMPLETADO",
    ]:
        assert esperado in tipos, f"falta el evento {esperado}"
    # Encadenado: cada evento referencia el hash del anterior.
    assert auditoria["events"][0]["previous_hash"] is None
    for anterior, siguiente in zip(auditoria["events"], auditoria["events"][1:]):
        assert siguiente["previous_hash"] == anterior["hash"]


def test_la_cadena_detecta_una_alteracion(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    from app.db import FabricaSesion
    from app.dominio import auditoria as modulo
    from app.models import EventoAuditoria
    from sqlalchemy import select

    with FabricaSesion() as sesion:
        evento = sesion.scalars(
            select(EventoAuditoria)
            .where(EventoAuditoria.contrato_id == contrato["contract_id"])
            .order_by(EventoAuditoria.secuencia)
        ).all()[2]
        tenant_id = evento.tenant_id
        evento.datos = {**evento.datos, "manipulado": True}
        sesion.commit()
        resultado = modulo.verificar_cadena(sesion, tenant_id, contrato["contract_id"])

    assert resultado["integra"] is False
    assert resultado["rota_en"] == 3


# 9. La plataforma origen recibe un webhook firmado e idempotente.
def test_idempotencia_no_duplica_contratos(cliente, empresa):
    crear_plantilla(cliente, empresa)
    cabeceras = {"Idempotency-Key": "pedido-123"}
    primera = cliente.post(
        "/v1/contratos", auth=empresa, headers=cabeceras,
        json={"plantilla": "contrato_servicio", "referencia_externa": "SOL-1",
              "firmantes": [{"nombre": "Juan Perez", "email": "juan@example.com"}],
              "variables": VARIABLES},
    )
    segunda = cliente.post(
        "/v1/contratos", auth=empresa, headers=cabeceras,
        json={"plantilla": "contrato_servicio", "referencia_externa": "SOL-1",
              "firmantes": [{"nombre": "Juan Perez", "email": "juan@example.com"}],
              "variables": VARIABLES},
    )
    assert primera.status_code == 201
    assert segunda.json()["contract_id"] == primera.json()["contract_id"]
    assert segunda.headers.get("Idempotent-Replay") == "true"


def test_misma_clave_con_cuerpo_distinto_es_conflicto(cliente, empresa):
    crear_plantilla(cliente, empresa)
    cabeceras = {"Idempotency-Key": "pedido-456"}
    base = {"plantilla": "contrato_servicio",
            "firmantes": [{"nombre": "Juan Perez", "email": "juan@example.com"}],
            "variables": VARIABLES}
    cliente.post("/v1/contratos", auth=empresa, headers=cabeceras, json=base)
    distinta = cliente.post(
        "/v1/contratos", auth=empresa, headers=cabeceras,
        json={**base, "referencia_externa": "OTRA"},
    )
    assert distinta.status_code == 409


def test_webhook_firmado_llega_al_receptor(cliente, empresa, otp_fijo):
    from tests.receptor import receptor_webhook

    with receptor_webhook() as receptor:
        registro = cliente.post(
            "/v1/webhooks", auth=empresa,
            json={"url": receptor.url, "eventos": ["contract.sent", "contract.completed"]},
        )
        assert registro.status_code == 201
        secreto = registro.json()["secret"]

        crear_plantilla(cliente, empresa)
        contrato = crear_contrato(cliente, empresa).json()
        firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)
        receptor.esperar(2)

    tipos = [e["cuerpo"]["event"] for e in receptor.entregas]
    assert "contract.sent" in tipos and "contract.completed" in tipos

    from app.dominio.webhooks import firma_esperada

    for entrega in receptor.entregas:
        esperada = firma_esperada(secreto, entrega["marca"], entrega["crudo"])
        assert entrega["firma"] == esperada, "la firma HMAC no coincide"
        assert entrega["cuerpo"]["contract_id"] == contrato["contract_id"]


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:9000/hook",   # loopback por http
        "https://169.254.169.254/x",    # metadatos de la nube
        "ftp://ejemplo.com/x",          # esquema no permitido
        "https://usuario:clave@ejemplo.com/x",
    ],
)
def test_webhook_hacia_destinos_peligrosos_se_rechaza(cliente, empresa, url, monkeypatch):
    from app.config import ajustes

    monkeypatch.setattr(ajustes(), "permitir_webhook_privado", False)
    respuesta = cliente.post("/v1/webhooks", auth=empresa, json={"url": url})
    assert respuesta.status_code == 400


# 10. Los secretos B2B nunca llegan al navegador.
def test_el_secreto_no_viaja_al_portal(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True).text
    client_id, secreto = empresa
    assert secreto not in pagina
    assert client_id not in pagina


def test_el_secreto_solo_existe_hasheado(empresa):
    from sqlalchemy import select

    from app.db import FabricaSesion
    from app.models import CredencialApi

    client_id, secreto = empresa
    with FabricaSesion() as sesion:
        credencial = sesion.scalars(
            select(CredencialApi).where(CredencialApi.client_id == client_id)
        ).first()
        assert secreto not in credencial.secreto_hash
        assert credencial.secreto_hash.startswith("scrypt$")


# 11. Los contratos completados no pueden modificarse ni eliminarse silenciosamente.
def test_contrato_completado_no_se_anula(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp_fijo)

    anulacion = cliente.post(
        f"/v1/contratos/{contrato['contract_id']}/anular", auth=empresa,
        json={"motivo": "me arrepenti"},
    )
    assert anulacion.status_code == 409


def test_contrato_anulado_no_se_puede_firmar(cliente, empresa, otp_fijo):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    cliente.post(
        f"/v1/contratos/{contrato['contract_id']}/anular", auth=empresa,
        json={"motivo": "pedido cancelado"},
    )
    assert cliente.get(f"/firma/{token}", follow_redirects=False).status_code == 400


# 12. La implementacion del proveedor de firma puede sustituirse.
def test_el_proveedor_de_firma_es_intercambiable():
    from app.dominio.firma import ProveedorExterno, ProveedorInterno, ProveedorFirma

    for clase in (ProveedorInterno, ProveedorExterno):
        assert isinstance(clase(), ProveedorFirma), f"{clase.__name__} no cumple la interfaz"


def test_la_firma_detecta_un_documento_alterado():
    from datetime import datetime, timezone

    from app.dominio.firma import ProveedorInterno, SolicitudFirma

    proveedor = ProveedorInterno()
    base = dict(
        tenant_id="t", contrato_id="c", parte_id="p", hash_evidencia="e",
        nombre="Ana", documento="40221182617", rol="CLIENTE",
        firmado_en=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )
    original = SolicitudFirma(hash_documento="hash_bueno", **base)
    resultado = proveedor.firmar(original)
    assert proveedor.verificar(original, resultado) is True

    alterado = SolicitudFirma(hash_documento="hash_cambiado", **base)
    assert proveedor.verificar(alterado, resultado) is False
