"""Version PDF del documento final."""
from __future__ import annotations

import re

from app.dominio import pdf
from app.seguridad import sha256
from tests.ayudas import crear_contrato, crear_plantilla, firmar_como, token_de


def _completado(cliente, empresa, otp, **extra) -> dict:
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa, **extra).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp)
    return cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()


def test_al_completar_se_emite_el_pdf_con_su_hash(cliente, empresa, otp_fijo):
    contrato = _completado(cliente, empresa, otp_fijo)
    assert contrato["final_document_pdf_hash"]

    respuesta = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa,
        params={"formato": "pdf"},
    )
    assert respuesta.status_code == 200
    assert respuesta.headers["content-type"] == "application/pdf"
    assert respuesta.content.startswith(b"%PDF")
    assert respuesta.headers["x-document-hash"] == sha256(respuesta.content)
    assert respuesta.headers["x-document-hash"] == contrato["final_document_pdf_hash"]
    assert respuesta.headers["content-disposition"].startswith("attachment;")

    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    completado = next(e for e in auditoria["events"] if e["type"] == "COMPLETADO")
    assert completado["data"]["hash_documento_final_pdf"] == contrato["final_document_pdf_hash"]
    descarga = [e for e in auditoria["events"] if e["type"] == "DESCARGADO"][-1]
    assert descarga["data"]["formato"] == "pdf"


def test_sin_completar_no_hay_pdf(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    respuesta = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa,
        params={"formato": "pdf"},
    )
    assert respuesta.status_code == 409
    assert respuesta.json()["error"] == "pdf_no_disponible"


def test_un_formato_desconocido_se_rechaza(cliente, empresa):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    respuesta = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa,
        params={"formato": "docx"},
    )
    assert respuesta.status_code == 422


def test_si_falla_el_pdf_el_contrato_se_completa_igual(cliente, empresa, otp_fijo, monkeypatch):
    def roto(*_args, **_kwargs):
        raise RuntimeError("maquetacion imposible")

    monkeypatch.setattr(pdf, "html_a_pdf", roto)
    contrato = _completado(cliente, empresa, otp_fijo)

    assert contrato["status"] == "COMPLETADO"
    assert contrato["final_document_pdf_hash"] is None
    auditoria = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/auditoria", auth=empresa
    ).json()
    assert "PDF_NO_GENERADO" in [e["type"] for e in auditoria["events"]]
    assert auditoria["chain"]["integra"] is True

    respuesta = cliente.get(
        f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa,
        params={"formato": "pdf"},
    )
    assert respuesta.status_code == 409
    # El HTML final sigue disponible.
    html = cliente.get(f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa)
    assert html.headers["x-document-kind"] == "final"


def test_el_mismo_html_da_siempre_los_mismos_bytes():
    html = "<html><body><h1>Contrato</h1><p>Texto <strong>importante</strong>.</p></body></html>"
    assert pdf.html_a_pdf(html) == pdf.html_a_pdf(html)


def test_el_pdf_lleva_el_contenido_y_la_constancia(cliente, empresa, otp_fijo):
    contrato = _completado(cliente, empresa, otp_fijo)
    html = cliente.get(f"/v1/contratos/{contrato['contract_id']}/documento", auth=empresa).text
    crudo = pdf.html_a_pdf(html, comprimir=False)
    for texto in [b"Contrato de Servicio", b"Juan Perez", b"Constancia de firma electronica",
                  b"Linea de auditoria", contrato["document_hash"][:40].encode()]:
        assert texto in crudo, texto


def test_el_texto_del_integrador_no_se_interpreta_como_marcado():
    html = "<p>&lt;b&gt;no es negrita&lt;/b&gt; &amp; &lt;script&gt;x&lt;/script&gt;</p>"
    crudo = pdf.html_a_pdf(html, comprimir=False)
    # ReportLab parte la linea en varios operadores Tj; se juntan para leerla.
    texto = b"".join(re.findall(rb"\((.*?)\) Tj", crudo))
    assert b"<b>no es negrita</b> & <script>x</script>" in texto
    # Si "<b>" se hubiera interpretado, el PDF necesitaria la fuente en negrita.
    assert b"Times-Bold" not in crudo


def test_etiquetas_de_la_lista_blanca():
    html = (
        "<h2>Clausulas</h2><ol><li>Primera</li><li>Segunda</li></ol>"
        "<ul><li><em>uno</em></li></ul><blockquote>cita</blockquote><hr>"
        "<table><thead><tr><th>A</th><th>B</th></tr></thead>"
        "<tbody><tr><td>1</td></tr></tbody></table><div><span>suelto</span><br>fin</div>"
    )
    crudo = pdf.html_a_pdf(html, comprimir=False)
    for texto in [b"Clausulas", b"Primera", b"Segunda", b"uno", b"cita", b"suelto", b"fin"]:
        assert texto in crudo, texto
