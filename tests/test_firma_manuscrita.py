"""Firma dibujada con el mouse o el dedo, en lugar de una casilla."""
from __future__ import annotations

import json
import re

import pytest
from sqlalchemy import select

from app.db import FabricaSesion
from app.dominio import firma_manuscrita as fm
from app.models import Evidencia
from tests.ayudas import (
    crear_contrato,
    crear_plantilla,
    csrf_de,
    firma_dibujada,
    firmar_como,
    identificarse,
    token_de,
)


def _firma(trazos) -> str:
    return json.dumps({"ancho": 600, "alto": 200, "trazos": trazos})


# --- validacion ---------------------------------------------------------------

def test_una_firma_normal_se_acepta_y_se_normaliza():
    firma = fm.validar(firma_dibujada())
    assert (firma["ancho"], firma["alto"]) == (600, 200)
    assert len(firma["trazos"]) == 1 and len(firma["trazos"][0]) == 40


@pytest.mark.parametrize(
    "texto",
    [
        "",
        "   ",
        "no es json",
        "[]",
        json.dumps({"ancho": 600, "alto": 200}),  # sin trazos
        json.dumps({"ancho": 600, "alto": 200, "trazos": []}),
        json.dumps({"ancho": 999, "alto": 200, "trazos": [[[1, 1], [50, 50]]]}),  # lienzo distinto
    ],
)
def test_rechaza_lo_que_no_es_una_firma(texto):
    with pytest.raises(fm.FirmaInvalida):
        fm.validar(texto)


@pytest.mark.parametrize(
    "trazos",
    [
        [[[100, 100]]],                                  # un toque suelto
        [[[100, 100], [101, 101], [102, 100]]],          # una rayita diminuta
        [[[100, 100], [140, 100]]],                      # corta: 40 de largo, menos que el minimo
        [[[100, 100], [100, 100], [100, 100], [100, 100]]],  # sin moverse
    ],
)
def test_un_toque_o_una_rayita_no_es_una_firma(trazos):
    with pytest.raises(fm.FirmaInvalida, match="corta|Dibuja"):
        fm.validar(_firma(trazos))


@pytest.mark.parametrize(
    "trazos",
    [
        [[[0, 0], ["a", 5]]],               # texto en vez de numero
        [[[0, 0], [True, 5]]],              # booleano
        [[[0, 0], [5]]],                    # punto incompleto
        [[[0, 0], [5, 5, 5]]],              # punto con tres coordenadas
        [[[0, 0], [9999, 5]]],              # fuera del lienzo
        [[[0, 0], [5, -50]]],               # fuera del lienzo
        ["no es una lista"],
        [[[0, 0], [float("nan"), 5]]],
    ],
)
def test_rechaza_puntos_mal_formados_o_fuera_del_lienzo(trazos):
    with pytest.raises(fm.FirmaInvalida):
        fm.validar(_firma(trazos).replace("NaN", "NaN"))


def test_rechaza_firmas_demasiado_grandes():
    muchos_trazos = [[[10, 10], [200, 150]] for _ in range(fm.MAX_TRAZOS + 1)]
    with pytest.raises(fm.FirmaInvalida, match="compleja"):
        fm.validar(_firma(muchos_trazos))

    muchos_puntos = [[[i % 590, (i * 7) % 190] for i in range(fm.MAX_PUNTOS + 1)]]
    with pytest.raises(fm.FirmaInvalida, match="compleja"):
        fm.validar(_firma(muchos_puntos))

    with pytest.raises(fm.FirmaInvalida, match="compleja"):
        fm.validar("[" + ",".join(["0"] * fm.MAX_BYTES) + "]")


def test_el_dibujo_sale_igual_con_los_mismos_trazos_y_no_lleva_nada_ajeno():
    firma = fm.validar(firma_dibujada())
    assert fm.svg(firma) == fm.svg(fm.validar(firma_dibujada()))
    assert fm.hash_de(firma) == fm.hash_de(fm.validar(firma_dibujada()))
    codigo = fm.svg(firma)
    # Solo geometria: ni scripts, ni atributos de eventos, ni referencias externas.
    assert "<script" not in codigo and "onload" not in codigo and "href" not in codigo
    assert re.fullmatch(r'<svg [^>]*>(<polyline [^>]*/>)+</svg>', codigo)


# --- portal -------------------------------------------------------------------

def _hasta_el_documento(cliente, empresa, otp):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    token = token_de(contrato["signing_url"])
    return contrato, token, identificarse(cliente, token, otp)


def test_la_pagina_de_firma_trae_el_lienzo_y_ya_no_la_casilla(cliente, empresa, otp_fijo):
    _, token, pagina = _hasta_el_documento(cliente, empresa, otp_fijo)
    assert 'id="lienzo"' in pagina
    assert 'name="firma"' in pagina
    assert 'name="acepto"' not in pagina and 'type="checkbox"' not in pagina
    # Con el dedo: sin esto, la pagina se desplaza en vez de dejar dibujar.
    assert "touch-action: none" in cliente.get(f"/firma/{token}/documento").text


@pytest.mark.parametrize(
    "firma, mensaje",
    [
        ("", "Dibuja tu firma"),
        (_firma([[[100, 100]]]), "Dibuja tu firma"),
        (_firma([[[100, 100], [130, 100]]]), "muy corta"),
        ("basura", "no es valida"),
    ],
)
def test_sin_una_firma_de_verdad_no_se_firma(cliente, empresa, otp_fijo, firma, mensaje):
    contrato, token, pagina = _hasta_el_documento(cliente, empresa, otp_fijo)
    respuesta = cliente.post(
        f"/firma/{token}/firmar", data={"csrf": csrf_de(pagina), "firma": firma}
    )
    assert respuesta.status_code == 400
    assert mensaje in respuesta.text
    estado = cliente.get(f"/v1/contratos/{contrato['contract_id']}", auth=empresa).json()
    assert estado["status"] == "PENDIENTE_CLIENTE"


def test_la_casilla_sola_ya_no_basta(cliente, empresa, otp_fijo):
    """Quien mande la forma vieja (acepto=si) sin dibujo, no firma."""
    _, token, pagina = _hasta_el_documento(cliente, empresa, otp_fijo)
    respuesta = cliente.post(
        f"/firma/{token}/firmar", data={"csrf": csrf_de(pagina), "acepto": "si"}
    )
    assert respuesta.status_code == 400


# --- evidencia, documento final y PDF ------------------------------------------

def _completar(cliente, empresa, otp):
    crear_plantilla(cliente, empresa)
    contrato = crear_contrato(cliente, empresa).json()
    firmar_como(cliente, token_de(contrato["signing_url"]), otp)
    return contrato["contract_id"]


def test_la_firma_dibujada_queda_en_la_evidencia_sellada(cliente, empresa, otp_fijo):
    contrato_id = _completar(cliente, empresa, otp_fijo)
    with FabricaSesion() as sesion:
        evidencia = sesion.scalars(
            select(Evidencia).where(Evidencia.contrato_id == contrato_id)
        ).one()
    datos = evidencia.datos
    assert datos["firma_manuscrita"] == fm.validar(firma_dibujada())
    assert datos["firma_manuscrita_hash"] == fm.hash_de(datos["firma_manuscrita"])

    # El hash de la evidencia (lo que se sella) cubre el dibujo: cambiar un trazo lo rompe.
    from app.seguridad import json_canonico, sha256

    sin_sello = {k: v for k, v in datos.items() if k not in ("firma", "algoritmo")}
    assert sha256(json_canonico(sin_sello)) == evidencia.hash_evidencia
    alterada = {**sin_sello, "firma_manuscrita": {**datos["firma_manuscrita"], "trazos": [[[1, 1], [2, 2]]]}}
    assert sha256(json_canonico(alterada)) != evidencia.hash_evidencia


def test_el_documento_final_muestra_la_firma_y_su_huella(cliente, empresa, otp_fijo):
    contrato_id = _completar(cliente, empresa, otp_fijo)
    documento = cliente.get(f"/v1/contratos/{contrato_id}/documento", auth=empresa)
    assert 'class="firma-manuscrita"' in documento.text
    assert "<svg" in documento.text and "<polyline" in documento.text
    assert "Huella de la firma manuscrita" in documento.text
    assert fm.hash_de(fm.validar(firma_dibujada())) in documento.text

    auditoria = cliente.get(f"/v1/contratos/{contrato_id}/auditoria", auth=empresa).json()
    consentimiento = next(e for e in auditoria["events"] if e["type"] == "CONSENTIMIENTO_ACEPTADO")
    assert consentimiento["data"]["medio"] == "firma dibujada"
    assert auditoria["chain"]["integra"] is True


def test_el_pdf_dibuja_la_firma(cliente, empresa, otp_fijo):
    from app.dominio import pdf

    contrato_id = _completar(cliente, empresa, otp_fijo)
    html = cliente.get(f"/v1/contratos/{contrato_id}/documento", auth=empresa).text
    con_firma = pdf.html_a_pdf(html, comprimir=False)
    sin_firma = pdf.html_a_pdf(re.sub(r'<div class="firma-manuscrita">.*?</svg></div>', "", html, flags=re.S),
                               comprimir=False)
    # El dibujo agrega trazos vectoriales al PDF, y el resultado sigue siendo reproducible.
    assert len(con_firma) > len(sin_firma)
    assert con_firma == pdf.html_a_pdf(html, comprimir=False)
    assert b"Firma manuscrita" in con_firma

    descarga = cliente.get(
        f"/v1/contratos/{contrato_id}/documento", auth=empresa, params={"formato": "pdf"}
    )
    assert descarga.status_code == 200 and descarga.content.startswith(b"%PDF")
