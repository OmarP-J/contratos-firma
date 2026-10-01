"""
Portal de firma alojado.

El firmante entra por un enlace con un token, se autentica, lee el contrato,
acepta expresamente el uso de firma electronica y firma. Todo ocurre en nuestro
dominio: asi controlamos las cookies, las cabeceras y el aislamiento, y la
plataforma integradora no tiene que implementar nada de esto.
"""
from __future__ import annotations

import secrets
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.almacenamiento import almacen
from app.config import ajustes
from app.db import ahora_utc, obtener_sesion
from app.dependencias import ip_observada, limitar
from app.dominio import auditoria, contratos as servicio, webhooks
from app.dominio.contratos import Contexto, ErrorDeNegocio
from app.models import Contrato, DesafioOtp, Invitacion, ParteContrato, SesionFirma
from app.seguridad import (
    codigo_otp,
    comparar_seguro,
    derivar_clave,
    enmascarar,
    hash_de_token,
    hmac_sha256,
    sha256,
)

router = APIRouter(prefix="/firma", tags=["portal"])
plantillas = Jinja2Templates(directory=str(Path(__file__).parent / "plantillas"))

COOKIE_SESION = "__Host-sesion_firma" if False else "sesion_firma"


# ---------------------------------------------------------------------------
# Resolucion de la invitacion y la sesion
# ---------------------------------------------------------------------------

class Acceso:
    def __init__(
        self, invitacion: Invitacion, contrato: Contrato, parte: ParteContrato,
        sesion_firma: SesionFirma, token: str,
    ) -> None:
        self.invitacion = invitacion
        self.contrato = contrato
        self.parte = parte
        self.sesion_firma = sesion_firma
        self.token = token


def _error(mensaje: str, codigo: int = status.HTTP_400_BAD_REQUEST) -> HTTPException:
    return HTTPException(status_code=codigo, detail={"error": "firma", "mensaje": mensaje})


def resolver_acceso(
    token: str, request: Request, sesion: Session, crear_sesion: bool = True
) -> Acceso:
    limitar(f"portal:{ip_observada(request)}", limite=120, ventana_s=60)

    invitacion = sesion.scalars(
        select(Invitacion).where(Invitacion.token_hash == hash_de_token(token))
    ).first()
    if invitacion is None:
        raise _error("Este enlace no es valido.", status.HTTP_404_NOT_FOUND)
    if invitacion.estado != "ACTIVA":
        raise _error("Este enlace ya no esta activo.")
    if invitacion.expira_en <= ahora_utc():
        invitacion.estado = "VENCIDA"
        sesion.commit()
        raise _error("Este enlace ya vencio.")

    contrato = sesion.get(Contrato, invitacion.contrato_id)
    parte = sesion.get(ParteContrato, invitacion.parte_id)
    if contrato is None or parte is None:
        raise _error("Este enlace no es valido.", status.HTTP_404_NOT_FOUND)
    if contrato.estado not in {"PENDIENTE_CLIENTE", "PENDIENTE_EMPRESA"}:
        raise _error("Este contrato ya no admite firmas.")

    sesion_firma = sesion.scalars(
        select(SesionFirma)
        .where(SesionFirma.invitacion_id == invitacion.id)
        .order_by(SesionFirma.creada_en.desc())
        .limit(1)
    ).first()

    if sesion_firma is None or sesion_firma.expira_en <= ahora_utc():
        if not crear_sesion:
            raise _error("La sesion de firma vencio. Vuelve a abrir el enlace.")
        sesion_firma = SesionFirma(
            tenant_id=contrato.tenant_id,
            contrato_id=contrato.id,
            parte_id=parte.id,
            invitacion_id=invitacion.id,
            ip=ip_observada(request),
            agente=(request.headers.get("user-agent") or "")[:400],
            expira_en=ahora_utc() + timedelta(minutes=60),
        )
        sesion.add(sesion_firma)
        sesion.flush()

    # La IP y el dispositivo se refrescan en cada paso: son evidencia.
    sesion_firma.ip = ip_observada(request)
    sesion_firma.agente = (request.headers.get("user-agent") or "")[:400]
    return Acceso(invitacion, contrato, parte, sesion_firma, token)


def token_csrf(sesion_firma: SesionFirma) -> str:
    """Token ligado a la sesion de firma. No hace falta guardarlo: se recalcula."""
    return hmac_sha256(derivar_clave("csrf"), sesion_firma.id)


def exigir_csrf(acceso: Acceso, enviado: str) -> None:
    if not comparar_seguro(token_csrf(acceso.sesion_firma), enviado or ""):
        raise _error("La solicitud no es valida. Recarga la pagina e intentalo de nuevo.")


def _contexto_firmante(acceso: Acceso, request: Request) -> Contexto:
    return Contexto(
        tenant_id=acceso.contrato.tenant_id,
        actor_tipo="FIRMANTE",
        actor_id=acceso.parte.id,
        ip=ip_observada(request),
        agente=request.headers.get("user-agent"),
    )


def _base(request: Request, acceso: Acceso) -> dict:
    return {
        "request": request,
        "token": acceso.token,
        "contrato": acceso.contrato,
        "parte": acceso.parte,
        "csrf": token_csrf(acceso.sesion_firma),
        "politica": acceso.contrato.politica or {},
    }


# ---------------------------------------------------------------------------
# Paso 1: abrir el enlace
# ---------------------------------------------------------------------------

@router.get("/{token}", response_class=HTMLResponse)
def abrir(token: str, request: Request, sesion: Session = Depends(obtener_sesion)):
    acceso = resolver_acceso(token, request, sesion)
    if acceso.invitacion.abierta_en is None:
        acceso.invitacion.abierta_en = ahora_utc()
        auditoria.registrar(
            sesion,
            tenant_id=acceso.contrato.tenant_id,
            contrato_id=acceso.contrato.id,
            tipo="CONTRATO_ABIERTO",
            actor_tipo="FIRMANTE",
            actor_id=acceso.parte.id,
            ip=ip_observada(request),
            agente=request.headers.get("user-agent"),
        )
        webhooks.encolar(
            sesion,
            tenant_id=acceso.contrato.tenant_id,
            evento="contract.viewed",
            contrato_id=acceso.contrato.id,
            datos={"status": acceso.contrato.estado,
                   "external_reference": acceso.contrato.referencia_externa},
        )
    sesion.commit()

    if acceso.sesion_firma.autenticada or not (acceso.contrato.politica or {}).get("requiere_otp", True):
        return RedirectResponse(f"/firma/{token}/documento", status_code=303)
    return plantillas.TemplateResponse(request, "identificacion.html", _base(request, acceso))


# ---------------------------------------------------------------------------
# Paso 2: identificacion con codigo de un solo uso
# ---------------------------------------------------------------------------

@router.post("/{token}/codigo", response_class=HTMLResponse)
def solicitar_codigo(
    token: str, request: Request, csrf: str = Form(default=""),
    sesion: Session = Depends(obtener_sesion),
):
    acceso = resolver_acceso(token, request, sesion, crear_sesion=False)
    exigir_csrf(acceso, csrf)
    destino = acceso.parte.email or acceso.parte.telefono
    if not destino:
        raise _error("Este firmante no tiene correo ni telefono para enviarle el codigo.")

    limitar(f"otp:{acceso.parte.id}", limite=5, ventana_s=15 * 60)

    codigo = codigo_otp()
    desafio = DesafioOtp(
        tenant_id=acceso.contrato.tenant_id,
        sesion_id=acceso.sesion_firma.id,
        canal="EMAIL" if acceso.parte.email else "SMS",
        destino_enmascarado=enmascarar(destino),
        # Nunca se guarda el codigo en claro.
        codigo_hash=sha256(codigo),
        expira_en=ahora_utc() + timedelta(minutes=ajustes().minutos_otp),
    )
    sesion.add(desafio)
    auditoria.registrar(
        sesion,
        tenant_id=acceso.contrato.tenant_id,
        contrato_id=acceso.contrato.id,
        tipo="OTP_SOLICITADO",
        actor_tipo="FIRMANTE",
        actor_id=acceso.parte.id,
        datos={"canal": desafio.canal, "destino": desafio.destino_enmascarado},
        ip=ip_observada(request),
    )
    sesion.commit()

    # En produccion esto lo envia el proveedor transaccional. En desarrollo se
    # imprime para poder probar el flujo completo sin correo.
    if ajustes().mostrar_secretos_en_log:
        print(f"[DESARROLLO] codigo OTP para {desafio.destino_enmascarado}: {codigo}")

    contexto = _base(request, acceso)
    contexto.update({"enviado": True, "destino": desafio.destino_enmascarado})
    return plantillas.TemplateResponse(request, "identificacion.html", contexto)


@router.post("/{token}/verificar", response_class=HTMLResponse)
def verificar_codigo(
    token: str, request: Request, codigo: str = Form(...), csrf: str = Form(default=""),
    sesion: Session = Depends(obtener_sesion),
):
    acceso = resolver_acceso(token, request, sesion, crear_sesion=False)
    exigir_csrf(acceso, csrf)
    limitar(f"otp-verif:{acceso.parte.id}", limite=10, ventana_s=15 * 60)

    desafio = sesion.scalars(
        select(DesafioOtp)
        .where(DesafioOtp.sesion_id == acceso.sesion_firma.id, DesafioOtp.estado == "PENDIENTE")
        .order_by(DesafioOtp.creado_en.desc())
        .limit(1)
    ).first()

    contexto = _base(request, acceso)
    contexto["enviado"] = True

    if desafio is None or desafio.expira_en <= ahora_utc():
        if desafio is not None:
            desafio.estado = "VENCIDO"
        sesion.commit()
        contexto["error"] = "El codigo vencio. Solicita uno nuevo."
        return plantillas.TemplateResponse(request, "identificacion.html", contexto, status_code=400)

    desafio.intentos += 1
    contexto["destino"] = desafio.destino_enmascarado

    if desafio.intentos > ajustes().intentos_maximos_otp:
        desafio.estado = "AGOTADO"
        auditoria.registrar(
            sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
            tipo="OTP_FALLIDO", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
            datos={"motivo": "intentos agotados"}, ip=ip_observada(request),
        )
        sesion.commit()
        contexto["error"] = "Demasiados intentos. Solicita un codigo nuevo."
        return plantillas.TemplateResponse(request, "identificacion.html", contexto, status_code=429)

    # Comparacion en tiempo constante: con == se podria adivinar el codigo
    # midiendo cuanto tarda la respuesta.
    if not comparar_seguro(sha256(codigo.strip()), desafio.codigo_hash):
        auditoria.registrar(
            sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
            tipo="OTP_FALLIDO", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
            datos={"intento": desafio.intentos}, ip=ip_observada(request),
        )
        sesion.commit()
        contexto["error"] = "El codigo no coincide."
        return plantillas.TemplateResponse(request, "identificacion.html", contexto, status_code=400)

    desafio.estado = "VERIFICADO"
    desafio.verificado_en = ahora_utc()
    acceso.sesion_firma.autenticada = True
    acceso.sesion_firma.metodo_autenticacion = f"OTP_{desafio.canal}"
    auditoria.registrar(
        sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
        tipo="OTP_VERIFICADO", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
        datos={"canal": desafio.canal}, ip=ip_observada(request),
    )
    sesion.commit()
    return RedirectResponse(f"/firma/{token}/documento", status_code=303)


# ---------------------------------------------------------------------------
# Paso 3: leer el documento y firmar
# ---------------------------------------------------------------------------

def _exigir_autenticado(acceso: Acceso) -> None:
    requiere = (acceso.contrato.politica or {}).get("requiere_otp", True)
    if requiere and not acceso.sesion_firma.autenticada:
        raise _error("Primero tienes que identificarte.", status.HTTP_403_FORBIDDEN)


@router.get("/{token}/documento", response_class=HTMLResponse)
def ver_documento(token: str, request: Request, sesion: Session = Depends(obtener_sesion)):
    acceso = resolver_acceso(token, request, sesion, crear_sesion=False)
    _exigir_autenticado(acceso)
    auditoria.registrar(
        sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
        tipo="DOCUMENTO_VISTO", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
        ip=ip_observada(request), agente=request.headers.get("user-agent"),
    )
    sesion.commit()
    contexto = _base(request, acceso)
    contexto["nonce"] = secrets.token_urlsafe(16)
    respuesta = plantillas.TemplateResponse(request, "documento.html", contexto)
    respuesta.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'nonce-{contexto['nonce']}'; "
        "style-src 'self' 'unsafe-inline'; frame-src 'self'; frame-ancestors 'none'"
    )
    return respuesta


@router.get("/{token}/contrato.html", response_class=HTMLResponse)
def contenido_contrato(token: str, request: Request, sesion: Session = Depends(obtener_sesion)):
    """
    El documento en si, para mostrarlo dentro de un iframe aislado.

    Va con sandbox y sin permitir scripts: aunque una plantilla lograra colar
    algo, no podria ejecutarse ni salir del marco.
    """
    acceso = resolver_acceso(token, request, sesion, crear_sesion=False)
    _exigir_autenticado(acceso)
    contenido = almacen.leer(acceso.contrato.clave_documento)
    return Response(
        content=contenido,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/{token}/firmar", response_class=HTMLResponse)
def firmar(
    token: str,
    request: Request,
    csrf: str = Form(default=""),
    acepto: str = Form(default=""),
    latitud: str = Form(default=""),
    longitud: str = Form(default=""),
    precision: str = Form(default=""),
    sesion: Session = Depends(obtener_sesion),
):
    acceso = resolver_acceso(token, request, sesion, crear_sesion=False)
    exigir_csrf(acceso, csrf)
    _exigir_autenticado(acceso)

    politica = acceso.contrato.politica or {}
    contexto = _base(request, acceso)

    if acepto != "si":
        contexto["error"] = "Tienes que aceptar el uso de firma electronica para poder firmar."
        return plantillas.TemplateResponse(request, "documento.html", contexto, status_code=400)

    if latitud and longitud:
        try:
            acceso.sesion_firma.latitud = float(latitud)
            acceso.sesion_firma.longitud = float(longitud)
            acceso.sesion_firma.precision_m = float(precision) if precision else None
            acceso.sesion_firma.ubicacion_en = ahora_utc()
            auditoria.registrar(
                sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
                tipo="UBICACION_CONCEDIDA", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
                ip=ip_observada(request),
            )
        except ValueError:
            pass

    if politica.get("requiere_geolocalizacion") and acceso.sesion_firma.latitud is None:
        auditoria.registrar(
            sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
            tipo="UBICACION_DENEGADA", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
            ip=ip_observada(request),
        )
        sesion.commit()
        contexto["error"] = (
            "Este contrato exige compartir la ubicacion. Permite el acceso en tu navegador "
            "para poder continuar."
        )
        return plantillas.TemplateResponse(request, "documento.html", contexto, status_code=400)

    consentimiento_en = ahora_utc()
    auditoria.registrar(
        sesion, tenant_id=acceso.contrato.tenant_id, contrato_id=acceso.contrato.id,
        tipo="CONSENTIMIENTO_ACEPTADO", actor_tipo="FIRMANTE", actor_id=acceso.parte.id,
        ip=ip_observada(request), agente=request.headers.get("user-agent"),
    )

    try:
        servicio.registrar_firma(
            sesion,
            _contexto_firmante(acceso, request),
            contrato=acceso.contrato,
            parte=acceso.parte,
            sesion_firma=acceso.sesion_firma,
            consentimiento_en=consentimiento_en,
        )
    except ErrorDeNegocio as error:
        sesion.rollback()
        contexto["error"] = str(error)
        return plantillas.TemplateResponse(request, "documento.html", contexto, status_code=409)

    acceso.invitacion.estado = "USADA"
    sesion.commit()
    webhooks.procesar_pendientes()
    return RedirectResponse(f"/firma/{token}/listo", status_code=303)


@router.get("/{token}/listo", response_class=HTMLResponse)
def listo(token: str, request: Request, sesion: Session = Depends(obtener_sesion)):
    invitacion = sesion.scalars(
        select(Invitacion).where(Invitacion.token_hash == hash_de_token(token))
    ).first()
    if invitacion is None:
        raise _error("Este enlace no es valido.", status.HTTP_404_NOT_FOUND)
    contrato = sesion.get(Contrato, invitacion.contrato_id)
    parte = sesion.get(ParteContrato, invitacion.parte_id)
    return plantillas.TemplateResponse(
        request, "listo.html", {"contrato": contrato, "parte": parte}
    )
