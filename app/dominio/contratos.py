"""
Servicio de contratos: el corazon del sistema.

Aqui ocurre el flujo que describe el documento de la propuesta:
crear -> validar -> generar -> congelar -> invitar -> autenticar -> firmar ->
auditar -> completar -> custodiar -> notificar.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.almacenamiento import almacen, nueva_clave
from app.config import ajustes
from app.db import ahora_utc
from app.dominio import auditoria, avisos, documentos, firma_manuscrita, pdf, webhooks
from app.dominio.estados import EVENTO_WEBHOOK, Estado, exigir_transicion
from app.dominio.firma import SolicitudFirma, proveedor_actual
from app.dominio.politica import normalizar as normalizar_politica
from app.dominio.plantillas import sanitizar_cuerpo, validar_coherencia
from app.dominio.variables import DatosInvalidos, validar_schema, validar_valores
from app.models import (
    Contrato,
    Invitacion,
    ParteContrato,
    Plantilla,
    Tenant,
    VersionPlantilla,
    Evidencia,
    Firma,
    SesionFirma,
)
from app.notificaciones import Mensaje
from app.seguridad import hash_de_token, json_canonico, sha256, token_aleatorio

registro = logging.getLogger("contratos")


class ErrorDeNegocio(Exception):
    """Error que es culpa de la peticion, no del servicio."""

    def __init__(self, mensaje: str, detalles: dict | None = None) -> None:
        self.mensaje = mensaje
        self.detalles = detalles or {}
        super().__init__(mensaje)


class NoEncontrado(ErrorDeNegocio):
    """Un recurso ajeno responde esto, no 'prohibido': no confirmamos que exista."""


@dataclass(frozen=True)
class Contexto:
    """Quien actua y desde donde. Viaja a la auditoria y a las evidencias."""

    tenant_id: str
    actor_tipo: str
    actor_id: str | None = None
    ip: str | None = None
    agente: str | None = None


# ---------------------------------------------------------------------------
# Resolucion de plantilla
# ---------------------------------------------------------------------------

def resolver_version(
    sesion: Session, tenant_id: str, referencia: str, version: int | None = None
) -> VersionPlantilla:
    """
    Acepta el codigo de la plantilla ("contrato_servicio"), el codigo con
    sufijo de version ("contrato_servicio_v3") o el id de la plantilla.
    Sin version explicita, devuelve la ultima publicada.
    """
    texto = referencia.strip()
    pedida = version
    if pedida is None and "_v" in texto:
        base, _, sufijo = texto.rpartition("_v")
        if sufijo.isdigit():
            texto, pedida = base, int(sufijo)

    consulta = (
        select(VersionPlantilla)
        .join(Plantilla, Plantilla.id == VersionPlantilla.plantilla_id)
        .where(
            VersionPlantilla.tenant_id == tenant_id,
            VersionPlantilla.estado == "PUBLICADA",
            (Plantilla.codigo == texto) | (Plantilla.id == texto),
        )
        .order_by(VersionPlantilla.version.desc())
    )
    if pedida is not None:
        consulta = consulta.where(VersionPlantilla.version == pedida)

    encontrada = sesion.scalars(consulta.limit(1)).first()
    if encontrada is None:
        detalle = f"version {pedida} de " if pedida is not None else ""
        raise ErrorDeNegocio(f"No hay una {detalle}la plantilla publicada: {referencia}")
    return encontrada


def publicar_plantilla(
    sesion: Session,
    tenant_id: str,
    *,
    codigo: str,
    nombre: str,
    titulo: str,
    cuerpo: str,
    schema_variables: dict,
    politica: dict | None = None,
) -> tuple[Plantilla, VersionPlantilla]:
    """
    Crea la plantilla si no existe y publica una version nueva e inmutable.
    Lanza DatosInvalidos o PlantillaInvalida con el detalle de lo que falla.
    """
    schema = validar_schema(schema_variables)
    cuerpo = sanitizar_cuerpo(cuerpo)

    plantilla = sesion.scalars(
        select(Plantilla).where(Plantilla.tenant_id == tenant_id, Plantilla.codigo == codigo)
    ).first()
    if plantilla is None:
        plantilla = Plantilla(tenant_id=tenant_id, codigo=codigo, nombre=nombre)
        sesion.add(plantilla)
        sesion.flush()

    ultima = sesion.scalars(
        select(VersionPlantilla)
        .where(
            VersionPlantilla.tenant_id == tenant_id,
            VersionPlantilla.plantilla_id == plantilla.id,
        )
        .order_by(VersionPlantilla.version.desc())
        .limit(1)
    ).first()

    politica = normalizar_politica(politica)
    numero = (ultima.version if ultima else 0) + 1
    version = VersionPlantilla(
        tenant_id=tenant_id,
        plantilla_id=plantilla.id,
        version=numero,
        titulo=titulo,
        cuerpo=cuerpo,
        schema_variables=schema,
        politica=politica,
        hash_contenido=sha256(
            json_canonico(
                {"cuerpo": cuerpo, "schema": schema, "politica": politica,
                 "titulo": titulo, "version": numero}
            )
        ),
    )
    sesion.add(version)
    sesion.flush()
    publicar_version(sesion, version)
    return plantilla, version


def publicar_version(sesion: Session, version: VersionPlantilla) -> VersionPlantilla:
    """Antes de publicar se comprueba que plantilla y schema sean coherentes."""
    validar_coherencia(version.cuerpo, version.schema_variables)
    version.estado = "PUBLICADA"
    version.publicada_en = ahora_utc()
    sesion.flush()
    return version


# ---------------------------------------------------------------------------
# Creacion
# ---------------------------------------------------------------------------

def crear_contrato(
    sesion: Session,
    ctx: Contexto,
    *,
    plantilla: str,
    firmantes: list[dict],
    variables: dict,
    referencia_externa: str | None = None,
    version: int | None = None,
    enviar_ahora: bool = True,
) -> Contrato:
    tenant = sesion.get(Tenant, ctx.tenant_id)
    if tenant is None:
        raise NoEncontrado("Empresa no encontrada")

    version_plantilla = resolver_version(sesion, ctx.tenant_id, plantilla, version)
    schema = version_plantilla.schema_variables or {}

    # Lista blanca: lo que no esta declarado en la plantilla se rechaza.
    valores = validar_valores(schema, variables)

    clientes = [f for f in firmantes if (f.get("rol") or "CLIENTE").upper() == "CLIENTE"]
    if len(clientes) != 1:
        raise ErrorDeNegocio("Debe haber exactamente un firmante con rol CLIENTE")

    politica = normalizar_politica(version_plantilla.politica)
    empresa = [f for f in firmantes if (f.get("rol") or "").upper() == "EMPRESA"]
    if politica["requiere_firma_empresa"] and not empresa:
        raise ErrorDeNegocio(
            "Esta plantilla exige firma de la empresa: falta un firmante con rol EMPRESA"
        )

    contrato = Contrato(
        tenant_id=ctx.tenant_id,
        plantilla_id=version_plantilla.plantilla_id,
        version_plantilla_id=version_plantilla.id,
        numero_version=version_plantilla.version,
        referencia_externa=referencia_externa,
        titulo=version_plantilla.titulo,
        estado=Estado.CREADO.value,
        variables={},
        variables_canonicas="",
        hash_variables="",
        clave_documento="",
        hash_documento="",
        politica=politica,
        credencial_id=ctx.actor_id if ctx.actor_tipo == "CREDENCIAL" else None,
        expira_en=ahora_utc() + timedelta(hours=politica["horas_vigencia"]),
    )
    sesion.add(contrato)
    sesion.flush()

    orden = 0
    partes_doc: list[dict] = []
    for firmante in clientes + empresa:
        parte = ParteContrato(
            tenant_id=ctx.tenant_id,
            contrato_id=contrato.id,
            rol=(firmante.get("rol") or "CLIENTE").upper(),
            orden=orden,
            nombre=str(firmante["nombre"]).strip(),
            documento=firmante.get("documento"),
            email=(firmante.get("email") or "").strip().lower() or None,
            telefono=firmante.get("telefono"),
        )
        sesion.add(parte)
        partes_doc.append({"rol": parte.rol, "nombre": parte.nombre, "documento": parte.documento})
        orden += 1
    sesion.flush()

    # --- Congelado: variables canonicas, documento generado y sus hashes ---
    canonico, hash_variables = documentos.hash_de_variables(valores)
    contexto_doc = {
        "id": contrato.id,
        "fecha": documentos.iso(contrato.creado_en) or "",
        "referencia": referencia_externa or "",
    }
    html = documentos.construir_documento(
        titulo=version_plantilla.titulo,
        cuerpo_plantilla=version_plantilla.cuerpo,
        schema=schema,
        valores=valores,
        partes=partes_doc,
        contexto=contexto_doc,
        tenant_nombre=tenant.nombre,
        plantilla_codigo=version_plantilla.plantilla.codigo,
        numero_version=version_plantilla.version,
    )
    generado = documentos.generar(html)
    clave = nueva_clave(ctx.tenant_id, contrato.id, "contrato.html")
    almacen.guardar(clave, generado.bytes_)

    contrato.variables = {k: str(v) for k, v in valores.items()}
    contrato.variables_canonicas = canonico
    contrato.hash_variables = hash_variables
    contrato.clave_documento = clave
    contrato.hash_documento = generado.hash

    auditoria.registrar(
        sesion,
        tenant_id=ctx.tenant_id,
        contrato_id=contrato.id,
        tipo="CONTRATO_CREADO",
        actor_tipo=ctx.actor_tipo,
        actor_id=ctx.actor_id,
        datos={
            "plantilla": version_plantilla.plantilla.codigo,
            "version": version_plantilla.version,
            "hash_variables": hash_variables,
            "hash_documento": generado.hash,
            "referencia_externa": referencia_externa,
        },
        ip=ctx.ip,
        agente=ctx.agente,
    )
    sesion.flush()

    if enviar_ahora:
        # La URL de firma solo existe en este instante: en la base guardamos el
        # hash del token, no el token. Se adjunta al objeto para que la capa
        # HTTP pueda devolverla en la respuesta de creacion y nada mas.
        contrato.url_firma_recien_creada = enviar(sesion, ctx, contrato)
    return contrato


# ---------------------------------------------------------------------------
# Envio e invitaciones
# ---------------------------------------------------------------------------

def parte_pendiente(sesion: Session, contrato: Contrato) -> ParteContrato | None:
    """La siguiente parte que debe firmar, en orden: primero cliente, luego empresa."""
    return sesion.scalars(
        select(ParteContrato)
        .where(
            ParteContrato.tenant_id == contrato.tenant_id,
            ParteContrato.contrato_id == contrato.id,
            ParteContrato.estado == "PENDIENTE",
        )
        .order_by(ParteContrato.orden)
        .limit(1)
    ).first()


def enviar(sesion: Session, ctx: Contexto, contrato: Contrato) -> str:
    """Crea la invitacion de la parte que toca y devuelve su URL de firma."""
    if esta_vencido(contrato):
        raise ErrorDeNegocio("El contrato ya vencio: no se pueden enviar invitaciones nuevas")
    parte = parte_pendiente(sesion, contrato)
    if parte is None:
        raise ErrorDeNegocio("No queda ninguna parte pendiente de firma")

    destino = (
        Estado.PENDIENTE_CLIENTE if parte.rol == "CLIENTE" else Estado.PENDIENTE_EMPRESA
    )
    if contrato.estado != destino.value:
        exigir_transicion(Estado(contrato.estado), destino)
        contrato.estado = destino.value
    if contrato.enviado_en is None:
        contrato.enviado_en = ahora_utc()

    # Revocar invitaciones previas de esa parte: solo una activa a la vez.
    for previa in sesion.scalars(
        select(Invitacion).where(
            Invitacion.tenant_id == contrato.tenant_id,
            Invitacion.parte_id == parte.id,
            Invitacion.estado == "ACTIVA",
        )
    ):
        previa.estado = "REVOCADA"

    token = token_aleatorio(32)
    invitacion = Invitacion(
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        parte_id=parte.id,
        token_hash=hash_de_token(token),
        expira_en=ahora_utc() + timedelta(minutes=ajustes().minutos_invitacion),
    )
    sesion.add(invitacion)
    url = url_de_firma(token)

    aviso = None
    if (contrato.politica or {}).get("notificar_invitaciones", True):
        aviso = _avisar_invitacion(sesion, contrato, parte, url, invitacion.expira_en)

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="INVITACION_CREADA",
        actor_tipo=ctx.actor_tipo,
        actor_id=ctx.actor_id,
        datos={"parte": parte.id, "rol": parte.rol, "aviso": aviso},
        ip=ctx.ip,
        agente=ctx.agente,
    )

    if parte.rol == "CLIENTE":
        webhooks.encolar(
            sesion,
            tenant_id=contrato.tenant_id,
            evento="contract.sent",
            contrato_id=contrato.id,
            datos={
                "status": contrato.estado,
                "external_reference": contrato.referencia_externa,
            },
        )
    sesion.flush()
    return url


def url_de_firma(token: str) -> str:
    return f"{ajustes().url_publica.rstrip('/')}/firma/{token}"


def _avisar_invitacion(
    sesion: Session, contrato: Contrato, parte: ParteContrato, url: str, expira_en
) -> str | None:
    """
    Le manda el enlace al firmante y devuelve por que canal.

    El enlace del representante de la empresa se crea en el momento en que
    firma el cliente; sin este aviso solo podria recuperarse reenviando por la
    API. El aviso se guarda en esta misma transaccion y sale despues (ver
    dominio/avisos.py).
    """
    if parte.email:
        canal, destino = "EMAIL", parte.email
    elif parte.telefono:
        canal, destino = "SMS", parte.telefono
    else:
        return None

    tenant = sesion.get(Tenant, contrato.tenant_id)
    emisor = tenant.nombre if tenant else "La empresa"
    vence = expira_en.strftime("%d/%m/%Y %H:%M UTC")
    if canal == "SMS":
        texto = f"{emisor} te envio un documento para firmar: {url} (vence el {vence})"
    else:
        texto = (
            f"Hola {parte.nombre}:\n\n"
            f"{emisor} te envio \"{contrato.titulo}\" para que lo revises y lo firmes "
            f"electronicamente.\n\n{url}\n\n"
            f"El enlace es personal y vence el {vence}. Si no esperabas este mensaje, "
            "ignoralo."
        )
    avisos.encolar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        mensaje=Mensaje(canal=canal, destino=destino,
                        asunto=f"Documento para firmar: {contrato.titulo}", texto=texto),
    )
    return canal


# ---------------------------------------------------------------------------
# Firma
# ---------------------------------------------------------------------------

def registrar_firma(
    sesion: Session,
    ctx: Contexto,
    *,
    contrato: Contrato,
    parte: ParteContrato,
    sesion_firma: SesionFirma,
    consentimiento_en,
    trazos_firma: dict,
) -> Firma:
    """
    Registra la firma de una parte: arma la evidencia, la sella con el proveedor
    de firma y hace avanzar el contrato.

    trazos_firma es la firma que dibujo el firmante, ya validada
    (firma_manuscrita.validar). Entra en la evidencia ANTES de sellarla: la firma
    criptografica cubre tambien ese dibujo.
    """
    if parte.estado != "PENDIENTE":
        raise ErrorDeNegocio("Esta parte ya firmo o rechazo el contrato")

    firmado_en = ahora_utc()
    datos_evidencia = {
        "rol": parte.rol,
        "nombre": parte.nombre,
        "documento": parte.documento,
        "email": parte.email,
        "telefono": parte.telefono,
        "metodo_autenticacion": sesion_firma.metodo_autenticacion,
        "ip": sesion_firma.ip,
        "agente": sesion_firma.agente,
        "latitud": sesion_firma.latitud,
        "longitud": sesion_firma.longitud,
        "precision_m": sesion_firma.precision_m,
        "ubicacion_en": documentos.iso(sesion_firma.ubicacion_en),
        "consentimiento_en": documentos.iso(consentimiento_en),
        "firma_manuscrita": trazos_firma,
        "firma_manuscrita_hash": firma_manuscrita.hash_de(trazos_firma),
        "firmado_en": documentos.iso(firmado_en),
        "hash_documento_al_firmar": contrato.hash_documento,
        "plantilla_version": contrato.numero_version,
    }
    hash_evidencia = sha256(json_canonico(datos_evidencia))

    solicitud = SolicitudFirma(
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        parte_id=parte.id,
        hash_documento=contrato.hash_documento,
        hash_evidencia=hash_evidencia,
        nombre=parte.nombre,
        documento=parte.documento,
        rol=parte.rol,
        firmado_en=firmado_en,
    )
    resultado = proveedor_actual.firmar(solicitud)
    datos_evidencia["firma"] = resultado.valor
    datos_evidencia["algoritmo"] = resultado.algoritmo

    evidencia = Evidencia(
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        parte_id=parte.id,
        datos=datos_evidencia,
        hash_evidencia=hash_evidencia,
    )
    sesion.add(evidencia)
    sesion.flush()

    firma = Firma(
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        parte_id=parte.id,
        evidencia_id=evidencia.id,
        proveedor=resultado.proveedor,
        algoritmo=resultado.algoritmo,
        valor=resultado.valor,
        hash_documento_al_firmar=contrato.hash_documento,
        firmado_en=firmado_en,
    )
    sesion.add(firma)

    parte.estado = "FIRMADA"
    parte.firmado_en = firmado_en

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="FIRMADO",
        actor_tipo="FIRMANTE",
        actor_id=parte.id,
        datos={"rol": parte.rol, "hash_evidencia": hash_evidencia},
        ip=ctx.ip,
        agente=ctx.agente,
    )

    webhooks.encolar(
        sesion,
        tenant_id=contrato.tenant_id,
        evento="contract.client_signed" if parte.rol == "CLIENTE" else "contract.company_signed",
        contrato_id=contrato.id,
        datos={"status": contrato.estado, "external_reference": contrato.referencia_externa},
    )

    siguiente = parte_pendiente(sesion, contrato)
    if siguiente is None:
        completar(sesion, ctx, contrato)
    else:
        enviar(sesion, ctx, contrato)
    sesion.flush()
    return firma


def completar(sesion: Session, ctx: Contexto, contrato: Contrato) -> None:
    """Genera el documento final con la constancia y cierra el contrato."""
    exigir_transicion(Estado(contrato.estado), Estado.COMPLETADO)
    contrato.estado = Estado.COMPLETADO.value
    contrato.completado_en = ahora_utc()

    evidencias = sesion.scalars(
        select(Evidencia).where(
            Evidencia.tenant_id == contrato.tenant_id,
            Evidencia.contrato_id == contrato.id,
        ).order_by(Evidencia.creada_en)
    ).all()
    eventos = auditoria.listar(sesion, contrato.tenant_id, contrato.id)

    plantilla = sesion.get(Plantilla, contrato.plantilla_id)
    constancia = documentos.construir_constancia(
        contrato={
            "id": contrato.id,
            "titulo": contrato.titulo,
            "referencia_externa": contrato.referencia_externa,
            "plantilla_codigo": plantilla.codigo if plantilla else "",
            "numero_version": contrato.numero_version,
            "hash_variables": contrato.hash_variables,
            "hash_documento": contrato.hash_documento,
            "creado_en": documentos.iso(contrato.creado_en),
            "completado_en": documentos.iso(contrato.completado_en),
        },
        evidencias=[{"datos": e.datos} for e in evidencias],
        eventos=[
            {
                "secuencia": e.secuencia,
                "tipo": e.tipo,
                "creado_en": documentos.iso(e.creado_en) or "",
                "actor_tipo": e.actor_tipo,
                "hash": e.hash,
            }
            for e in eventos
        ],
    )
    html_original = almacen.leer(contrato.clave_documento).decode("utf-8")
    final = documentos.generar(documentos.componer_documento_final(html_original, constancia))
    clave_final = nueva_clave(contrato.tenant_id, contrato.id, "final.html")
    almacen.guardar(clave_final, final.bytes_)

    contrato.clave_documento_final = clave_final
    contrato.hash_documento_final = final.hash
    hash_pdf = _emitir_pdf(sesion, contrato, final.html)

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="COMPLETADO",
        actor_tipo="SISTEMA",
        datos={"hash_documento_final": final.hash, "hash_documento_final_pdf": hash_pdf},
    )
    webhooks.encolar(
        sesion,
        tenant_id=contrato.tenant_id,
        evento=EVENTO_WEBHOOK[Estado.COMPLETADO],
        contrato_id=contrato.id,
        datos={
            "status": contrato.estado,
            "external_reference": contrato.referencia_externa,
            "document_hash": final.hash,
            "document_pdf_hash": hash_pdf,
        },
    )


def _emitir_pdf(sesion: Session, contrato: Contrato, html_final: str) -> str | None:
    """
    Guarda la version PDF del documento final y devuelve su hash.

    Si la conversion falla, el contrato se completa igual y queda constancia
    en la auditoria: el documento de referencia es el HTML, y perder firmas
    ya hechas por un problema de maquetacion seria mucho peor.
    """
    try:
        datos = pdf.html_a_pdf(html_final, titulo=contrato.titulo)
    except Exception:
        registro.exception("no se pudo generar el PDF del contrato %s", contrato.id)
        auditoria.registrar(
            sesion,
            tenant_id=contrato.tenant_id,
            contrato_id=contrato.id,
            tipo="PDF_NO_GENERADO",
            actor_tipo="SISTEMA",
        )
        return None
    clave = nueva_clave(contrato.tenant_id, contrato.id, "final.pdf")
    almacen.guardar(clave, datos)
    contrato.clave_documento_final_pdf = clave
    contrato.hash_documento_final_pdf = sha256(datos)
    return contrato.hash_documento_final_pdf


def rechazar(
    sesion: Session,
    ctx: Contexto,
    *,
    contrato: Contrato,
    parte: ParteContrato,
    motivo: str | None,
) -> None:
    """
    El firmante declina firmar. Cierra el contrato para todas las partes: un
    contrato que una de ellas rechazo ya no puede completarse.
    """
    if parte.estado != "PENDIENTE":
        raise ErrorDeNegocio("Esta parte ya firmo o rechazo el contrato")
    exigir_transicion(Estado(contrato.estado), Estado.RECHAZADO)

    texto = (motivo or "").strip()[:300] or None
    parte.estado = "RECHAZADA"
    parte.motivo_rechazo = texto
    contrato.estado = Estado.RECHAZADO.value
    _revocar_invitaciones(sesion, contrato)

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="RECHAZADO",
        actor_tipo="FIRMANTE",
        actor_id=parte.id,
        datos={"rol": parte.rol, "motivo": texto},
        ip=ctx.ip,
        agente=ctx.agente,
    )
    webhooks.encolar(
        sesion,
        tenant_id=contrato.tenant_id,
        evento=EVENTO_WEBHOOK[Estado.RECHAZADO],
        contrato_id=contrato.id,
        datos={
            "status": contrato.estado,
            "external_reference": contrato.referencia_externa,
            "declined_by": parte.rol,
            "reason": texto,
        },
    )
    sesion.flush()


def _revocar_invitaciones(sesion: Session, contrato: Contrato) -> None:
    """Un contrato cerrado no deja enlaces de firma vivos."""
    for invitacion in sesion.scalars(
        select(Invitacion).where(
            Invitacion.tenant_id == contrato.tenant_id,
            Invitacion.contrato_id == contrato.id,
            Invitacion.estado == "ACTIVA",
        )
    ):
        invitacion.estado = "REVOCADA"


def anular(sesion: Session, ctx: Contexto, contrato: Contrato, motivo: str | None) -> None:
    exigir_transicion(Estado(contrato.estado), Estado.ANULADO)
    contrato.estado = Estado.ANULADO.value
    contrato.anulado_en = ahora_utc()
    contrato.motivo_anulacion = (motivo or "")[:300] or None
    _revocar_invitaciones(sesion, contrato)

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="ANULADO",
        actor_tipo=ctx.actor_tipo,
        actor_id=ctx.actor_id,
        datos={"motivo": contrato.motivo_anulacion},
        ip=ctx.ip,
        agente=ctx.agente,
    )
    webhooks.encolar(
        sesion,
        tenant_id=contrato.tenant_id,
        evento=EVENTO_WEBHOOK[Estado.ANULADO],
        contrato_id=contrato.id,
        datos={"status": contrato.estado, "external_reference": contrato.referencia_externa},
    )
    sesion.flush()


# ---------------------------------------------------------------------------
# Vencimiento
# ---------------------------------------------------------------------------

# Solo vencen los contratos que todavia esperan al cliente. Una vez que el
# cliente firmo, la maquina de estados no admite VENCIDO: el contrato queda a
# la espera de la empresa, que es parte interesada y no deberia perderlo.
ESTADOS_QUE_VENCEN = (Estado.CREADO.value, Estado.PENDIENTE_CLIENTE.value)


def esta_vencido(contrato: Contrato, ahora=None) -> bool:
    """Si ya paso su vigencia, aunque la tarea periodica aun no lo haya marcado."""
    return (
        contrato.estado in ESTADOS_QUE_VENCEN
        and contrato.expira_en is not None
        and contrato.expira_en <= (ahora or ahora_utc())
    )


def vencer(sesion: Session, contrato: Contrato) -> None:
    """Cierra el contrato por vencimiento y revoca sus enlaces de firma."""
    exigir_transicion(Estado(contrato.estado), Estado.VENCIDO)
    contrato.estado = Estado.VENCIDO.value
    _revocar_invitaciones(sesion, contrato)

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="VENCIDO",
        actor_tipo="SISTEMA",
        datos={"expira_en": documentos.iso(contrato.expira_en)},
    )
    webhooks.encolar(
        sesion,
        tenant_id=contrato.tenant_id,
        evento=EVENTO_WEBHOOK[Estado.VENCIDO],
        contrato_id=contrato.id,
        datos={"status": contrato.estado, "external_reference": contrato.referencia_externa},
    )
    sesion.flush()


def vencer_pendientes(sesion: Session, ahora=None, limite: int = 200) -> int:
    """
    Marca como vencidos los contratos cuya vigencia ya paso.

    Es una tarea de sistema: recorre todas las empresas, pero cada contrato se
    cierra con su propio tenant_id en la auditoria y en los webhooks. Procesa
    por lotes para no bloquear la base si se acumularon muchos.
    """
    momento = ahora or ahora_utc()
    candidatos = sesion.scalars(
        select(Contrato)
        .where(
            Contrato.estado.in_(ESTADOS_QUE_VENCEN),
            Contrato.expira_en.is_not(None),
            Contrato.expira_en <= momento,
        )
        .order_by(Contrato.expira_en)
        .limit(limite)
    ).all()
    for contrato in candidatos:
        vencer(sesion, contrato)
    return len(candidatos)


def obtener(sesion: Session, tenant_id: str, contrato_id: str) -> Contrato:
    """
    SIEMPRE filtra por tenant. Un contrato de otra empresa responde "no
    encontrado", no "prohibido": no confirmamos ni que exista.
    """
    contrato = sesion.scalars(
        select(Contrato).where(
            Contrato.tenant_id == tenant_id, Contrato.id == contrato_id
        )
    ).first()
    if contrato is None:
        raise NoEncontrado("Contrato no encontrado")
    return contrato


def listar(
    sesion: Session,
    tenant_id: str,
    *,
    estado: str | None = None,
    estados: tuple[str, ...] | None = None,
    referencia_externa: str | None = None,
    creado_desde: datetime | None = None,
    creado_hasta: datetime | None = None,
    despues_de: tuple[datetime, str] | None = None,
    limite: int = 50,
) -> list[Contrato]:
    """
    Contratos de la empresa, del mas nuevo al mas viejo.

    Pagina por cursor (fecha de creacion + id) y no por desplazamiento: si
    entran contratos nuevos mientras el integrador recorre las paginas, no se
    le repiten ni se le saltan filas.
    """
    consulta = select(Contrato).where(Contrato.tenant_id == tenant_id)
    if estado:
        consulta = consulta.where(Contrato.estado == estado)
    if estados:
        consulta = consulta.where(Contrato.estado.in_(estados))
    if referencia_externa:
        consulta = consulta.where(Contrato.referencia_externa == referencia_externa)
    if creado_desde:
        consulta = consulta.where(Contrato.creado_en >= creado_desde)
    if creado_hasta:
        consulta = consulta.where(Contrato.creado_en < creado_hasta)
    if despues_de:
        fecha, ultimo_id = despues_de
        consulta = consulta.where(
            or_(
                Contrato.creado_en < fecha,
                and_(Contrato.creado_en == fecha, Contrato.id < ultimo_id),
            )
        )
    return list(
        sesion.scalars(
            consulta.order_by(Contrato.creado_en.desc(), Contrato.id.desc()).limit(limite)
        )
    )


def cursor_de(contrato: Contrato) -> str:
    """El cursor que apunta justo despues de este contrato en el listado."""
    crudo = json.dumps({"c": contrato.creado_en.isoformat(), "i": contrato.id})
    return base64.urlsafe_b64encode(crudo.encode()).decode().rstrip("=")


def leer_cursor(cursor: str) -> tuple[datetime, str]:
    """Lanza ValueError si el cursor no es uno que hayamos emitido."""
    try:
        relleno = "=" * (-len(cursor) % 4)
        datos = json.loads(base64.urlsafe_b64decode(cursor + relleno))
        fecha = datetime.fromisoformat(datos["c"])
        identificador = str(datos["i"])
    except (ValueError, KeyError, TypeError) as error:
        raise ValueError("El cursor no es valido") from error
    if fecha.tzinfo is None:
        raise ValueError("El cursor no es valido")
    return fecha, identificador


def contar_por_estado(sesion: Session, tenant_id: str) -> dict[str, int]:
    filas = sesion.execute(
        select(Contrato.estado, func.count())
        .where(Contrato.tenant_id == tenant_id)
        .group_by(Contrato.estado)
    )
    return {estado: cuantos for estado, cuantos in filas}


def resumen_json(contrato: Contrato) -> dict[str, Any]:
    """La version corta de como_json, para listados: sin firmantes."""
    return {
        "contract_id": contrato.id,
        "status": contrato.estado,
        "title": contrato.titulo,
        "external_reference": contrato.referencia_externa,
        "template_version": contrato.numero_version,
        "created_at": documentos.iso(contrato.creado_en),
        "sent_at": documentos.iso(contrato.enviado_en),
        "completed_at": documentos.iso(contrato.completado_en),
        "expires_at": documentos.iso(contrato.expira_en),
    }


def como_json(sesion: Session, contrato: Contrato) -> dict[str, Any]:
    partes = sesion.scalars(
        select(ParteContrato)
        .where(
            ParteContrato.tenant_id == contrato.tenant_id,
            ParteContrato.contrato_id == contrato.id,
        )
        .order_by(ParteContrato.orden)
    ).all()
    return {
        "contract_id": contrato.id,
        "status": contrato.estado,
        "title": contrato.titulo,
        "external_reference": contrato.referencia_externa,
        "template_version": contrato.numero_version,
        "variables_hash": contrato.hash_variables,
        "document_hash": contrato.hash_documento,
        "final_document_hash": contrato.hash_documento_final,
        "final_document_pdf_hash": contrato.hash_documento_final_pdf,
        "created_at": documentos.iso(contrato.creado_en),
        "sent_at": documentos.iso(contrato.enviado_en),
        "completed_at": documentos.iso(contrato.completado_en),
        "expires_at": documentos.iso(contrato.expira_en),
        "signers": [
            {
                "role": p.rol,
                "name": p.nombre,
                "document": p.documento,
                "email": p.email,
                "status": p.estado,
                "signed_at": documentos.iso(p.firmado_en),
                "decline_reason": p.motivo_rechazo,
            }
            for p in partes
        ],
    }
