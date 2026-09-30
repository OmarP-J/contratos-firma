"""
Servicio de contratos: el corazon del sistema.

Aqui ocurre el flujo que describe el documento de la propuesta:
crear -> validar -> generar -> congelar -> invitar -> autenticar -> firmar ->
auditar -> completar -> custodiar -> notificar.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.almacenamiento import almacen, nueva_clave
from app.config import ajustes
from app.db import ahora_utc
from app.dominio import auditoria, documentos, webhooks
from app.dominio.estados import EVENTO_WEBHOOK, Estado, exigir_transicion
from app.dominio.firma import SolicitudFirma, proveedor_actual
from app.dominio.politica import normalizar as normalizar_politica
from app.dominio.plantillas import validar_coherencia
from app.dominio.variables import DatosInvalidos, validar_valores
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
from app.seguridad import hash_de_token, json_canonico, sha256, token_aleatorio


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

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="INVITACION_CREADA",
        actor_tipo=ctx.actor_tipo,
        actor_id=ctx.actor_id,
        datos={"parte": parte.id, "rol": parte.rol},
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
    return url_de_firma(token)


def url_de_firma(token: str) -> str:
    return f"{ajustes().url_publica.rstrip('/')}/firma/{token}"


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
) -> Firma:
    """
    Registra la firma de una parte: arma la evidencia, la sella con el proveedor
    de firma y hace avanzar el contrato.
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

    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="COMPLETADO",
        actor_tipo="SISTEMA",
        datos={"hash_documento_final": final.hash},
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
        },
    )


def anular(sesion: Session, ctx: Contexto, contrato: Contrato, motivo: str | None) -> None:
    exigir_transicion(Estado(contrato.estado), Estado.ANULADO)
    contrato.estado = Estado.ANULADO.value
    contrato.anulado_en = ahora_utc()
    contrato.motivo_anulacion = (motivo or "")[:300] or None

    for invitacion in sesion.scalars(
        select(Invitacion).where(
            Invitacion.tenant_id == contrato.tenant_id,
            Invitacion.contrato_id == contrato.id,
            Invitacion.estado == "ACTIVA",
        )
    ):
        invitacion.estado = "REVOCADA"

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
            }
            for p in partes
        ],
    }
