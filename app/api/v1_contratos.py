"""
API B2B.

Para el integrador el producto se siente asi: crear contrato -> obtener URL de
firma -> esperar webhook -> descargar documento final. Toda la complejidad vive
del lado de aca.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import obtener_sesion
from app.dependencias import (
    CredencialAutenticada,
    contexto_b2b,
    exigir_permiso,
    ip_observada,
    limitar,
)
from app.dominio import auditoria, contratos as servicio, webhooks
from app.dominio.contratos import ErrorDeNegocio, NoEncontrado
from app.dominio.estados import TransicionInvalida
from app.dominio.plantillas import PlantillaInvalida, sanitizar_cuerpo
from app.dominio.variables import DatosInvalidos, validar_schema
from app.almacenamiento import almacen
from app.models import ClaveIdempotencia, Plantilla, VersionPlantilla
from app.schemas import AnularContrato, CrearContrato, CrearPlantilla, RegistrarWebhook
from app.seguridad import json_canonico, sha256

router = APIRouter(prefix="/v1", tags=["b2b"])


@router.post("/contratos", status_code=status.HTTP_201_CREATED)
def crear_contrato(
    peticion: CrearContrato,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:crear")),
    sesion: Session = Depends(obtener_sesion),
):
    limitar(f"crear:{credencial.tenant_id}", limite=60, ventana_s=60)
    ctx = contexto_b2b(request, credencial)
    hash_peticion = sha256(json_canonico(peticion.model_dump(mode="json")))

    # --- Idempotencia: si el integrador reintenta por un timeout, devolvemos
    # --- el contrato que ya se creo en vez de duplicarlo.
    if idempotency_key:
        previa = sesion.scalars(
            select(ClaveIdempotencia).where(
                ClaveIdempotencia.tenant_id == credencial.tenant_id,
                ClaveIdempotencia.credencial_id == credencial.id,
                ClaveIdempotencia.clave == idempotency_key,
            )
        ).first()
        if previa is not None:
            if previa.hash_peticion != hash_peticion:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "error": "conflicto",
                        "mensaje": "Esa Idempotency-Key ya se uso con un cuerpo distinto",
                    },
                )
            response.status_code = previa.codigo_respuesta
            response.headers["Idempotent-Replay"] = "true"
            return previa.cuerpo_respuesta

    try:
        contrato = servicio.crear_contrato(
            sesion,
            ctx,
            plantilla=peticion.plantilla,
            version=peticion.version,
            referencia_externa=peticion.referencia_externa,
            firmantes=[f.model_dump() for f in peticion.firmantes],
            variables=peticion.variables,
            enviar_ahora=peticion.enviar_ahora,
        )
    except DatosInvalidos as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "variables_invalidas",
                "mensaje": "Hay variables invalidas o no declaradas en la plantilla",
                "detalles": error.detalles,
            },
        ) from error
    except (ErrorDeNegocio, PlantillaInvalida) as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "solicitud_invalida", "mensaje": str(error)},
        ) from error

    cuerpo = servicio.como_json(sesion, contrato)
    if peticion.enviar_ahora:
        invitacion_url = _url_firma_actual(contrato)
        if invitacion_url:
            cuerpo["signing_url"] = invitacion_url

    if idempotency_key:
        sesion.add(
            ClaveIdempotencia(
                tenant_id=credencial.tenant_id,
                credencial_id=credencial.id,
                clave=idempotency_key,
                hash_peticion=hash_peticion,
                codigo_respuesta=status.HTTP_201_CREATED,
                cuerpo_respuesta=cuerpo,
            )
        )
    sesion.commit()
    webhooks.procesar_pendientes()
    return cuerpo


def _url_firma_actual(contrato) -> str | None:
    """
    La URL de firma solo existe en el momento de crearla: en la base guardamos
    el hash del token, no el token. Por eso se devuelve aqui y no se puede
    recuperar despues; para reenviarla hay que generar una invitacion nueva.
    """
    return getattr(contrato, "url_firma_recien_creada", None)


@router.get("/contratos/{contrato_id}")
def obtener_contrato(
    contrato_id: str,
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:leer")),
    sesion: Session = Depends(obtener_sesion),
):
    # obtener() filtra por tenant: un contrato ajeno responde 404, no 403.
    contrato = servicio.obtener(sesion, credencial.tenant_id, contrato_id)
    return servicio.como_json(sesion, contrato)


@router.post("/contratos/{contrato_id}/anular")
def anular_contrato(
    contrato_id: str,
    peticion: AnularContrato,
    request: Request,
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:anular")),
    sesion: Session = Depends(obtener_sesion),
):
    contrato = servicio.obtener(sesion, credencial.tenant_id, contrato_id)
    try:
        servicio.anular(sesion, contexto_b2b(request, credencial), contrato, peticion.motivo)
    except TransicionInvalida as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "estado_invalido", "mensaje": str(error)},
        ) from error
    sesion.commit()
    webhooks.procesar_pendientes()
    return servicio.como_json(sesion, contrato)


@router.post("/contratos/{contrato_id}/reenviar")
def reenviar_invitacion(
    contrato_id: str,
    request: Request,
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:crear")),
    sesion: Session = Depends(obtener_sesion),
):
    """
    Genera una invitacion nueva para la parte que toca firmar y devuelve su URL.

    Es la unica forma de recuperar un enlace de firma: el token original no se
    guarda, solo su hash. Reenviar revoca la invitacion anterior.
    """
    contrato = servicio.obtener(sesion, credencial.tenant_id, contrato_id)
    try:
        url = servicio.enviar(sesion, contexto_b2b(request, credencial), contrato)
    except (ErrorDeNegocio, TransicionInvalida) as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "estado_invalido", "mensaje": str(error)},
        ) from error
    sesion.commit()
    webhooks.procesar_pendientes()
    cuerpo = servicio.como_json(sesion, contrato)
    cuerpo["signing_url"] = url
    return cuerpo


@router.get("/contratos/{contrato_id}/documento")
def descargar_documento(
    contrato_id: str,
    request: Request,
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:descargar")),
    sesion: Session = Depends(obtener_sesion),
):
    limitar(f"descarga:{credencial.tenant_id}", limite=60, ventana_s=60)
    contrato = servicio.obtener(sesion, credencial.tenant_id, contrato_id)
    clave = contrato.clave_documento_final or contrato.clave_documento
    contenido = almacen.leer(clave)
    auditoria.registrar(
        sesion,
        tenant_id=contrato.tenant_id,
        contrato_id=contrato.id,
        tipo="DESCARGADO",
        actor_tipo="CREDENCIAL",
        actor_id=credencial.id,
        ip=ip_observada(request),
        agente=request.headers.get("user-agent"),
    )
    sesion.commit()
    es_final = contrato.clave_documento_final is not None
    return Response(
        content=contenido,
        media_type="text/html; charset=utf-8",
        headers={
            "X-Document-Hash": contrato.hash_documento_final or contrato.hash_documento,
            "X-Document-Kind": "final" if es_final else "presentado",
            "Content-Disposition": f'inline; filename="contrato-{contrato.id[:8]}.html"',
        },
    )


@router.get("/contratos/{contrato_id}/auditoria")
def auditoria_contrato(
    contrato_id: str,
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:leer")),
    sesion: Session = Depends(obtener_sesion),
):
    contrato = servicio.obtener(sesion, credencial.tenant_id, contrato_id)
    eventos = auditoria.listar(sesion, contrato.tenant_id, contrato.id)
    verificacion = auditoria.verificar_cadena(sesion, contrato.tenant_id, contrato.id)
    return {
        "contract_id": contrato.id,
        "chain": verificacion,
        "events": [
            {
                "sequence": e.secuencia,
                "type": e.tipo,
                "actor_type": e.actor_tipo,
                "created_at": e.creado_en.isoformat().replace("+00:00", "Z"),
                "hash": e.hash,
                "previous_hash": e.hash_anterior,
                "data": e.datos,
            }
            for e in eventos
        ],
    }


@router.post("/webhooks", status_code=status.HTTP_201_CREATED)
def registrar_webhook(
    peticion: RegistrarWebhook,
    credencial: CredencialAutenticada = Depends(exigir_permiso("contratos:crear")),
    sesion: Session = Depends(obtener_sesion),
):
    try:
        endpoint, secreto = webhooks.registrar_endpoint(
            sesion, credencial.tenant_id, peticion.url, peticion.eventos
        )
    except webhooks.DestinoNoPermitido as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "destino_no_permitido", "mensaje": str(error)},
        ) from error
    sesion.commit()
    return {
        "endpoint_id": endpoint.id,
        "url": endpoint.url,
        "events": endpoint.eventos,
        # El secreto se muestra UNA sola vez. Despues solo existe cifrado.
        "secret": secreto,
    }


@router.post("/plantillas", status_code=status.HTTP_201_CREATED)
def crear_plantilla(
    peticion: CrearPlantilla,
    credencial: CredencialAutenticada = Depends(exigir_permiso("plantillas:administrar")),
    sesion: Session = Depends(obtener_sesion),
):
    """Crea la plantilla si no existe y publica una version nueva e inmutable."""
    try:
        schema = validar_schema(peticion.schema_variables)
        cuerpo = sanitizar_cuerpo(peticion.cuerpo)
    except (DatosInvalidos, PlantillaInvalida) as error:
        detalles = getattr(error, "detalles", None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "plantilla_invalida", "mensaje": str(error), "detalles": detalles},
        ) from error

    plantilla = sesion.scalars(
        select(Plantilla).where(
            Plantilla.tenant_id == credencial.tenant_id, Plantilla.codigo == peticion.codigo
        )
    ).first()
    if plantilla is None:
        plantilla = Plantilla(
            tenant_id=credencial.tenant_id, codigo=peticion.codigo, nombre=peticion.nombre
        )
        sesion.add(plantilla)
        sesion.flush()

    ultima = sesion.scalars(
        select(VersionPlantilla)
        .where(
            VersionPlantilla.tenant_id == credencial.tenant_id,
            VersionPlantilla.plantilla_id == plantilla.id,
        )
        .order_by(VersionPlantilla.version.desc())
        .limit(1)
    ).first()

    from app.dominio.politica import normalizar as normalizar_politica

    politica = normalizar_politica(peticion.politica)
    numero = (ultima.version if ultima else 0) + 1
    version = VersionPlantilla(
        tenant_id=credencial.tenant_id,
        plantilla_id=plantilla.id,
        version=numero,
        titulo=peticion.titulo,
        cuerpo=cuerpo,
        schema_variables=schema,
        politica=politica,
        hash_contenido=sha256(
            json_canonico(
                {"cuerpo": cuerpo, "schema": schema, "politica": politica,
                 "titulo": peticion.titulo, "version": numero}
            )
        ),
    )
    sesion.add(version)
    sesion.flush()
    try:
        servicio.publicar_version(sesion, version)
    except PlantillaInvalida as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "plantilla_invalida", "mensaje": str(error)},
        ) from error
    sesion.commit()
    return {
        "template_id": plantilla.id,
        "code": plantilla.codigo,
        "version": version.version,
        "content_hash": version.hash_contenido,
        "status": version.estado,
    }
