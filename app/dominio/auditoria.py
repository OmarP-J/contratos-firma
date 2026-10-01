"""
Linea de auditoria.

Los eventos son append-only y encadenan hashes: cada evento incluye el hash del
anterior del mismo contrato. Eliminar o modificar un evento intermedio rompe la
cadena y se detecta al verificarla.

Esto no sustituye a los permisos de base de datos: en produccion el usuario de
la aplicacion no deberia tener UPDATE ni DELETE sobre esta tabla.
"""
from __future__ import annotations

from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import ahora_utc
from app.models import EventoAuditoria
from app.seguridad import json_canonico, sha256


def _calcular_hash(
    *, anterior: str | None, evento_id: str, tenant_id: str, contrato_id: str | None,
    tipo: str, actor_tipo: str, actor_id: str | None, datos: dict, creado_en: str,
) -> str:
    return sha256(
        json_canonico({
            "anterior": anterior,
            "id": evento_id,
            "tenant": tenant_id,
            "contrato": contrato_id,
            "tipo": tipo,
            "actor_tipo": actor_tipo,
            "actor_id": actor_id,
            "datos": datos,
            "creado_en": creado_en,
        })
    )


def registrar(
    sesion: Session,
    *,
    tenant_id: str,
    contrato_id: str | None,
    tipo: str,
    actor_tipo: str,
    actor_id: str | None = None,
    datos: dict[str, Any] | None = None,
    ip: str | None = None,
    agente: str | None = None,
) -> EventoAuditoria:
    anterior = sesion.scalars(
        select(EventoAuditoria)
        .where(
            EventoAuditoria.tenant_id == tenant_id,
            EventoAuditoria.contrato_id == contrato_id,
        )
        .order_by(EventoAuditoria.secuencia.desc())
        .limit(1)
    ).first()

    evento = EventoAuditoria(
        # El id se genera aqui, no en el INSERT: el hash se calcula sobre el y
        # tiene que ser el mismo valor que acabe guardado.
        id=str(uuid4()),
        tenant_id=tenant_id,
        contrato_id=contrato_id,
        secuencia=(anterior.secuencia + 1) if anterior else 1,
        tipo=tipo,
        actor_tipo=actor_tipo,
        actor_id=actor_id,
        datos=datos or {},
        ip=ip,
        agente=(agente or "")[:400] or None,
        hash_anterior=anterior.hash if anterior else None,
        creado_en=ahora_utc(),
    )
    evento.hash = _calcular_hash(
        anterior=evento.hash_anterior,
        evento_id=evento.id,
        tenant_id=tenant_id,
        contrato_id=contrato_id,
        tipo=tipo,
        actor_tipo=actor_tipo,
        actor_id=actor_id,
        datos=evento.datos,
        creado_en=evento.creado_en.isoformat(),
    )
    sesion.add(evento)
    sesion.flush()
    return evento


def listar(sesion: Session, tenant_id: str, contrato_id: str) -> list[EventoAuditoria]:
    return list(
        sesion.scalars(
            select(EventoAuditoria)
            .where(
                EventoAuditoria.tenant_id == tenant_id,
                EventoAuditoria.contrato_id == contrato_id,
            )
            .order_by(EventoAuditoria.secuencia)
        )
    )


def verificar_cadena(sesion: Session, tenant_id: str, contrato_id: str) -> dict:
    """Recalcula la cadena completa. Si alguien toco la tabla, aqui se ve."""
    anterior: str | None = None
    for evento in listar(sesion, tenant_id, contrato_id):
        esperado = _calcular_hash(
            anterior=anterior,
            evento_id=evento.id,
            tenant_id=tenant_id,
            contrato_id=contrato_id,
            tipo=evento.tipo,
            actor_tipo=evento.actor_tipo,
            actor_id=evento.actor_id,
            datos=evento.datos,
            creado_en=evento.creado_en.isoformat(),
        )
        if esperado != evento.hash or evento.hash_anterior != anterior:
            return {"integra": False, "rota_en": evento.secuencia}
        anterior = evento.hash
    return {"integra": True, "rota_en": None}
