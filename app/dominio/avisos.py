"""
Avisos salientes: el enlace de firma que recibe cada firmante.

Patron outbox. El aviso se guarda en la misma transaccion que crea la
invitacion: si la transaccion se confirma, el aviso existe y saldra aunque el
proveedor de correo este caido en ese momento; si se deshace, tampoco existe.
Se intenta enviar justo despues de responder, y el proceso de tareas
periodicas reintenta los que fallaron.

El texto lleva el enlace con el token de firma, que en el resto del sistema
solo se guarda hasheado. Por eso aqui va cifrado, y se borra en cuanto sale.

Los codigos OTP no pasan por aqui: el firmante esta esperando en la pantalla y
un codigo que llega diez minutos tarde ya vencio. Esos se envian en el momento
y, si fallan, se le dice al firmante.
"""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import notificaciones
from app.db import FabricaSesion, ahora_utc
from app.dominio import auditoria
from app.models import AvisoSaliente
from app.notificaciones import ErrorDeEnvio, Mensaje
from app.seguridad import cifrar, descifrar, enmascarar

registro = logging.getLogger("avisos")

MAX_INTENTOS = 5
ESTADOS_RECLAMABLES = ("PENDIENTE", "EN_CURSO")
RESERVA = timedelta(minutes=2)


def encolar(
    sesion: Session, *, tenant_id: str, contrato_id: str | None, mensaje: Mensaje
) -> AvisoSaliente:
    aviso = AvisoSaliente(
        tenant_id=tenant_id,
        contrato_id=contrato_id,
        canal=mensaje.canal,
        destino=mensaje.destino,
        destino_enmascarado=enmascarar(mensaje.destino),
        contenido_cifrado=cifrar(json.dumps({"asunto": mensaje.asunto, "texto": mensaje.texto})),
        proximo_intento_en=ahora_utc(),
    )
    sesion.add(aviso)
    sesion.flush()
    return aviso


def _espera(intento: int) -> timedelta:
    escala = [60, 300, 1800, 7200]
    return timedelta(seconds=escala[min(intento - 1, len(escala) - 1)])


def procesar_pendientes(limite: int = 20) -> int:
    """
    Envia los avisos pendientes. Como en los webhooks, cada aviso se reclama
    con un UPDATE condicional, asi que varios procesos no mandan el mismo.
    """
    enviados = 0
    for aviso_id in _candidatos(limite):
        if reclamar(aviso_id) and _enviar(aviso_id):
            enviados += 1
    return enviados


def _candidatos(limite: int) -> list[str]:
    with FabricaSesion() as sesion:
        return list(
            sesion.scalars(
                select(AvisoSaliente.id)
                .where(
                    AvisoSaliente.estado.in_(ESTADOS_RECLAMABLES),
                    AvisoSaliente.proximo_intento_en <= ahora_utc(),
                )
                .order_by(AvisoSaliente.proximo_intento_en)
                .limit(limite)
            )
        )


def reclamar(aviso_id: str) -> bool:
    ahora = ahora_utc()
    with FabricaSesion() as sesion:
        resultado = sesion.execute(
            update(AvisoSaliente)
            .where(
                AvisoSaliente.id == aviso_id,
                AvisoSaliente.estado.in_(ESTADOS_RECLAMABLES),
                AvisoSaliente.proximo_intento_en <= ahora,
            )
            .values(estado="EN_CURSO", proximo_intento_en=ahora + RESERVA)
        )
        sesion.commit()
        return resultado.rowcount == 1


def _enviar(aviso_id: str) -> bool:
    with FabricaSesion() as sesion:
        aviso = sesion.get(AvisoSaliente, aviso_id)
        contenido = json.loads(descifrar(aviso.contenido_cifrado))
        mensaje = Mensaje(
            canal=aviso.canal, destino=aviso.destino,
            asunto=contenido["asunto"], texto=contenido["texto"],
        )

    error = None
    try:
        notificaciones.enviar(mensaje)
    except ErrorDeEnvio as fallo:
        error = str(fallo)[:400]

    with FabricaSesion() as sesion:
        aviso = sesion.get(AvisoSaliente, aviso_id)
        aviso.intentos += 1
        if error is None:
            aviso.estado = "ENVIADO"
            aviso.enviado_en = ahora_utc()
            aviso.ultimo_error = None
            aviso.contenido_cifrado = ""
        elif aviso.intentos >= MAX_INTENTOS:
            _dar_por_perdido(sesion, aviso, error)
        else:
            aviso.estado = "PENDIENTE"
            aviso.ultimo_error = error
            aviso.proximo_intento_en = ahora_utc() + _espera(aviso.intentos)
        sesion.commit()
    return error is None


def _dar_por_perdido(sesion: Session, aviso: AvisoSaliente, error: str) -> None:
    """
    Tras agotar los reintentos el aviso queda FALLIDO y se registra en la
    auditoria del contrato: el integrador lo ve ahi y puede reenviar el enlace.
    """
    aviso.estado = "FALLIDO"
    aviso.ultimo_error = error
    aviso.contenido_cifrado = ""
    registro.warning("aviso a %s perdido tras %s intentos", aviso.destino_enmascarado, aviso.intentos)
    if aviso.contrato_id:
        auditoria.registrar(
            sesion,
            tenant_id=aviso.tenant_id,
            contrato_id=aviso.contrato_id,
            tipo="AVISO_NO_ENVIADO",
            actor_tipo="SISTEMA",
            datos={"canal": aviso.canal, "destino": aviso.destino_enmascarado,
                   "intentos": aviso.intentos, "error": error},
        )
