"""
Webhooks salientes.

Tres cosas importan aqui:

1. SSRF. La URL la elige el tenant. Si no se valida, puede apuntar a
   127.0.0.1, a 169.254.169.254 (metadatos de la nube) o a una maquina de la
   red interna, y usar nuestro servidor como puente hacia adentro.
2. Autenticidad. Cada entrega va firmada con HMAC sobre marca de tiempo mas
   cuerpo, para que el receptor compruebe que viene de nosotros y que no es un
   reenvio antiguo.
3. Entrega. Hay reintentos con espera progresiva e historial, porque el
   receptor puede estar caido justo cuando se completa un contrato. La
   entrega es "al menos una vez": el receptor debe ignorar un X-Event-Id que
   ya proceso.
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import ajustes
from app.db import FabricaSesion, ahora_utc
from app.models import EndpointWebhook, EntregaWebhook
from app.seguridad import cifrar, descifrar, hmac_sha256, json_canonico, token_aleatorio

EVENTOS = [
    "contract.sent",
    "contract.viewed",
    "contract.client_signed",
    "contract.company_signed",
    "contract.completed",
    "contract.declined",
    "contract.expired",
    "contract.voided",
]

MAX_INTENTOS = 6
TIMEOUT_SEGUNDOS = 8.0

# EN_CURSO tambien se puede reclamar: es una entrega cuyo proceso murio y
# cuya reserva ya vencio.
ESTADOS_RECLAMABLES = ("PENDIENTE", "EN_CURSO")
RESERVA = timedelta(seconds=TIMEOUT_SEGUNDOS * 4)

# Fallos seguidos, entre todas sus entregas, a partir de los cuales un
# endpoint se suspende y deja de recibir eventos nuevos.
FALLOS_PARA_SUSPENDER = 15


class DestinoNoPermitido(Exception):
    pass


class EstadoNoPermitido(Exception):
    """La operacion no tiene sentido en el estado actual del endpoint o la entrega."""


def validar_destino(url: str) -> list[str]:
    """
    Comprueba que la URL de webhook apunte a Internet publico.

    Se aplica al registrar el endpoint y otra vez justo antes de cada entrega,
    porque el DNS puede cambiar entre ambos momentos. El pinning de la IP
    resuelta queda como mejora pendiente; mientras tanto, revalidar y no seguir
    redirecciones cubre los vectores habituales.
    """
    partes = urlparse(url)
    permitir_privado = ajustes().permitir_webhook_privado

    if partes.scheme != "https" and not (permitir_privado and partes.scheme == "http"):
        raise DestinoNoPermitido("El webhook debe usar HTTPS")
    if partes.username or partes.password:
        raise DestinoNoPermitido("La URL del webhook no puede incluir credenciales")
    if not partes.hostname:
        raise DestinoNoPermitido("La URL del webhook no tiene host")

    try:
        resueltas = socket.getaddrinfo(partes.hostname, partes.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise DestinoNoPermitido("No se pudo resolver el host del webhook") from error

    direcciones = sorted({info[4][0] for info in resueltas})
    if not direcciones:
        raise DestinoNoPermitido("El host del webhook no resuelve a ninguna IP")

    if not permitir_privado:
        for texto in direcciones:
            ip = ipaddress.ip_address(texto)
            if (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            ):
                raise DestinoNoPermitido(
                    "El webhook apunta a una direccion no permitida "
                    "(red privada, loopback o reservada)"
                )
    return direcciones


def registrar_endpoint(
    sesion: Session, tenant_id: str, url: str, eventos: list[str] | None = None
) -> tuple[EndpointWebhook, str]:
    """Devuelve el endpoint y el secreto EN CLARO, que solo se muestra esta vez."""
    validar_destino(url)
    seleccionados = [e for e in (eventos or EVENTOS) if e in EVENTOS]
    if not seleccionados:
        raise DestinoNoPermitido("Debe suscribirse al menos a un evento valido")

    secreto = f"whsec_{token_aleatorio(24)}"
    endpoint = EndpointWebhook(
        tenant_id=tenant_id,
        url=url,
        secreto_cifrado=cifrar(secreto),
        eventos=seleccionados,
    )
    sesion.add(endpoint)
    sesion.flush()
    return endpoint, secreto


def encolar(
    sesion: Session, *, tenant_id: str, evento: str, contrato_id: str, datos: dict[str, Any]
) -> None:
    """Crea una entrega pendiente para cada endpoint suscrito del tenant."""
    endpoints = sesion.scalars(
        select(EndpointWebhook).where(
            EndpointWebhook.tenant_id == tenant_id,
            EndpointWebhook.estado == "ACTIVO",
        )
    ).all()

    for endpoint in endpoints:
        if evento not in (endpoint.eventos or []):
            continue
        evento_id = token_aleatorio(12)
        sesion.add(
            EntregaWebhook(
                tenant_id=tenant_id,
                endpoint_id=endpoint.id,
                evento_id=evento_id,
                tipo_evento=evento,
                contrato_id=contrato_id,
                payload={
                    "event": evento,
                    "event_id": evento_id,
                    "created_at": ahora_utc().isoformat().replace("+00:00", "Z"),
                    "contract_id": contrato_id,
                    **datos,
                },
                proximo_intento_en=ahora_utc(),
            )
        )
    sesion.flush()


def _espera(intento: int) -> timedelta:
    escala = [30, 120, 600, 3600, 21600, 43200]
    return timedelta(seconds=escala[min(intento - 1, len(escala) - 1)])


def entregar_en_linea() -> int:
    """
    Entrega lo pendiente desde el propio proceso de la API, salvo que la
    configuracion lo deje todo para el proceso de tareas periodicas.
    """
    if not ajustes().entregar_webhooks_en_linea:
        return 0
    return procesar_pendientes()


def procesar_pendientes(limite: int = 20) -> int:
    """
    Intenta entregar lo que este pendiente. Lo llaman la API (despues de
    responder) y el proceso de tareas periodicas.

    Puede correr en varios procesos a la vez: cada entrega se reclama con un
    UPDATE condicional antes de enviarla, asi que dos procesos no mandan la
    misma. Si un proceso muere a mitad de una entrega, la reserva vence y
    otro la retoma.
    """
    entregadas = 0
    for entrega_id in _candidatas(limite):
        if reclamar(entrega_id) and _entregar(entrega_id):
            entregadas += 1
    return entregadas


def _candidatas(limite: int) -> list[str]:
    with FabricaSesion() as sesion:
        return list(
            sesion.scalars(
                select(EntregaWebhook.id)
                .where(
                    EntregaWebhook.estado.in_(ESTADOS_RECLAMABLES),
                    EntregaWebhook.proximo_intento_en <= ahora_utc(),
                )
                .order_by(EntregaWebhook.proximo_intento_en)
                .limit(limite)
            )
        )


def reclamar(entrega_id: str) -> bool:
    """
    Toma la entrega para este proceso. Si otro la tomo primero, el UPDATE no
    encuentra la fila en el estado esperado y devuelve 0 filas. Funciona igual
    en SQLite y en PostgreSQL, sin bloqueos de fila explicitos.
    """
    ahora = ahora_utc()
    with FabricaSesion() as sesion:
        resultado = sesion.execute(
            update(EntregaWebhook)
            .where(
                EntregaWebhook.id == entrega_id,
                EntregaWebhook.estado.in_(ESTADOS_RECLAMABLES),
                EntregaWebhook.proximo_intento_en <= ahora,
            )
            .values(estado="EN_CURSO", proximo_intento_en=ahora + RESERVA)
        )
        sesion.commit()
        return resultado.rowcount == 1


def _entregar(entrega_id: str) -> bool:
    with FabricaSesion() as sesion:
        entrega = sesion.get(EntregaWebhook, entrega_id)
        endpoint = sesion.get(EndpointWebhook, entrega.endpoint_id)
        if endpoint is None or endpoint.estado != "ACTIVO":
            entrega.estado = "ABANDONADA"
            entrega.ultimo_error = "endpoint inactivo"
            sesion.commit()
            return False
        # Se copia lo necesario y se suelta la conexion antes de salir a la
        # red: un receptor lento no debe retener conexiones de la base.
        url, secreto_cifrado = endpoint.url, endpoint.secreto_cifrado
        payload, evento_id, tipo = entrega.payload, entrega.evento_id, entrega.tipo_evento

    codigo, error = _enviar(url, secreto_cifrado, payload, evento_id, tipo)

    with FabricaSesion() as sesion:
        entrega = sesion.get(EntregaWebhook, entrega_id)
        endpoint = sesion.get(EndpointWebhook, entrega.endpoint_id)
        intento = entrega.intentos + 1
        if error is None:
            entrega.estado = "ENTREGADA"
            entrega.intentos = intento
            entrega.entregada_en = ahora_utc()
            entrega.ultimo_codigo = codigo
            entrega.ultimo_error = None
            endpoint.fallos_consecutivos = 0
        else:
            _fallo(entrega, endpoint, intento, error, codigo)
        sesion.commit()
    return error is None


def _enviar(
    url: str, secreto_cifrado: str, payload: dict, evento_id: str, tipo: str
) -> tuple[int | None, str | None]:
    """Hace la peticion. Devuelve (codigo HTTP, error); error es None si se entrego."""
    cuerpo = json_canonico(payload)
    try:
        # Revalidacion justo antes de enviar: el DNS pudo cambiar desde el registro.
        validar_destino(url)
        marca = str(int(ahora_utc().timestamp()))
        firma = hmac_sha256(descifrar(secreto_cifrado), f"{marca}.{cuerpo}")

        respuesta = httpx.post(
            url,
            content=cuerpo.encode("utf-8"),
            headers={
                "content-type": "application/json",
                "user-agent": "servicio-contratos-firma/1.0",
                "x-signature": f"sha256={firma}",
                "x-timestamp": marca,
                "x-event-id": evento_id,
                "x-event-type": tipo,
            },
            timeout=TIMEOUT_SEGUNDOS,
            # Seguir redirecciones es un vector clasico de SSRF: el destino
            # responde 302 hacia una IP interna y nos lleva de la mano.
            follow_redirects=False,
        )
    except Exception as error:
        return None, str(error)[:300]
    if 200 <= respuesta.status_code < 300:
        return respuesta.status_code, None
    return respuesta.status_code, f"HTTP {respuesta.status_code}"


def _fallo(
    entrega: EntregaWebhook, endpoint: EndpointWebhook, intento: int,
    mensaje: str, codigo: int | None,
) -> None:
    agotado = intento >= MAX_INTENTOS
    entrega.estado = "FALLIDA" if agotado else "PENDIENTE"
    entrega.intentos = intento
    entrega.ultimo_error = mensaje
    entrega.ultimo_codigo = codigo
    entrega.proximo_intento_en = ahora_utc() + _espera(intento)
    endpoint.fallos_consecutivos += 1
    if endpoint.fallos_consecutivos >= FALLOS_PARA_SUSPENDER and endpoint.estado == "ACTIVO":
        # Un endpoint que lleva tanto tiempo fallando solo acumula reintentos
        # inutiles. Se suspende y el integrador lo reactiva cuando lo arregle.
        endpoint.estado = "SUSPENDIDO"


# ---------------------------------------------------------------------------
# Gestion por parte del integrador
# ---------------------------------------------------------------------------

def listar_endpoints(sesion: Session, tenant_id: str) -> list[EndpointWebhook]:
    return list(
        sesion.scalars(
            select(EndpointWebhook)
            .where(EndpointWebhook.tenant_id == tenant_id)
            .order_by(EndpointWebhook.creado_en)
        )
    )


def obtener_endpoint(sesion: Session, tenant_id: str, endpoint_id: str) -> EndpointWebhook | None:
    return sesion.scalars(
        select(EndpointWebhook).where(
            EndpointWebhook.tenant_id == tenant_id, EndpointWebhook.id == endpoint_id
        )
    ).first()


def listar_entregas(
    sesion: Session, tenant_id: str, endpoint_id: str, limite: int = 50
) -> list[EntregaWebhook]:
    return list(
        sesion.scalars(
            select(EntregaWebhook)
            .where(
                EntregaWebhook.tenant_id == tenant_id,
                EntregaWebhook.endpoint_id == endpoint_id,
            )
            .order_by(EntregaWebhook.creada_en.desc())
            .limit(limite)
        )
    )


def obtener_entrega(sesion: Session, tenant_id: str, entrega_id: str) -> EntregaWebhook | None:
    return sesion.scalars(
        select(EntregaWebhook).where(
            EntregaWebhook.tenant_id == tenant_id, EntregaWebhook.id == entrega_id
        )
    ).first()


def reactivar(endpoint: EndpointWebhook) -> None:
    endpoint.estado = "ACTIVO"
    endpoint.fallos_consecutivos = 0


def reintentar(entrega: EntregaWebhook, endpoint: EndpointWebhook) -> None:
    """
    Vuelve a poner una entrega en la cola, aunque ya se hubiera entregado:
    sirve al integrador que perdio el evento de su lado. Si ya habia agotado
    los reintentos, el reintento manual es uno solo.
    """
    if endpoint.estado != "ACTIVO":
        raise EstadoNoPermitido("El endpoint esta suspendido: reactivalo antes de reintentar")
    if entrega.estado == "EN_CURSO":
        raise EstadoNoPermitido("La entrega se esta enviando en este momento")
    entrega.estado = "PENDIENTE"
    entrega.proximo_intento_en = ahora_utc()


def firma_esperada(secreto: str, marca_tiempo: str, cuerpo: str) -> str:
    """
    Utilidad para quien recibe: asi se verifica una entrega nuestra.

    Compara el resultado con la cabecera X-Signature usando una comparacion en
    tiempo constante, y rechaza marcas de tiempo muy viejas para evitar
    reenvios.
    """
    return f"sha256={hmac_sha256(secreto, f'{marca_tiempo}.{cuerpo}')}"
