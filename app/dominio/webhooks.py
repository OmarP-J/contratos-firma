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
   receptor puede estar caido justo cuando se completa un contrato.
"""
from __future__ import annotations

import ipaddress
import socket
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
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


class DestinoNoPermitido(Exception):
    pass


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


def procesar_pendientes(limite: int = 20) -> int:
    """
    Intenta entregar lo que este pendiente. Se llama despues de encolar y
    puede llamarse tambien desde una tarea periodica.
    """
    entregadas = 0
    with FabricaSesion() as sesion:
        pendientes = sesion.scalars(
            select(EntregaWebhook)
            .where(
                EntregaWebhook.estado == "PENDIENTE",
                EntregaWebhook.proximo_intento_en <= ahora_utc(),
            )
            .order_by(EntregaWebhook.creada_en)
            .limit(limite)
        ).all()

        for entrega in pendientes:
            endpoint = sesion.get(EndpointWebhook, entrega.endpoint_id)
            if endpoint is None or endpoint.estado != "ACTIVO":
                entrega.estado = "ABANDONADA"
                entrega.ultimo_error = "endpoint inactivo"
                continue
            if _intentar(sesion, entrega, endpoint):
                entregadas += 1
        sesion.commit()
    return entregadas


def _intentar(sesion: Session, entrega: EntregaWebhook, endpoint: EndpointWebhook) -> bool:
    intento = entrega.intentos + 1
    cuerpo = json_canonico(entrega.payload)
    try:
        # Revalidacion justo antes de enviar: el DNS pudo cambiar desde el registro.
        validar_destino(endpoint.url)
        marca = str(int(ahora_utc().timestamp()))
        firma = hmac_sha256(descifrar(endpoint.secreto_cifrado), f"{marca}.{cuerpo}")

        respuesta = httpx.post(
            endpoint.url,
            content=cuerpo.encode("utf-8"),
            headers={
                "content-type": "application/json",
                "user-agent": "servicio-contratos-firma/1.0",
                "x-signature": f"sha256={firma}",
                "x-timestamp": marca,
                "x-event-id": entrega.evento_id,
                "x-event-type": entrega.tipo_evento,
            },
            timeout=TIMEOUT_SEGUNDOS,
            # Seguir redirecciones es un vector clasico de SSRF: el destino
            # responde 302 hacia una IP interna y nos lleva de la mano.
            follow_redirects=False,
        )
        if 200 <= respuesta.status_code < 300:
            entrega.estado = "ENTREGADA"
            entrega.intentos = intento
            entrega.entregada_en = ahora_utc()
            entrega.ultimo_codigo = respuesta.status_code
            entrega.ultimo_error = None
            endpoint.fallos_consecutivos = 0
            return True
        _fallo(entrega, endpoint, intento, f"HTTP {respuesta.status_code}", respuesta.status_code)
        return False
    except Exception as error:
        _fallo(entrega, endpoint, intento, str(error)[:300], None)
        return False


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


def firma_esperada(secreto: str, marca_tiempo: str, cuerpo: str) -> str:
    """
    Utilidad para quien recibe: asi se verifica una entrega nuestra.

    Compara el resultado con la cabecera X-Signature usando una comparacion en
    tiempo constante, y rechaza marcas de tiempo muy viejas para evitar
    reenvios.
    """
    return f"sha256={hmac_sha256(secreto, f'{marca_tiempo}.{cuerpo}')}"
