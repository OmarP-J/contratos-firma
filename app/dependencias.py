"""
Dependencias de FastAPI: autenticacion, contexto y limites de peticiones.
"""
from __future__ import annotations

import base64
import ipaddress
import time
from collections import defaultdict

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import ajustes
from app.db import ahora_utc, obtener_sesion
from app.dominio.contratos import Contexto
from app.models import CredencialApi
from app.seguridad import verificar_secreto

PERMISOS = {"contratos:crear", "contratos:leer", "contratos:anular", "contratos:descargar"}


# ---------------------------------------------------------------------------
# IP observada
# ---------------------------------------------------------------------------

def ip_observada(request: Request) -> str:
    """
    La IP que el servidor observa. Solo se acepta X-Forwarded-For si la
    conexion viene de un proxy que nosotros declaramos confiable; nunca porque
    la cabecera venga puesta.
    """
    directa = request.client.host if request.client else ""
    confiables = [c.strip() for c in ajustes().proxies_confiables.split(",") if c.strip()]
    reenviada = request.headers.get("x-forwarded-for")
    if not confiables or not reenviada:
        return directa
    try:
        ip_directa = ipaddress.ip_address(directa)
        if not any(ip_directa in ipaddress.ip_network(red, strict=False) for red in confiables):
            return directa
        candidata = reenviada.split(",")[0].strip()
        ipaddress.ip_address(candidata)
        return candidata
    except ValueError:
        return directa


# ---------------------------------------------------------------------------
# Limite de peticiones (en memoria; sustituir por Redis con varias instancias)
# ---------------------------------------------------------------------------

_contadores: dict[str, list[float]] = defaultdict(list)


def limitar(clave: str, limite: int, ventana_s: int) -> None:
    ahora = time.monotonic()
    marcas = [t for t in _contadores[clave] if ahora - t < ventana_s]
    if len(marcas) >= limite:
        _contadores[clave] = marcas
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "limite_excedido", "mensaje": "Demasiadas solicitudes"},
        )
    marcas.append(ahora)
    _contadores[clave] = marcas


def reiniciar_limites() -> None:
    _contadores.clear()


# ---------------------------------------------------------------------------
# Autenticacion B2B
# ---------------------------------------------------------------------------

class CredencialAutenticada:
    def __init__(self, credencial: CredencialApi) -> None:
        self.id = credencial.id
        self.tenant_id = credencial.tenant_id
        self.permisos = set(credencial.permisos or [])


def credencial_actual(
    request: Request,
    authorization: str = Header(default=""),
    sesion: Session = Depends(obtener_sesion),
) -> CredencialAutenticada:
    """
    Autenticacion HTTP Basic con client_id y client_secret.

    El secreto nunca viaja al navegador ni se guarda en claro: en la base solo
    vive su hash, y aqui se verifica con una comparacion en tiempo constante.
    """
    no_autenticado = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "no_autenticado", "mensaje": "Credenciales invalidas o ausentes"},
        headers={"WWW-Authenticate": "Basic"},
    )
    if not authorization.lower().startswith("basic "):
        raise no_autenticado
    try:
        crudo = base64.b64decode(authorization[6:].strip()).decode("utf-8")
        client_id, _, secreto = crudo.partition(":")
    except Exception as error:
        raise no_autenticado from error
    if not client_id or not secreto:
        raise no_autenticado

    limitar(f"auth:{ip_observada(request)}", limite=30, ventana_s=60)

    credencial = sesion.scalars(
        select(CredencialApi).where(CredencialApi.client_id == client_id)
    ).first()
    if credencial is None or credencial.estado != "ACTIVA":
        raise no_autenticado
    if not verificar_secreto(secreto, credencial.secreto_hash):
        raise no_autenticado

    credencial.ultimo_uso_en = ahora_utc()
    sesion.flush()
    return CredencialAutenticada(credencial)


def exigir_permiso(permiso: str):
    """Cada endpoint declara que permiso necesita. Sin el, 403."""

    def verificador(
        credencial: CredencialAutenticada = Depends(credencial_actual),
    ) -> CredencialAutenticada:
        if permiso not in credencial.permisos:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "sin_permiso",
                    "mensaje": f"La credencial no tiene el permiso {permiso}",
                },
            )
        return credencial

    return verificador


def contexto_b2b(request: Request, credencial: CredencialAutenticada) -> Contexto:
    return Contexto(
        tenant_id=credencial.tenant_id,
        actor_tipo="CREDENCIAL",
        actor_id=credencial.id,
        ip=ip_observada(request),
        agente=request.headers.get("user-agent"),
    )
