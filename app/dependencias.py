"""
Dependencias de FastAPI: autenticacion, contexto y limites de peticiones.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import time
from collections import defaultdict

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import ajustes
from app.db import ahora_utc, obtener_sesion
from app.dominio.contratos import Contexto
from app.dominio.credenciales import PERMISOS  # noqa: F401  (lista canonica)
from app.models import CredencialApi
from app.seguridad import verificar_secreto


registro = logging.getLogger("limites")


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
# Limite de peticiones
# ---------------------------------------------------------------------------

class LimitadorMemoria:
    """Ventana deslizante en memoria. Solo es correcto con una instancia de la API."""

    def __init__(self) -> None:
        self._marcas: dict[str, list[float]] = defaultdict(list)

    def permitir(self, clave: str, limite: int, ventana_s: int) -> bool:
        ahora = time.monotonic()
        marcas = [t for t in self._marcas[clave] if ahora - t < ventana_s]
        if len(marcas) >= limite:
            self._marcas[clave] = marcas
            return False
        marcas.append(ahora)
        self._marcas[clave] = marcas
        return True

    def reiniciar(self) -> None:
        self._marcas.clear()


class LimitadorRedis:
    """
    Ventana fija compartida en Redis, para varias instancias de la API: el
    limite vale para todo el sistema y no por proceso. En el borde entre dos
    ventanas puede dejar pasar hasta el doble durante un instante; a cambio
    son dos comandos por peticion y ningun script.

    Si Redis no responde, la peticion pasa y queda registrado: un limitador
    caido no deberia tumbar la API. Lo que protege secretos tiene ademas su
    propio tope en la base (los intentos de OTP).
    """

    def __init__(self, cliente, prefijo: str = "limite") -> None:
        from redis.exceptions import RedisError

        self.cliente = cliente
        self.prefijo = prefijo
        self._errores = (RedisError, OSError)

    def permitir(self, clave: str, limite: int, ventana_s: int) -> bool:
        ventana = int(time.time() // ventana_s)
        llave = f"{self.prefijo}:{clave}:{ventana}"
        try:
            tuberia = self.cliente.pipeline()
            tuberia.incr(llave)
            tuberia.expire(llave, ventana_s)
            cuenta, _ = tuberia.execute()
        except self._errores:
            registro.warning("Redis no responde; se omite el limite de %s", clave)
            return True
        return cuenta <= limite

    def reiniciar(self) -> None:
        """En Redis las claves caducan solas; no hay nada que limpiar a mano."""


def _crear_limitador() -> LimitadorMemoria | LimitadorRedis:
    url = ajustes().url_redis
    if not url:
        return LimitadorMemoria()
    import redis

    # Timeouts cortos: esperar a un Redis lento seria peor que no limitar.
    return LimitadorRedis(
        redis.Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
    )


_limitador = _crear_limitador()


def limitar(clave: str, limite: int, ventana_s: int) -> None:
    if not _limitador.permitir(clave, limite, ventana_s):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": "limite_excedido", "mensaje": "Demasiadas solicitudes"},
        )


def reiniciar_limites() -> None:
    _limitador.reiniciar()


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
