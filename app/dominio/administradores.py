"""
Acceso al portal administrativo: usuarios, sesiones y segundo factor.

Decisiones:

  - El segundo factor es obligatorio. La primera vez que alguien entra con su
    clave, antes de ver nada, tiene que registrar una app autenticadora.
  - Un mismo mensaje para todo fallo de acceso: no se revela si el correo
    existe ni si la cuenta esta bloqueada. Si el correo no existe se verifica
    igual contra un hash senuelo, para que el tiempo de respuesta no lo delate.
  - Cinco claves equivocadas bloquean la cuenta quince minutos. Cinco codigos
    equivocados cierran la sesion y obligan a empezar de nuevo.
  - La sesion vence a los 30 minutos sin uso y, como maximo, a las 8 horas.
"""
from __future__ import annotations

import time
from datetime import timedelta
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import ahora_utc
from app.dominio import auditoria
from app.models import SesionAdmin, Tenant, UsuarioAdmin
from app.seguridad import (
    cifrar,
    descifrar,
    hash_de_token,
    hash_secreto,
    secreto_totp,
    token_aleatorio,
    uri_totp,
    verificar_secreto,
    verificar_totp,
)

MAX_FALLOS_CLAVE = 5
BLOQUEO = timedelta(minutes=15)
MAX_FALLOS_MFA = 5
INACTIVIDAD = timedelta(minutes=30)
DURACION_MAXIMA = timedelta(hours=8)
LARGO_MINIMO_CLAVE = 12

MENSAJE_ACCESO = "Correo o clave incorrectos, o la cuenta esta bloqueada temporalmente."


class AccesoDenegado(Exception):
    pass


class DatosDeUsuarioInvalidos(Exception):
    pass


@lru_cache
def _hash_senuelo() -> str:
    return hash_secreto(token_aleatorio(16))


def _normalizar_email(email: str) -> str:
    return (email or "").strip().lower()


def crear_usuario(
    sesion: Session, *, tenant_id: str, email: str, nombre: str, clave: str
) -> UsuarioAdmin:
    email = _normalizar_email(email)
    if "@" not in email or len(email) > 254:
        raise DatosDeUsuarioInvalidos("El correo no es valido")
    if len(clave or "") < LARGO_MINIMO_CLAVE:
        raise DatosDeUsuarioInvalidos(
            f"La clave debe tener al menos {LARGO_MINIMO_CLAVE} caracteres"
        )
    if sesion.scalars(select(UsuarioAdmin).where(UsuarioAdmin.email == email)).first():
        raise DatosDeUsuarioInvalidos("Ya existe un usuario con ese correo")
    usuario = UsuarioAdmin(
        tenant_id=tenant_id, email=email, nombre=nombre.strip(), clave_hash=hash_secreto(clave)
    )
    sesion.add(usuario)
    sesion.flush()
    return usuario


def autenticar(
    sesion: Session, email: str, clave: str, *, ip: str | None, agente: str | None
) -> tuple[SesionAdmin, str]:
    """
    Primer factor. Devuelve la sesion (todavia sin MFA) y el token para la
    cookie, que solo existe en este momento.
    """
    ahora = ahora_utc()
    usuario = sesion.scalars(
        select(UsuarioAdmin).where(UsuarioAdmin.email == _normalizar_email(email))
    ).first()
    if usuario is None:
        verificar_secreto(clave or "", _hash_senuelo())
        raise AccesoDenegado(MENSAJE_ACCESO)

    bloqueado = usuario.bloqueado_hasta is not None and usuario.bloqueado_hasta > ahora
    if usuario.estado != "ACTIVO" or bloqueado:
        verificar_secreto(clave or "", _hash_senuelo())
        raise AccesoDenegado(MENSAJE_ACCESO)

    if not verificar_secreto(clave or "", usuario.clave_hash):
        usuario.intentos_fallidos += 1
        if usuario.intentos_fallidos >= MAX_FALLOS_CLAVE:
            usuario.bloqueado_hasta = ahora + BLOQUEO
            usuario.intentos_fallidos = 0
            auditoria.registrar(
                sesion, tenant_id=usuario.tenant_id, contrato_id=None,
                tipo="ADMIN_BLOQUEADO", actor_tipo="SISTEMA", actor_id=usuario.id, ip=ip,
            )
        sesion.flush()
        raise AccesoDenegado(MENSAJE_ACCESO)

    usuario.intentos_fallidos = 0
    usuario.bloqueado_hasta = None
    token = token_aleatorio(32)
    sesion_admin = SesionAdmin(
        tenant_id=usuario.tenant_id,
        usuario_id=usuario.id,
        token_hash=hash_de_token(token),
        ip=ip,
        agente=(agente or "")[:400] or None,
        creada_en=ahora,
        ultimo_uso_en=ahora,
        expira_en=ahora + DURACION_MAXIMA,
    )
    sesion.add(sesion_admin)
    sesion.flush()
    return sesion_admin, token


def sesion_vigente(sesion: Session, token: str | None) -> SesionAdmin | None:
    """La sesion de esa cookie, si sigue viva. Cada uso renueva la inactividad."""
    if not token:
        return None
    ahora = ahora_utc()
    sesion_admin = sesion.scalars(
        select(SesionAdmin).where(SesionAdmin.token_hash == hash_de_token(token))
    ).first()
    if (
        sesion_admin is None
        or sesion_admin.cerrada_en is not None
        or sesion_admin.expira_en <= ahora
        or sesion_admin.ultimo_uso_en + INACTIVIDAD <= ahora
    ):
        return None
    usuario = sesion.get(UsuarioAdmin, sesion_admin.usuario_id)
    if usuario is None or usuario.estado != "ACTIVO":
        return None
    sesion_admin.ultimo_uso_en = ahora
    return sesion_admin


def secreto_pendiente(sesion: Session, usuario: UsuarioAdmin) -> tuple[str, str]:
    """
    Secreto TOTP para registrar la app y la URI de su codigo QR. Si el usuario
    abandona a mitad y vuelve, se le muestra el mismo.
    """
    if usuario.mfa_activo:
        raise DatosDeUsuarioInvalidos("El segundo factor ya esta registrado")
    if not usuario.totp_secreto_cifrado:
        usuario.totp_secreto_cifrado = cifrar(secreto_totp())
        sesion.flush()
    secreto = descifrar(usuario.totp_secreto_cifrado)
    tenant = sesion.get(Tenant, usuario.tenant_id)
    emisor = f"Contratos {tenant.nombre}" if tenant else "Contratos"
    return secreto, uri_totp(secreto, usuario.email, emisor)


def verificar_segundo_factor(
    sesion: Session, sesion_admin: SesionAdmin, codigo: str, *, ip: str | None
) -> bool:
    usuario = sesion.get(UsuarioAdmin, sesion_admin.usuario_id)
    if not usuario.totp_secreto_cifrado:
        return False
    paso = verificar_totp(
        descifrar(usuario.totp_secreto_cifrado),
        codigo,
        instante=time.time(),
        ultimo_paso=usuario.totp_ultimo_paso,
    )
    if paso is None:
        sesion_admin.intentos_mfa += 1
        if sesion_admin.intentos_mfa >= MAX_FALLOS_MFA:
            sesion_admin.cerrada_en = ahora_utc()
        sesion.flush()
        return False

    registro_nuevo = not usuario.mfa_activo
    usuario.totp_ultimo_paso = paso
    usuario.mfa_activo = True
    usuario.ultimo_acceso_en = ahora_utc()
    sesion_admin.mfa_verificada = True
    auditoria.registrar(
        sesion, tenant_id=usuario.tenant_id, contrato_id=None,
        tipo="ADMIN_MFA_REGISTRADO" if registro_nuevo else "ADMIN_ENTRO",
        actor_tipo="ADMIN", actor_id=usuario.id, ip=ip, agente=sesion_admin.agente,
    )
    sesion.flush()
    return True


def cerrar(sesion: Session, sesion_admin: SesionAdmin) -> None:
    sesion_admin.cerrada_en = ahora_utc()
    auditoria.registrar(
        sesion, tenant_id=sesion_admin.tenant_id, contrato_id=None,
        tipo="ADMIN_SALIO", actor_tipo="ADMIN", actor_id=sesion_admin.usuario_id,
    )
    sesion.flush()
