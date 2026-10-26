"""
Credenciales B2B: con que se autentica cada plataforma integradora.

El secreto se genera aqui, se muestra una sola vez y en la base solo queda su
hash. Revocar una credencial la deja inservible de inmediato.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CredencialApi
from app.seguridad import hash_secreto, token_aleatorio

PERMISOS = (
    "contratos:crear",
    "contratos:leer",
    "contratos:anular",
    "contratos:descargar",
    "plantillas:administrar",
)


class CredencialInvalida(Exception):
    pass


def crear(
    sesion: Session, tenant_id: str, *, nombre: str, permisos: list[str]
) -> tuple[CredencialApi, str]:
    """Devuelve la credencial y su secreto EN CLARO, que solo se muestra esta vez."""
    nombre = (nombre or "").strip()
    if not 3 <= len(nombre) <= 120:
        raise CredencialInvalida("El nombre debe tener entre 3 y 120 caracteres")
    desconocidos = sorted(set(permisos) - set(PERMISOS))
    if desconocidos:
        raise CredencialInvalida(f"Permisos desconocidos: {', '.join(desconocidos)}")
    if not permisos:
        raise CredencialInvalida("La credencial necesita al menos un permiso")

    secreto = token_aleatorio(24)
    credencial = CredencialApi(
        tenant_id=tenant_id,
        nombre=nombre,
        client_id=f"cli_{token_aleatorio(8)}",
        secreto_hash=hash_secreto(secreto),
        permisos=[p for p in PERMISOS if p in permisos],
    )
    sesion.add(credencial)
    sesion.flush()
    return credencial, secreto


def listar(sesion: Session, tenant_id: str) -> list[CredencialApi]:
    return list(
        sesion.scalars(
            select(CredencialApi)
            .where(CredencialApi.tenant_id == tenant_id)
            .order_by(CredencialApi.creada_en)
        )
    )


def obtener(sesion: Session, tenant_id: str, credencial_id: str) -> CredencialApi | None:
    return sesion.scalars(
        select(CredencialApi).where(
            CredencialApi.tenant_id == tenant_id, CredencialApi.id == credencial_id
        )
    ).first()


def revocar(credencial: CredencialApi) -> None:
    credencial.estado = "REVOCADA"
