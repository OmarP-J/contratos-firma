"""
Modelo de datos.

Regla transversal: toda tabla de negocio lleva tenant_id, y todas las consultas
del servicio filtran por el. El aislamiento entre empresas no depende de que
los identificadores sean dificiles de adivinar.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base, FechaUtc, ahora_utc


def _id() -> str:
    from uuid import uuid4

    return str(uuid4())


class Tenant(Base):
    """Una empresa integradora. Todo cuelga de aqui."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    nombre: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(60), unique=True)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVO")
    creado_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)


class CredencialApi(Base):
    """Credencial con la que una plataforma externa llama a nuestra API."""

    __tablename__ = "credenciales_api"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    nombre: Mapped[str] = mapped_column(String(120))
    client_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    # El secreto nunca se guarda en claro: solo su hash.
    secreto_hash: Mapped[str] = mapped_column(String(200))
    permisos: Mapped[list] = mapped_column(JSON, default=list)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVA")
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    ultimo_uso_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)


class Plantilla(Base):
    __tablename__ = "plantillas"
    __table_args__ = (UniqueConstraint("tenant_id", "codigo", name="uq_plantilla_codigo"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    codigo: Mapped[str] = mapped_column(String(80))
    nombre: Mapped[str] = mapped_column(String(200))
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)

    versiones: Mapped[list[VersionPlantilla]] = relationship(back_populates="plantilla")


class VersionPlantilla(Base):
    """
    Una version publicada es INMUTABLE. Si hay que cambiar algo se publica una
    version nueva; los contratos ya emitidos siguen atados a la suya.
    """

    __tablename__ = "versiones_plantilla"
    __table_args__ = (UniqueConstraint("plantilla_id", "version", name="uq_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    plantilla_id: Mapped[str] = mapped_column(ForeignKey("plantillas.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    titulo: Mapped[str] = mapped_column(String(200))
    cuerpo: Mapped[str] = mapped_column(Text)
    schema_variables: Mapped[dict] = mapped_column(JSON, default=dict)
    politica: Mapped[dict] = mapped_column(JSON, default=dict)
    estado: Mapped[str] = mapped_column(String(20), default="BORRADOR")
    hash_contenido: Mapped[str] = mapped_column(String(64))
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    publicada_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)

    plantilla: Mapped[Plantilla] = relationship(back_populates="versiones")


class Contrato(Base):
    __tablename__ = "contratos"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    plantilla_id: Mapped[str] = mapped_column(ForeignKey("plantillas.id"))
    version_plantilla_id: Mapped[str] = mapped_column(ForeignKey("versiones_plantilla.id"))
    numero_version: Mapped[int] = mapped_column(Integer)

    referencia_externa: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    titulo: Mapped[str] = mapped_column(String(200))
    estado: Mapped[str] = mapped_column(String(30), index=True)

    # --- Datos congelados en el momento de generar ---
    variables: Mapped[dict] = mapped_column(JSON, default=dict)
    variables_canonicas: Mapped[str] = mapped_column(Text)
    hash_variables: Mapped[str] = mapped_column(String(64))
    clave_documento: Mapped[str] = mapped_column(String(200))
    hash_documento: Mapped[str] = mapped_column(String(64))
    clave_documento_final: Mapped[str | None] = mapped_column(String(200), nullable=True)
    hash_documento_final: Mapped[str | None] = mapped_column(String(64), nullable=True)
    politica: Mapped[dict] = mapped_column(JSON, default=dict)

    credencial_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    creado_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    enviado_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)
    completado_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)
    expira_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)
    anulado_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)
    motivo_anulacion: Mapped[str | None] = mapped_column(String(300), nullable=True)

    partes: Mapped[list[ParteContrato]] = relationship(
        back_populates="contrato", order_by="ParteContrato.orden"
    )


class ParteContrato(Base):
    """Cada persona que debe firmar: el cliente, y el representante de la empresa."""

    __tablename__ = "partes_contrato"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contrato_id: Mapped[str] = mapped_column(ForeignKey("contratos.id"), index=True)
    rol: Mapped[str] = mapped_column(String(20))  # CLIENTE | EMPRESA
    orden: Mapped[int] = mapped_column(Integer, default=0)
    nombre: Mapped[str] = mapped_column(String(200))
    documento: Mapped[str | None] = mapped_column(String(30), nullable=True)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    telefono: Mapped[str | None] = mapped_column(String(20), nullable=True)
    estado: Mapped[str] = mapped_column(String(20), default="PENDIENTE")
    firmado_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)
    motivo_rechazo: Mapped[str | None] = mapped_column(String(300), nullable=True)

    contrato: Mapped[Contrato] = relationship(back_populates="partes")


class Invitacion(Base):
    """El enlace que recibe un firmante. El token solo existe en ese enlace."""

    __tablename__ = "invitaciones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contrato_id: Mapped[str] = mapped_column(ForeignKey("contratos.id"), index=True)
    parte_id: Mapped[str] = mapped_column(ForeignKey("partes_contrato.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVA")
    expira_en: Mapped[datetime] = mapped_column(FechaUtc)
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    abierta_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)


class SesionFirma(Base):
    """Estado del firmante mientras recorre el portal: autenticado, consintio, etc."""

    __tablename__ = "sesiones_firma"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contrato_id: Mapped[str] = mapped_column(ForeignKey("contratos.id"), index=True)
    parte_id: Mapped[str] = mapped_column(ForeignKey("partes_contrato.id"), index=True)
    invitacion_id: Mapped[str] = mapped_column(ForeignKey("invitaciones.id"))
    autenticada: Mapped[bool] = mapped_column(Boolean, default=False)
    metodo_autenticacion: Mapped[str | None] = mapped_column(String(30), nullable=True)
    latitud: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitud: Mapped[float | None] = mapped_column(Float, nullable=True)
    precision_m: Mapped[float | None] = mapped_column(Float, nullable=True)
    ubicacion_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(60), nullable=True)
    agente: Mapped[str | None] = mapped_column(String(400), nullable=True)
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    expira_en: Mapped[datetime] = mapped_column(FechaUtc)


class DesafioOtp(Base):
    """Un codigo de un solo uso. Se guarda hasheado, nunca en claro."""

    __tablename__ = "desafios_otp"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    sesion_id: Mapped[str] = mapped_column(ForeignKey("sesiones_firma.id"), index=True)
    canal: Mapped[str] = mapped_column(String(10))
    destino_enmascarado: Mapped[str] = mapped_column(String(120))
    codigo_hash: Mapped[str] = mapped_column(String(64))
    intentos: Mapped[int] = mapped_column(Integer, default=0)
    estado: Mapped[str] = mapped_column(String(20), default="PENDIENTE")
    creado_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    expira_en: Mapped[datetime] = mapped_column(FechaUtc)
    verificado_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)


class Evidencia(Base):
    """Todo lo que se sabe sobre como ocurrio una firma concreta."""

    __tablename__ = "evidencias"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contrato_id: Mapped[str] = mapped_column(ForeignKey("contratos.id"), index=True)
    parte_id: Mapped[str] = mapped_column(ForeignKey("partes_contrato.id"))
    datos: Mapped[dict] = mapped_column(JSON, default=dict)
    hash_evidencia: Mapped[str] = mapped_column(String(64))
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)


class Firma(Base):
    __tablename__ = "firmas"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contrato_id: Mapped[str] = mapped_column(ForeignKey("contratos.id"), index=True)
    parte_id: Mapped[str] = mapped_column(ForeignKey("partes_contrato.id"))
    evidencia_id: Mapped[str] = mapped_column(ForeignKey("evidencias.id"))
    proveedor: Mapped[str] = mapped_column(String(30))
    algoritmo: Mapped[str] = mapped_column(String(30))
    valor: Mapped[str] = mapped_column(Text)
    hash_documento_al_firmar: Mapped[str] = mapped_column(String(64))
    firmado_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)


class EventoAuditoria(Base):
    """
    Append-only y encadenado: cada evento incluye el hash del anterior del mismo
    contrato. Borrar o alterar uno intermedio rompe la cadena y se detecta.
    """

    __tablename__ = "eventos_auditoria"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contrato_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    secuencia: Mapped[int] = mapped_column(Integer)
    tipo: Mapped[str] = mapped_column(String(40))
    actor_tipo: Mapped[str] = mapped_column(String(20))
    actor_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    datos: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str | None] = mapped_column(String(60), nullable=True)
    agente: Mapped[str | None] = mapped_column(String(400), nullable=True)
    hash_anterior: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hash: Mapped[str] = mapped_column(String(64))
    creado_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)


class EndpointWebhook(Base):
    __tablename__ = "endpoints_webhook"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    secreto_cifrado: Mapped[str] = mapped_column(Text)
    eventos: Mapped[list] = mapped_column(JSON, default=list)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVO")
    fallos_consecutivos: Mapped[int] = mapped_column(Integer, default=0)
    creado_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)


class EntregaWebhook(Base):
    __tablename__ = "entregas_webhook"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints_webhook.id"), index=True)
    evento_id: Mapped[str] = mapped_column(String(36), index=True)
    tipo_evento: Mapped[str] = mapped_column(String(40))
    contrato_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    estado: Mapped[str] = mapped_column(String(20), default="PENDIENTE", index=True)
    intentos: Mapped[int] = mapped_column(Integer, default=0)
    proximo_intento_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    ultimo_codigo: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ultimo_error: Mapped[str | None] = mapped_column(String(400), nullable=True)
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
    entregada_en: Mapped[datetime | None] = mapped_column(FechaUtc, nullable=True)


class ClaveIdempotencia(Base):
    """
    Guarda la respuesta de una creacion para devolver lo mismo si el integrador
    reintenta por un timeout, en vez de crear un contrato duplicado.
    """

    __tablename__ = "claves_idempotencia"
    __table_args__ = (
        UniqueConstraint("tenant_id", "credencial_id", "clave", name="uq_idempotencia"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_id)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    credencial_id: Mapped[str] = mapped_column(String(36))
    clave: Mapped[str] = mapped_column(String(200))
    hash_peticion: Mapped[str] = mapped_column(String(64))
    codigo_respuesta: Mapped[int] = mapped_column(Integer)
    cuerpo_respuesta: Mapped[dict] = mapped_column(JSON, default=dict)
    creada_en: Mapped[datetime] = mapped_column(FechaUtc, default=ahora_utc)
