"""
Contratos de entrada y salida de la API.

Todos los modelos de entrada llevan extra="forbid": si llega una propiedad que
no esta declarada, la peticion se rechaza. Es la lista blanca del documento
aplicada ya en el borde HTTP, antes de que nada toque el dominio.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EntradaEstricta(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class FirmanteEntrada(EntradaEstricta):
    rol: Literal["CLIENTE", "EMPRESA"] = "CLIENTE"
    nombre: str = Field(min_length=2, max_length=200)
    documento: str | None = Field(default=None, max_length=30)
    email: str | None = Field(default=None, max_length=254)
    telefono: str | None = Field(default=None, max_length=20)


class CrearContrato(EntradaEstricta):
    plantilla: str = Field(min_length=1, max_length=120)
    version: int | None = Field(default=None, ge=1)
    referencia_externa: str | None = Field(default=None, max_length=120)
    firmantes: list[FirmanteEntrada] = Field(min_length=1, max_length=10)
    variables: dict[str, Any] = Field(default_factory=dict)
    enviar_ahora: bool = True


class AnularContrato(EntradaEstricta):
    motivo: str | None = Field(default=None, max_length=300)


class RegistrarWebhook(EntradaEstricta):
    url: str = Field(min_length=8, max_length=500)
    eventos: list[str] | None = None


class CrearPlantilla(EntradaEstricta):
    codigo: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_]*$")
    nombre: str = Field(min_length=3, max_length=200)
    titulo: str = Field(min_length=3, max_length=200)
    cuerpo: str = Field(min_length=10)
    schema_variables: dict[str, Any]
    politica: dict[str, Any] | None = None


class RespuestaError(BaseModel):
    error: str
    mensaje: str
    detalles: dict[str, Any] | None = None
