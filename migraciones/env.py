"""
Entorno de Alembic.

La URL sale de la misma configuracion que el servicio (URL_BASE_DATOS), asi
las migraciones y la aplicacion nunca apuntan a bases distintas. Quien llame
desde codigo (las pruebas) puede fijar otra con sqlalchemy.url.
"""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app import models  # noqa: F401  (registra los modelos en Base)
from app.config import ajustes
from app.db import Base, FechaUtc

config = context.config

if config.config_file_name is not None and config.attributes.get("configurar_logs", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

if not config.get_main_option("sqlalchemy.url"):
    # configparser trata "%" como interpolacion: una clave con "%" romperia la URL.
    config.set_main_option("sqlalchemy.url", ajustes().url_sqlalchemy.replace("%", "%%"))

objetivo = Base.metadata


def _render_item(tipo, objeto, _contexto):
    """
    FechaUtc se guarda en la base como un DateTime normal: la conversion a UTC
    vive en Python. Asi las migraciones no dependen del codigo de la app.
    """
    if tipo == "type" and isinstance(objeto, FechaUtc):
        return "sa.DateTime()"
    return False


def _opciones(es_sqlite: bool) -> dict:
    return {
        "target_metadata": objetivo,
        "render_item": _render_item,
        "compare_type": True,
        # SQLite no sabe hacer ALTER de columnas: Alembic recrea la tabla.
        "render_as_batch": es_sqlite,
    }


def correr_sin_conexion() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, literal_binds=True, **_opciones(url.startswith("sqlite")))
    with context.begin_transaction():
        context.run_migrations()


def correr_con_conexion() -> None:
    motor = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with motor.connect() as conexion:
        context.configure(connection=conexion, **_opciones(conexion.dialect.name == "sqlite"))
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    correr_sin_conexion()
else:
    correr_con_conexion()
