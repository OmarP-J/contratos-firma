"""
Conexion a la base de datos.

Por defecto usa SQLite en un archivo local para que el proyecto arranque sin
instalar nada. Cambiando URL_BASE_DATOS se pasa a PostgreSQL sin tocar codigo:
los modelos y las consultas son las mismas.
"""
from collections.abc import Iterator
from datetime import datetime, timezone

from sqlalchemy import DateTime, TypeDecorator, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import ajustes


class Base(DeclarativeBase):
    pass


class FechaUtc(TypeDecorator):
    """
    Columna de fecha que SIEMPRE guarda y devuelve fechas con zona horaria UTC.

    Existe porque SQLite no almacena la zona horaria. Sin esto, una fecha
    guardada como "con zona" vuelve del disco "sin zona", y una evidencia de
    cuando se firmo un contrato que no sabe de que zona habla no prueba nada.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("No se admiten fechas sin zona horaria")
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


def ahora_utc() -> datetime:
    """El instante actual, con zona horaria. Nunca usar datetime.now() pelado."""
    return datetime.now(timezone.utc)


_config = ajustes()
_es_sqlite = _config.url_sqlalchemy.startswith("sqlite")

motor = create_engine(
    _config.url_sqlalchemy,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if _es_sqlite else {},
)

if _es_sqlite:

    @event.listens_for(motor, "connect")
    def _configurar_sqlite(conexion, _registro):
        cursor = conexion.cursor()
        # Sin esto SQLite ignora las llaves foraneas en silencio.
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


FabricaSesion = sessionmaker(bind=motor, autoflush=False, expire_on_commit=False)


def obtener_sesion() -> Iterator[Session]:
    """Dependencia de FastAPI: una sesion por peticion, cerrada al terminar."""
    sesion = FabricaSesion()
    try:
        yield sesion
    finally:
        sesion.close()


def crear_tablas() -> None:
    from app import models  # noqa: F401  (registra los modelos en Base)

    Base.metadata.create_all(motor)
