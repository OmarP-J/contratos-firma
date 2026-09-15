"""
Configuracion del servicio.

Todo entra por variables de entorno. No hay valores distintos escondidos en el
codigo segun el entorno, ni secretos en el repositorio.
"""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Ajustes(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    entorno: str = "desarrollo"
    puerto: int = 8000
    url_publica: str = "http://localhost:8000"

    # Vacia -> SQLite local. Con valor -> ese motor (por ejemplo PostgreSQL).
    url_base_datos: str = ""

    clave_app: str = "0" * 64
    carpeta_almacen: str = "./almacen"

    minutos_invitacion: int = 60 * 24 * 3
    minutos_otp: int = 10
    intentos_maximos_otp: int = 5

    permitir_webhook_privado: bool = False
    mostrar_secretos_en_log: bool = True

    # Proxies de confianza para aceptar la cabecera X-Forwarded-For.
    proxies_confiables: str = ""

    @property
    def es_produccion(self) -> bool:
        return self.entorno == "produccion"

    @property
    def url_sqlalchemy(self) -> str:
        if self.url_base_datos:
            return self.url_base_datos
        return f"sqlite:///{Path('contratos.db').resolve()}"


@lru_cache
def ajustes() -> Ajustes:
    config = Ajustes()
    if config.es_produccion:
        if len(config.clave_app) < 64 or set(config.clave_app) == {"0"}:
            raise RuntimeError("CLAVE_APP debe ser una clave real de 32 bytes en produccion")
        if config.mostrar_secretos_en_log:
            raise RuntimeError("MOSTRAR_SECRETOS_EN_LOG no puede estar activo en produccion")
    return config
