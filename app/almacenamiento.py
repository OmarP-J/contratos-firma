"""
Almacenamiento de documentos.

Los documentos no viven en la base de datos. Se guardan aparte, con claves
impredecibles, y la descarga siempre se autoriza en el backend antes de
entregar el archivo.

Hoy la implementacion es en disco local. Cambiarla por S3 es implementar esta
misma interfaz; ninguna otra parte del servicio se entera.
"""
from __future__ import annotations

import re
from pathlib import Path

from app.config import ajustes
from app.seguridad import token_aleatorio

CLAVE_VALIDA = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


class AlmacenLocal:
    def __init__(self, raiz: str | None = None) -> None:
        self.raiz = Path(raiz or ajustes().carpeta_almacen).resolve()
        self.raiz.mkdir(parents=True, exist_ok=True)

    def _ruta(self, clave: str) -> Path:
        if not CLAVE_VALIDA.match(clave) or ".." in clave:
            raise ValueError("Clave de documento invalida")
        ruta = (self.raiz / clave).resolve()
        # Defensa contra travesia de directorios.
        if not str(ruta).startswith(str(self.raiz) + "/"):
            raise ValueError("Clave fuera del almacen")
        return ruta

    def guardar(self, clave: str, contenido: bytes) -> None:
        ruta = self._ruta(clave)
        ruta.parent.mkdir(parents=True, exist_ok=True)
        ruta.write_bytes(contenido)
        ruta.chmod(0o600)

    def leer(self, clave: str) -> bytes:
        return self._ruta(clave).read_bytes()

    def existe(self, clave: str) -> bool:
        return self._ruta(clave).exists()


def nueva_clave(tenant_id: str, contrato_id: str, sufijo: str) -> str:
    """Clave impredecible: conocer el tenant y el contrato no basta para adivinarla."""
    return f"{tenant_id}/{contrato_id}/{token_aleatorio(16)}-{sufijo}"


almacen = AlmacenLocal()
