"""
Preparacion del entorno de pruebas.

Las variables de entorno se fijan ANTES de importar la aplicacion, porque el
motor de base de datos y la configuracion se crean al importar.
"""
import os
import secrets
import tempfile
from pathlib import Path

_TEMPORAL = Path(tempfile.mkdtemp(prefix="pruebas-contratos-"))
os.environ["ENTORNO"] = "pruebas"
os.environ["URL_BASE_DATOS"] = f"sqlite:///{_TEMPORAL / 'pruebas.db'}"
os.environ["CARPETA_ALMACEN"] = str(_TEMPORAL / "almacen")
os.environ["CLAVE_APP"] = secrets.token_hex(32)
os.environ["URL_PUBLICA"] = "http://testserver"
os.environ["PERMITIR_WEBHOOK_PRIVADO"] = "true"
os.environ["MOSTRAR_SECRETOS_EN_LOG"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import FabricaSesion, crear_tablas  # noqa: E402
from app.dependencias import reiniciar_limites  # noqa: E402
from app.main import app  # noqa: E402
from app.models import CredencialApi, Tenant  # noqa: E402
from app.seguridad import hash_secreto, token_aleatorio  # noqa: E402

PERMISOS = [
    "contratos:crear", "contratos:leer", "contratos:anular",
    "contratos:descargar", "plantillas:administrar",
]


@pytest.fixture(scope="session", autouse=True)
def _preparar_base():
    crear_tablas()


@pytest.fixture(autouse=True)
def _limpiar_limites():
    reiniciar_limites()
    yield
    reiniciar_limites()


@pytest.fixture
def cliente():
    with TestClient(app) as c:
        yield c


def _crear_empresa(nombre: str) -> tuple[str, tuple[str, str]]:
    with FabricaSesion() as sesion:
        tenant = Tenant(nombre=nombre, slug=f"{nombre.lower()}-{token_aleatorio(4)}")
        sesion.add(tenant)
        sesion.flush()
        secreto = token_aleatorio(16)
        credencial = CredencialApi(
            tenant_id=tenant.id,
            nombre="pruebas",
            client_id=f"cli_{token_aleatorio(6)}",
            secreto_hash=hash_secreto(secreto),
            permisos=PERMISOS,
        )
        sesion.add(credencial)
        sesion.commit()
        return tenant.id, (credencial.client_id, secreto)


@pytest.fixture
def empresa():
    """Una empresa con su credencial B2B lista para usar."""
    _, auth = _crear_empresa("Acme")
    return auth


@pytest.fixture
def otra_empresa():
    """Una segunda empresa, para comprobar el aislamiento entre tenants."""
    _, auth = _crear_empresa("Rival")
    return auth


@pytest.fixture
def otp_fijo(monkeypatch):
    """Fija el codigo OTP para poder recorrer el flujo de firma en las pruebas."""
    from app.portal import firma as modulo_firma

    monkeypatch.setattr(modulo_firma, "codigo_otp", lambda digitos=6: "123456")
    return "123456"
