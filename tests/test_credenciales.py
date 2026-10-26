"""Alta y revocacion de credenciales B2B desde el dominio."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db import FabricaSesion
from app.dominio import credenciales
from app.models import CredencialApi


def _tenant_de(auth) -> str:
    with FabricaSesion() as sesion:
        return sesion.scalars(
            select(CredencialApi.tenant_id).where(CredencialApi.client_id == auth[0])
        ).one()


def test_una_credencial_nueva_sirve_y_al_revocarla_deja_de_servir(cliente, empresa):
    tenant_id = _tenant_de(empresa)
    with FabricaSesion() as sesion:
        credencial, secreto = credenciales.crear(
            sesion, tenant_id, nombre="Integracion CRM", permisos=["contratos:leer"]
        )
        sesion.commit()
        auth = (credencial.client_id, secreto)
        assert secreto not in credencial.secreto_hash

    assert cliente.get("/v1/contratos", auth=auth).status_code == 200
    # Solo tiene el permiso que se le dio.
    assert cliente.post("/v1/webhooks", auth=auth, json={"url": "https://x.com"}).status_code == 403

    with FabricaSesion() as sesion:
        credenciales.revocar(credenciales.obtener(sesion, tenant_id, credencial.id))
        sesion.commit()
    assert cliente.get("/v1/contratos", auth=auth).status_code == 401


@pytest.mark.parametrize(
    "nombre, permisos",
    [("Integracion", ["contratos:borrar_todo"]), ("Integracion", []), ("x", ["contratos:leer"])],
)
def test_datos_invalidos(empresa, nombre, permisos):
    with FabricaSesion() as sesion, pytest.raises(credenciales.CredencialInvalida):
        credenciales.crear(sesion, _tenant_de(empresa), nombre=nombre, permisos=permisos)


def test_no_se_ve_ni_se_revoca_una_credencial_ajena(empresa, otra_empresa):
    with FabricaSesion() as sesion:
        ajena = credenciales.listar(sesion, _tenant_de(otra_empresa))[0]
        assert credenciales.obtener(sesion, _tenant_de(empresa), ajena.id) is None
