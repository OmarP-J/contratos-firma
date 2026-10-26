"""
Crea una empresa de ejemplo con su credencial y una plantilla publicada.

    python -m scripts.sembrar
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import FabricaSesion, crear_tablas  # noqa: E402
from app.dominio import credenciales  # noqa: E402
from app.dominio.contratos import publicar_plantilla  # noqa: E402
from app.models import Tenant  # noqa: E402

CUERPO = """
<p>Entre <strong>ACME Servicios SRL</strong>, en lo adelante EL PRESTADOR, y
{{ cliente.nombre }}, portador de la cedula {{ cliente.cedula }}, en lo adelante EL CLIENTE,
se acuerda lo siguiente.</p>

<h2>Primera: Objeto</h2>
<p>EL PRESTADOR se obliga a suministrar el servicio {{ servicio.nombre }} en la direccion
{{ cliente.direccion }}, conforme a las condiciones aqui pactadas.</p>

<h2>Segunda: Precio y forma de pago</h2>
<p>EL CLIENTE pagara la suma de RD$ {{ servicio.precio }} mensuales durante
{{ servicio.meses }} meses, pagaderos el dia cinco de cada mes.</p>

<h2>Tercera: Vigencia</h2>
<p>El presente contrato entra en vigor el {{ servicio.inicio }} y se regira por la
legislacion de la Republica Dominicana.</p>
"""

SCHEMA = {
    "cliente.nombre": {"tipo": "texto", "requerido": True, "max_largo": 150},
    "cliente.cedula": {"tipo": "cedula", "requerido": True},
    "cliente.direccion": {"tipo": "texto", "requerido": True, "max_largo": 300},
    "servicio.nombre": {"tipo": "texto", "requerido": True, "max_largo": 120},
    "servicio.precio": {"tipo": "dinero", "requerido": True, "minimo": 0},
    "servicio.meses": {"tipo": "entero", "requerido": True, "minimo": 1, "maximo": 120},
    "servicio.inicio": {"tipo": "fecha", "requerido": True},
}


def sembrar() -> dict:
    crear_tablas()
    with FabricaSesion() as sesion:
        tenant = Tenant(nombre="ACME Servicios SRL", slug="acme")
        sesion.add(tenant)
        sesion.flush()

        credencial, secreto = credenciales.crear(
            sesion, tenant.id, nombre="Integracion principal",
            permisos=list(credenciales.PERMISOS),
        )
        plantilla, _ = publicar_plantilla(
            sesion,
            tenant.id,
            codigo="contrato_servicio",
            nombre="Contrato de servicio",
            titulo="Contrato de Servicio",
            cuerpo=CUERPO,
            schema_variables=SCHEMA,
            politica={"requiere_otp": True, "requiere_firma_empresa": True},
        )
        sesion.commit()

        return {
            "tenant": tenant.nombre,
            "client_id": credencial.client_id,
            "client_secret": secreto,
            "plantilla": plantilla.codigo,
        }


if __name__ == "__main__":
    datos = sembrar()
    print("\nEmpresa de ejemplo creada\n")
    for clave, valor in datos.items():
        print(f"  {clave:15} {valor}")
    print("\nGuarda el client_secret: no se vuelve a mostrar.\n")
