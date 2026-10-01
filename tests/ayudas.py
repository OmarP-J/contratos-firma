"""Utilidades compartidas por las pruebas."""
from __future__ import annotations

import re

CUERPO_PLANTILLA = (
    "<p>Yo, {{ cliente.nombre }}, portador de la cedula {{ cliente.cedula }}, "
    "contrato el servicio {{ servicio.nombre }} por un valor de RD$ "
    "{{ servicio.precio }} mensuales.</p>"
)

SCHEMA = {
    "cliente.nombre": {"tipo": "texto", "requerido": True, "max_largo": 150},
    "cliente.cedula": {"tipo": "cedula", "requerido": True},
    "servicio.nombre": {"tipo": "texto", "requerido": True},
    "servicio.precio": {"tipo": "dinero", "requerido": True, "minimo": 0},
}

VARIABLES = {
    "cliente": {"nombre": "Juan Perez", "cedula": "402-2118261-7"},
    "servicio": {"nombre": "Plan Premium", "precio": "12500"},
}


def crear_plantilla(cliente, auth, *, codigo="contrato_servicio", politica=None, cuerpo=None):
    respuesta = cliente.post(
        "/v1/plantillas",
        auth=auth,
        json={
            "codigo": codigo,
            "nombre": "Contrato de servicio",
            "titulo": "Contrato de Servicio",
            "cuerpo": cuerpo or CUERPO_PLANTILLA,
            "schema_variables": SCHEMA,
            "politica": politica or {"requiere_otp": True, "requiere_firma_empresa": False},
        },
    )
    assert respuesta.status_code == 201, respuesta.text
    return respuesta.json()


def crear_contrato(cliente, auth, *, variables=None, firmantes=None, **extra):
    cuerpo = {
        "plantilla": extra.pop("plantilla", "contrato_servicio"),
        "referencia_externa": extra.pop("referencia_externa", "SOL-839291"),
        "firmantes": firmantes
        or [{"rol": "CLIENTE", "nombre": "Juan Perez", "documento": "40221182617",
             "email": "juan@example.com"}],
        "variables": VARIABLES if variables is None else variables,
    }
    cuerpo.update(extra)
    return cliente.post("/v1/contratos", auth=auth, json=cuerpo)


def token_de(url_firma: str) -> str:
    return url_firma.rstrip("/").split("/")[-1]


def csrf_de(html: str) -> str:
    encontrado = re.search(r'name="csrf" value="([^"]+)"', html)
    assert encontrado, "no se encontro el token csrf en la pagina"
    return encontrado.group(1)


def firmar_como(cliente, token: str, codigo: str = "123456", **datos_extra) -> None:
    """Recorre el portal completo: abrir, pedir codigo, verificar, aceptar y firmar."""
    pagina = cliente.get(f"/firma/{token}", follow_redirects=True)
    assert pagina.status_code == 200, pagina.text

    csrf = csrf_de(pagina.text)
    envio = cliente.post(f"/firma/{token}/codigo", data={"csrf": csrf})
    assert envio.status_code == 200, envio.text

    csrf = csrf_de(envio.text)
    verificacion = cliente.post(
        f"/firma/{token}/verificar", data={"csrf": csrf, "codigo": codigo},
        follow_redirects=True,
    )
    assert verificacion.status_code == 200, verificacion.text

    csrf = csrf_de(verificacion.text)
    datos = {"csrf": csrf, "acepto": "si"}
    datos.update(datos_extra)
    firma = cliente.post(f"/firma/{token}/firmar", data=datos, follow_redirects=True)
    assert firma.status_code == 200, firma.text
