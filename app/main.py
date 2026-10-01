"""
Arranque de la aplicacion.

Aqui se montan las rutas, las cabeceras de seguridad y la traduccion de errores
del dominio a respuestas HTTP.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.api.v1_contratos import router as router_b2b
from app.config import ajustes
from app.db import crear_tablas
from app.dominio.contratos import ErrorDeNegocio, NoEncontrado
from app.dominio.estados import TransicionInvalida
from app.dominio.firma import proveedor_actual
from app.dominio.plantillas import PlantillaInvalida
from app.dominio.variables import DatosInvalidos
from app.portal.firma import router as router_portal

app = FastAPI(
    title="Servicio B2B de contratos y firma electronica",
    version="0.1.0",
    description=(
        "Genera contratos desde plantillas versionadas, los envia a firma, recopila "
        "evidencias, custodia el documento final y notifica por webhook."
    ),
)


@app.on_event("startup")
def preparar() -> None:
    crear_tablas()


@app.middleware("http")
async def cabeceras_de_seguridad(request: Request, call_next):
    """
    Cabeceras que aplican a todo. Las rutas que necesitan una CSP mas fina
    (como el documento dentro del iframe) la ponen ellas y esta no la pisa.
    """
    respuesta = await call_next(request)
    respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
    respuesta.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    respuesta.headers.setdefault("X-Frame-Options", "DENY")
    respuesta.headers.setdefault(
        "Permissions-Policy", "geolocation=(self), camera=(), microphone=(), payment=()"
    )
    if ajustes().es_produccion:
        respuesta.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return respuesta


def _json(codigo: int, error: str, mensaje: str, detalles: dict | None = None) -> JSONResponse:
    cuerpo: dict = {"error": error, "mensaje": mensaje}
    if detalles:
        cuerpo["detalles"] = detalles
    return JSONResponse(status_code=codigo, content=cuerpo)


@app.exception_handler(NoEncontrado)
async def _no_encontrado(_: Request, error: NoEncontrado):
    # Un recurso de otra empresa responde esto, no 403: no confirmamos que exista.
    return _json(status.HTTP_404_NOT_FOUND, "no_encontrado", str(error))


@app.exception_handler(DatosInvalidos)
async def _datos_invalidos(_: Request, error: DatosInvalidos):
    return _json(
        status.HTTP_400_BAD_REQUEST,
        "variables_invalidas",
        "Hay variables invalidas o no declaradas en la plantilla",
        error.detalles,
    )


@app.exception_handler(PlantillaInvalida)
async def _plantilla_invalida(_: Request, error: PlantillaInvalida):
    return _json(status.HTTP_400_BAD_REQUEST, "plantilla_invalida", str(error))


@app.exception_handler(TransicionInvalida)
async def _transicion(_: Request, error: TransicionInvalida):
    return _json(status.HTTP_409_CONFLICT, "estado_invalido", str(error))


@app.exception_handler(ErrorDeNegocio)
async def _negocio(_: Request, error: ErrorDeNegocio):
    return _json(status.HTTP_400_BAD_REQUEST, "solicitud_invalida", str(error))


@app.exception_handler(HTTPException)
async def _http(_: Request, error: HTTPException):
    """
    Deja la respuesta de error plana: {"error", "mensaje", "detalles"}.

    FastAPI por defecto envuelve todo en {"detail": ...}, lo que obliga al
    integrador a desenvolver una capa que no aporta nada.
    """
    if isinstance(error.detail, dict):
        return JSONResponse(
            status_code=error.status_code, content=error.detail, headers=error.headers
        )
    return JSONResponse(
        status_code=error.status_code,
        content={"error": "error", "mensaje": str(error.detail)},
        headers=error.headers,
    )


@app.get("/salud", tags=["servicio"])
def salud() -> dict:
    return {"estado": "ok", "entorno": ajustes().entorno}


@app.get("/.well-known/clave-de-firma", tags=["servicio"])
def clave_de_firma() -> dict:
    """
    Clave publica del proveedor de firma, para que un tercero pueda verificar
    por su cuenta las firmas que emitimos.
    """
    return {"proveedor": proveedor_actual.nombre, "clave_publica": proveedor_actual.clave_publica()}


app.include_router(router_b2b)
app.include_router(router_portal)
