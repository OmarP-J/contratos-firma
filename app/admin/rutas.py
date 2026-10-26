"""
Portal administrativo de cada empresa.

Lo que hasta ahora solo se podia hacer por API, con una interfaz web: la
bandeja de contratos, el detalle con su linea de auditoria, reenviar o anular,
publicar plantillas y dar de alta o revocar credenciales.

Seguridad, ademas de la del dominio (dominio/administradores.py):
  - Cookie HttpOnly, SameSite=Strict, limitada a /admin y Secure en produccion.
  - CSRF en todo formulario: un HMAC del id de sesion, como en el portal de firma.
  - Todo se filtra por la empresa del usuario. Lo ajeno responde 404.
  - Las acciones sobre un contrato quedan en su auditoria con actor ADMIN; las
    de la empresa (plantillas, credenciales, accesos), en la de la empresa.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import segno
from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.almacenamiento import almacen
from app.config import ajustes
from app.db import obtener_sesion
from app.dependencias import ip_observada, limitar
from app.dominio import administradores, auditoria, contratos as servicio, credenciales
from app.dominio.contratos import Contexto, ErrorDeNegocio, NoEncontrado
from app.dominio.estados import Estado, TransicionInvalida, es_final
from app.dominio.plantillas import PlantillaInvalida
from app.dominio.variables import DatosInvalidos
from app.models import Plantilla, SesionAdmin, Tenant, UsuarioAdmin
from app.schemas import CrearPlantilla
from app.seguridad import comparar_seguro, derivar_clave, hmac_sha256
from app.tareas import despachar_en_linea

router = APIRouter(prefix="/admin", include_in_schema=False)
plantillas = Jinja2Templates(directory=str(Path(__file__).parent / "plantillas"))

COOKIE = "admin_sesion"
PENDIENTES = (Estado.PENDIENTE_CLIENTE.value, Estado.PENDIENTE_EMPRESA.value)
AVISOS = {
    "anulado": "El contrato quedo anulado y sus enlaces de firma dejaron de servir.",
    "publicada": "La version nueva de la plantilla quedo publicada.",
    "revocada": "La credencial quedo revocada. Las llamadas con ella ya responden 401.",
    "salida": "Cerraste la sesion.",
}


def _fecha(valor) -> str:
    if valor is None:
        return "-"
    if isinstance(valor, str):
        valor = datetime.fromisoformat(valor.replace("Z", "+00:00"))
    return valor.strftime("%d/%m/%Y %H:%M UTC")


plantillas.env.filters["fecha"] = _fecha


class Redirigir(Exception):
    """Se traduce a un 303 en main.py. Lo usan las dependencias de acceso."""

    def __init__(self, destino: str) -> None:
        self.destino = destino
        super().__init__(destino)


@dataclass
class Admin:
    sesion_admin: SesionAdmin
    usuario: UsuarioAdmin
    tenant: Tenant

    @property
    def tenant_id(self) -> str:
        return self.tenant.id

    @property
    def csrf(self) -> str:
        return hmac_sha256(derivar_clave("csrf-admin"), self.sesion_admin.id)


# ---------------------------------------------------------------------------
# Acceso
# ---------------------------------------------------------------------------

def admin_sin_mfa(request: Request, sesion: Session = Depends(obtener_sesion)) -> Admin:
    """Clave verificada; el segundo factor puede faltar todavia."""
    sesion_admin = administradores.sesion_vigente(sesion, request.cookies.get(COOKIE))
    if sesion_admin is None:
        raise Redirigir("/admin/entrar")
    sesion.commit()  # guarda la renovacion por uso
    return Admin(
        sesion_admin,
        sesion.get(UsuarioAdmin, sesion_admin.usuario_id),
        sesion.get(Tenant, sesion_admin.tenant_id),
    )


def admin_actual(admin: Admin = Depends(admin_sin_mfa)) -> Admin:
    if not admin.sesion_admin.mfa_verificada:
        raise Redirigir("/admin/mfa")
    return admin


def _exigir_csrf(admin: Admin, enviado: str) -> None:
    if not comparar_seguro(admin.csrf, enviado or ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "csrf", "mensaje": "La solicitud no es valida. Recarga la pagina."},
        )


def _contexto(admin: Admin, request: Request) -> Contexto:
    return Contexto(
        tenant_id=admin.tenant_id,
        actor_tipo="ADMIN",
        actor_id=admin.usuario.id,
        ip=ip_observada(request),
        agente=request.headers.get("user-agent"),
    )


def _registrar_en_empresa(sesion: Session, admin: Admin, request: Request, tipo: str, datos=None):
    auditoria.registrar(
        sesion, tenant_id=admin.tenant_id, contrato_id=None, tipo=tipo,
        actor_tipo="ADMIN", actor_id=admin.usuario.id, datos=datos or {},
        ip=ip_observada(request), agente=request.headers.get("user-agent"),
    )


def _pagina(request: Request, nombre: str, admin: Admin | None = None, codigo: int = 200, **datos):
    contexto = {"admin": admin, "csrf": admin.csrf if admin else "", **datos}
    return plantillas.TemplateResponse(request, nombre, contexto, status_code=codigo)


def _poner_cookie(respuesta: Response, token: str) -> None:
    respuesta.set_cookie(
        COOKIE, token, httponly=True, samesite="strict", path="/admin",
        secure=ajustes().es_produccion or ajustes().url_publica.startswith("https://"),
    )


@router.get("/entrar", response_class=HTMLResponse)
def ver_entrar(request: Request, aviso: str | None = None, sesion: Session = Depends(obtener_sesion)):
    vigente = administradores.sesion_vigente(sesion, request.cookies.get(COOKIE))
    if vigente is not None and vigente.mfa_verificada:
        return RedirectResponse("/admin/contratos", status_code=303)
    return _pagina(request, "entrar.html", aviso=AVISOS.get(aviso or ""))


@router.post("/entrar", response_class=HTMLResponse)
def entrar(
    request: Request,
    email: str = Form(default=""),
    clave: str = Form(default=""),
    sesion: Session = Depends(obtener_sesion),
):
    limitar(f"admin-entrar:{ip_observada(request)}", limite=10, ventana_s=60)
    try:
        _, token = administradores.autenticar(
            sesion, email, clave, ip=ip_observada(request),
            agente=request.headers.get("user-agent"),
        )
    except administradores.AccesoDenegado as error:
        sesion.commit()  # guarda el intento fallido y un posible bloqueo
        return _pagina(request, "entrar.html", codigo=401, error=str(error), email=email)
    sesion.commit()
    respuesta = RedirectResponse("/admin/mfa", status_code=303)
    _poner_cookie(respuesta, token)
    return respuesta


@router.get("/mfa", response_class=HTMLResponse)
def ver_mfa(request: Request, admin: Admin = Depends(admin_sin_mfa),
            sesion: Session = Depends(obtener_sesion)):
    if admin.sesion_admin.mfa_verificada:
        return RedirectResponse("/admin/contratos", status_code=303)
    return _pagina_mfa(request, admin, sesion)


def _pagina_mfa(request: Request, admin: Admin, sesion: Session, codigo: int = 200, error=None):
    datos = {"error": error, "registrar": not admin.usuario.mfa_activo}
    if datos["registrar"]:
        secreto, uri = administradores.secreto_pendiente(sesion, admin.usuario)
        sesion.commit()
        datos["secreto"] = " ".join(secreto[i:i + 4] for i in range(0, len(secreto), 4))
        datos["qr"] = segno.make(uri, error="m").svg_inline(scale=5, border=2)
    return _pagina(request, "mfa.html", admin, codigo=codigo, **datos)


@router.post("/mfa", response_class=HTMLResponse)
def verificar_mfa(
    request: Request,
    codigo: str = Form(default=""),
    csrf: str = Form(default=""),
    admin: Admin = Depends(admin_sin_mfa),
    sesion: Session = Depends(obtener_sesion),
):
    _exigir_csrf(admin, csrf)
    limitar(f"admin-mfa:{admin.sesion_admin.id}", limite=10, ventana_s=60)
    if administradores.verificar_segundo_factor(
        sesion, admin.sesion_admin, codigo, ip=ip_observada(request)
    ):
        sesion.commit()
        return RedirectResponse("/admin/contratos", status_code=303)
    sesion.commit()
    if admin.sesion_admin.cerrada_en is not None:
        respuesta = _pagina(
            request, "entrar.html", codigo=401,
            error="Demasiados codigos incorrectos. Vuelve a entrar con tu clave.",
        )
        respuesta.delete_cookie(COOKIE, path="/admin")
        return respuesta
    return _pagina_mfa(request, admin, sesion, codigo=400, error="El codigo no es correcto.")


@router.post("/salir")
def salir(csrf: str = Form(default=""), admin: Admin = Depends(admin_sin_mfa),
          sesion: Session = Depends(obtener_sesion)):
    _exigir_csrf(admin, csrf)
    administradores.cerrar(sesion, admin.sesion_admin)
    sesion.commit()
    respuesta = RedirectResponse("/admin/entrar?aviso=salida", status_code=303)
    respuesta.delete_cookie(COOKIE, path="/admin")
    return respuesta


# ---------------------------------------------------------------------------
# Contratos
# ---------------------------------------------------------------------------

@router.get("")
@router.get("/")
def inicio(_: Admin = Depends(admin_actual)):
    return RedirectResponse("/admin/contratos", status_code=303)


@router.get("/contratos", response_class=HTMLResponse)
def bandeja(
    request: Request,
    estado: str = Query(default="pendientes"),
    referencia: str = Query(default="", max_length=120),
    cursor: str | None = Query(default=None, max_length=300),
    aviso: str | None = None,
    admin: Admin = Depends(admin_actual),
    sesion: Session = Depends(obtener_sesion),
):
    filtro: dict = {}
    if estado == "pendientes":
        filtro["estados"] = PENDIENTES
    elif estado in {e.value for e in Estado}:
        filtro["estado"] = estado
    else:
        estado = "todos"
    try:
        despues_de = servicio.leer_cursor(cursor) if cursor else None
    except ValueError:
        despues_de = None

    filas = servicio.listar(
        sesion, admin.tenant_id, referencia_externa=referencia.strip() or None,
        despues_de=despues_de, limite=26, **filtro,
    )
    conteo = servicio.contar_por_estado(sesion, admin.tenant_id)
    return _pagina(
        request, "contratos.html", admin,
        contratos=filas[:25],
        siguiente=servicio.cursor_de(filas[24]) if len(filas) > 25 else None,
        estado=estado, referencia=referencia, conteo=conteo,
        pendientes=sum(conteo.get(e, 0) for e in PENDIENTES),
        estados=[e.value for e in Estado], aviso=AVISOS.get(aviso or ""),
    )


def _contrato_o_404(sesion: Session, admin: Admin, contrato_id: str):
    try:
        return servicio.obtener(sesion, admin.tenant_id, contrato_id)
    except NoEncontrado:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "no_encontrado", "mensaje": "Contrato no encontrado"},
        ) from None


def _pagina_contrato(request, admin, sesion, contrato, codigo=200, **extra):
    return _pagina(
        request, "contrato.html", admin, codigo=codigo,
        contrato=contrato,
        datos=servicio.como_json(sesion, contrato),
        eventos=auditoria.listar(sesion, admin.tenant_id, contrato.id),
        cadena=auditoria.verificar_cadena(sesion, admin.tenant_id, contrato.id),
        se_puede_reenviar=contrato.estado in PENDIENTES,
        se_puede_anular=not es_final(Estado(contrato.estado)),
        **extra,
    )


@router.get("/contratos/{contrato_id}", response_class=HTMLResponse)
def detalle(contrato_id: str, request: Request, aviso: str | None = None,
            admin: Admin = Depends(admin_actual), sesion: Session = Depends(obtener_sesion)):
    contrato = _contrato_o_404(sesion, admin, contrato_id)
    return _pagina_contrato(request, admin, sesion, contrato, aviso=AVISOS.get(aviso or ""))


@router.get("/contratos/{contrato_id}/documento")
def documento(
    contrato_id: str,
    request: Request,
    formato: str = Query(default="html", pattern="^(html|pdf)$"),
    admin: Admin = Depends(admin_actual),
    sesion: Session = Depends(obtener_sesion),
):
    contrato = _contrato_o_404(sesion, admin, contrato_id)
    if formato == "pdf":
        if not contrato.clave_documento_final_pdf:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "pdf_no_disponible", "mensaje": "Este contrato no tiene PDF"},
            )
        clave, tipo = contrato.clave_documento_final_pdf, "application/pdf"
    else:
        clave = contrato.clave_documento_final or contrato.clave_documento
        tipo = "text/html; charset=utf-8"
    contenido = almacen.leer(clave)
    auditoria.registrar(
        sesion, tenant_id=admin.tenant_id, contrato_id=contrato.id, tipo="DESCARGADO",
        actor_tipo="ADMIN", actor_id=admin.usuario.id, datos={"formato": formato},
        ip=ip_observada(request), agente=request.headers.get("user-agent"),
    )
    sesion.commit()
    return Response(
        content=contenido,
        media_type=tipo,
        headers={
            # El documento se muestra aislado, igual que en el portal de firma.
            "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
            "Content-Disposition": f'inline; filename="contrato-{contrato.id[:8]}.{formato}"',
        },
    )


@router.post("/contratos/{contrato_id}/reenviar", response_class=HTMLResponse)
def reenviar(
    contrato_id: str,
    request: Request,
    tareas: BackgroundTasks,
    csrf: str = Form(default=""),
    admin: Admin = Depends(admin_actual),
    sesion: Session = Depends(obtener_sesion),
):
    _exigir_csrf(admin, csrf)
    contrato = _contrato_o_404(sesion, admin, contrato_id)
    try:
        url = servicio.enviar(sesion, _contexto(admin, request), contrato)
    except (ErrorDeNegocio, TransicionInvalida) as error:
        sesion.rollback()
        return _pagina_contrato(request, admin, sesion, contrato, codigo=409, error=str(error))
    sesion.commit()
    tareas.add_task(despachar_en_linea)
    # El enlace solo existe ahora: en la base queda el hash del token.
    return _pagina_contrato(request, admin, sesion, contrato, enlace_nuevo=url)


@router.post("/contratos/{contrato_id}/anular")
def anular(
    contrato_id: str,
    request: Request,
    tareas: BackgroundTasks,
    csrf: str = Form(default=""),
    motivo: str = Form(default=""),
    admin: Admin = Depends(admin_actual),
    sesion: Session = Depends(obtener_sesion),
):
    _exigir_csrf(admin, csrf)
    contrato = _contrato_o_404(sesion, admin, contrato_id)
    try:
        servicio.anular(sesion, _contexto(admin, request), contrato, motivo)
    except TransicionInvalida as error:
        sesion.rollback()
        return _pagina_contrato(request, admin, sesion, contrato, codigo=409, error=str(error))
    sesion.commit()
    tareas.add_task(despachar_en_linea)
    return RedirectResponse(f"/admin/contratos/{contrato.id}?aviso=anulado", status_code=303)


# ---------------------------------------------------------------------------
# Plantillas
# ---------------------------------------------------------------------------

@router.get("/plantillas", response_class=HTMLResponse)
def ver_plantillas(request: Request, aviso: str | None = None,
                   admin: Admin = Depends(admin_actual), sesion: Session = Depends(obtener_sesion)):
    lista = sesion.scalars(
        select(Plantilla).where(Plantilla.tenant_id == admin.tenant_id).order_by(Plantilla.codigo)
    ).all()
    return _pagina(
        request, "plantillas.html", admin,
        plantillas=[(p, sorted(p.versiones, key=lambda v: v.version, reverse=True)) for p in lista],
        aviso=AVISOS.get(aviso or ""),
    )


@router.get("/plantillas/nueva", response_class=HTMLResponse)
def nueva_plantilla(request: Request, desde: str | None = None,
                    admin: Admin = Depends(admin_actual), sesion: Session = Depends(obtener_sesion)):
    formulario = {"schema_variables": "{}", "politica": json.dumps(
        {"requiere_otp": True, "requiere_firma_empresa": False}, indent=2)}
    if desde:
        plantilla = sesion.scalars(
            select(Plantilla).where(Plantilla.tenant_id == admin.tenant_id, Plantilla.id == desde)
        ).first()
        if plantilla is not None and plantilla.versiones:
            ultima = max(plantilla.versiones, key=lambda v: v.version)
            formulario = {
                "codigo": plantilla.codigo, "nombre": plantilla.nombre, "titulo": ultima.titulo,
                "cuerpo": ultima.cuerpo,
                "schema_variables": json.dumps(ultima.schema_variables, indent=2, ensure_ascii=False),
                "politica": json.dumps(ultima.politica, indent=2, ensure_ascii=False),
            }
    return _pagina(request, "plantilla_nueva.html", admin, f=formulario)


@router.post("/plantillas", response_class=HTMLResponse)
def publicar_plantilla(
    request: Request,
    csrf: str = Form(default=""),
    codigo: str = Form(default=""),
    nombre: str = Form(default=""),
    titulo: str = Form(default=""),
    cuerpo: str = Form(default=""),
    schema_variables: str = Form(default=""),
    politica: str = Form(default=""),
    admin: Admin = Depends(admin_actual),
    sesion: Session = Depends(obtener_sesion),
):
    _exigir_csrf(admin, csrf)
    formulario = {"codigo": codigo, "nombre": nombre, "titulo": titulo, "cuerpo": cuerpo,
                  "schema_variables": schema_variables, "politica": politica}

    def con_error(mensaje: str, detalles=None):
        return _pagina(request, "plantilla_nueva.html", admin, codigo=400, f=formulario,
                       error=mensaje, detalles=detalles or {})

    try:
        datos = CrearPlantilla(
            codigo=codigo, nombre=nombre, titulo=titulo, cuerpo=cuerpo,
            schema_variables=json.loads(schema_variables or "{}"),
            politica=json.loads(politica) if politica.strip() else None,
        )
    except json.JSONDecodeError as error:
        return con_error(f"El schema o la politica no son JSON valido: {error.msg} (linea {error.lineno})")
    except ValidationError as error:
        return con_error("Revisa los campos marcados.", {
            ".".join(str(p) for p in e["loc"]): e["msg"] for e in error.errors()
        })

    try:
        plantilla, version = servicio.publicar_plantilla(
            sesion, admin.tenant_id, **datos.model_dump(),
        )
    except (DatosInvalidos, PlantillaInvalida) as error:
        sesion.rollback()
        return con_error(str(error), getattr(error, "detalles", None))
    _registrar_en_empresa(sesion, admin, request, "PLANTILLA_PUBLICADA",
                          {"codigo": plantilla.codigo, "version": version.version,
                           "hash_contenido": version.hash_contenido})
    sesion.commit()
    return RedirectResponse("/admin/plantillas?aviso=publicada", status_code=303)


# ---------------------------------------------------------------------------
# Credenciales
# ---------------------------------------------------------------------------

def _pagina_credenciales(request, admin, sesion, codigo=200, **extra):
    return _pagina(
        request, "credenciales.html", admin, codigo=codigo,
        credenciales=credenciales.listar(sesion, admin.tenant_id),
        permisos=credenciales.PERMISOS, **extra,
    )


@router.get("/credenciales", response_class=HTMLResponse)
def ver_credenciales(request: Request, aviso: str | None = None,
                     admin: Admin = Depends(admin_actual), sesion: Session = Depends(obtener_sesion)):
    return _pagina_credenciales(request, admin, sesion, aviso=AVISOS.get(aviso or ""))


@router.post("/credenciales", response_class=HTMLResponse)
def crear_credencial(
    request: Request,
    csrf: str = Form(default=""),
    nombre: str = Form(default=""),
    permisos: list[str] = Form(default=[]),
    admin: Admin = Depends(admin_actual),
    sesion: Session = Depends(obtener_sesion),
):
    _exigir_csrf(admin, csrf)
    try:
        credencial, secreto = credenciales.crear(
            sesion, admin.tenant_id, nombre=nombre, permisos=permisos,
        )
    except credenciales.CredencialInvalida as error:
        return _pagina_credenciales(request, admin, sesion, codigo=400, error=str(error))
    _registrar_en_empresa(sesion, admin, request, "CREDENCIAL_CREADA",
                          {"client_id": credencial.client_id, "permisos": credencial.permisos})
    sesion.commit()
    return _pagina(request, "credencial_creada.html", admin, credencial=credencial, secreto=secreto)


@router.post("/credenciales/{credencial_id}/revocar")
def revocar_credencial(credencial_id: str, request: Request, csrf: str = Form(default=""),
                       admin: Admin = Depends(admin_actual), sesion: Session = Depends(obtener_sesion)):
    _exigir_csrf(admin, csrf)
    credencial = credenciales.obtener(sesion, admin.tenant_id, credencial_id)
    if credencial is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "no_encontrado", "mensaje": "Credencial no encontrada"},
        )
    credenciales.revocar(credencial)
    _registrar_en_empresa(sesion, admin, request, "CREDENCIAL_REVOCADA",
                          {"client_id": credencial.client_id})
    sesion.commit()
    return RedirectResponse("/admin/credenciales?aviso=revocada", status_code=303)
