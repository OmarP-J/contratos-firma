"""
Generacion del documento.

Todo ocurre en el servidor. El navegador no participa: no se confia en HTML,
importes ni hashes calculados en el cliente.

El mismo HTML que se convierte en documento es el que se muestra en el portal
de firma, de modo que lo que el firmante lee es exactamente lo que queda
registrado en el hash.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from html import escape
from typing import Any

from app.dominio.plantillas import renderizar
from app.seguridad import json_canonico, sha256

ESTILOS = """
body { font-family: Georgia, 'Times New Roman', serif; font-size: 11pt; color: #14151a;
       line-height: 1.6; max-width: 46rem; margin: 0 auto; padding: 2.5rem 1.5rem; }
h1 { font-size: 1.5rem; text-align: center; margin: 0 0 1.5rem; }
h2 { font-size: 1.1rem; margin: 1.6rem 0 .5rem; }
p { text-align: justify; margin: 0 0 .8rem; }
table { width: 100%; border-collapse: collapse; margin: .8rem 0 1.2rem; font-size: .92em; }
th, td { border: 1px solid #b9b9c2; padding: .45rem .6rem; text-align: left; }
th { background: #eeeef2; }
.pie { margin-top: 2.5rem; border-top: 1px solid #c9c9d2; padding-top: .8rem;
       font-size: .8em; color: #5a5c66; font-family: ui-monospace, monospace; }
.constancia { margin-top: 2.5rem; border-top: 3px double #14151a; padding-top: 1.2rem; }
"""


@dataclass(frozen=True)
class DocumentoGenerado:
    """Congelado: un documento ya generado no se modifica, su hash es evidencia."""

    html: str
    hash: str
    bytes_: bytes


def _documento_legible(documento: str | None) -> str:
    """Una cedula se lee 402-2118261-7, no 40221182617."""
    if documento and len(documento) == 11 and documento.isdigit():
        return f"{documento[:3]}-{documento[3:10]}-{documento[10]}"
    return documento or ""


def _tabla_partes(partes: list[dict]) -> str:
    filas = "".join(
        f"<tr><td>{escape('Por la empresa' if p['rol'] == 'EMPRESA' else 'Cliente')}</td>"
        f"<td>{escape(p['nombre'])}</td>"
        f"<td>{escape(_documento_legible(p.get('documento')))}</td></tr>"
        for p in partes
    )
    return (
        "<h2>Firmantes</h2><table><thead><tr><th>Calidad</th><th>Nombre</th>"
        f"<th>Documento</th></tr></thead><tbody>{filas}</tbody></table>"
    )


def construir_documento(
    *,
    titulo: str,
    cuerpo_plantilla: str,
    schema: dict,
    valores: dict[str, Any],
    partes: list[dict],
    contexto: dict,
    tenant_nombre: str,
    plantilla_codigo: str,
    numero_version: int,
) -> str:
    """El HTML completo del contrato, antes de cualquier firma."""
    cuerpo = renderizar(cuerpo_plantilla, schema, valores, contexto)
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>{escape(titulo)}</title>
<style>{ESTILOS}</style></head><body>
<h1>{escape(titulo)}</h1>
{cuerpo}
{_tabla_partes(partes)}
<p class="pie">Documento generado electronicamente por {escape(tenant_nombre)} el
{escape(contexto.get('fecha', ''))}. Plantilla {escape(plantilla_codigo)} version
{numero_version}. Identificador {escape(contexto.get('id', ''))}.</p>
</body></html>"""


def generar(html: str) -> DocumentoGenerado:
    """Congela el documento: bytes exactos y su hash SHA-256."""
    datos = html.encode("utf-8")
    return DocumentoGenerado(html=html, hash=sha256(datos), bytes_=datos)


def hash_de_variables(valores: dict[str, Any]) -> tuple[str, str]:
    """Devuelve (json_canonico, hash). El canonico se guarda para poder recalcular."""
    canonico = json_canonico(valores)
    return canonico, sha256(canonico)


def _fila(etiqueta: str, valor: Any) -> str:
    return f"<tr><td>{escape(etiqueta)}</td><td>{escape(str(valor if valor not in (None, '') else 'No aplica'))}</td></tr>"


def construir_constancia(
    *,
    contrato: dict,
    evidencias: list[dict],
    eventos: list[dict],
) -> str:
    """
    La constancia de firma: quien firmo, como se autentico, cuando, desde donde,
    sobre que version de plantilla y sobre que hash de documento.

    Es la parte que sostiene el valor probatorio del documento final.
    """
    bloques = []
    for ev in evidencias:
        d = ev["datos"]
        ubicacion = (
            f"{d.get('latitud')}, {d.get('longitud')} (precision {d.get('precision_m')} m)"
            if d.get("latitud") is not None
            else "No capturada"
        )
        bloques.append(
            f"<h3>{escape('Firmante por la empresa' if d.get('rol') == 'EMPRESA' else 'Firmante cliente')}: "
            f"{escape(d.get('nombre', ''))}</h3><table><tbody>"
            + _fila("Documento de identidad", _documento_legible(d.get("documento")))
            + _fila("Correo", d.get("email"))
            + _fila("Metodo de autenticacion", d.get("metodo_autenticacion"))
            + _fila("Aceptacion de uso de firma electronica", d.get("consentimiento_en"))
            + _fila("Fecha y hora de firma (UTC)", d.get("firmado_en"))
            + _fila("IP observada por el servidor", d.get("ip"))
            + _fila("Dispositivo declarado", (d.get("agente") or "")[:120])
            + _fila("Ubicacion declarada", ubicacion)
            + _fila("Hash del documento al firmar", d.get("hash_documento_al_firmar"))
            + _fila("Algoritmo de firma", d.get("algoritmo"))
            + _fila("Valor de firma", (d.get("firma") or "")[:64])
            + "</tbody></table>"
        )

    filas_eventos = "".join(
        f"<tr><td>{e['secuencia']}</td><td>{escape(e['tipo'])}</td>"
        f"<td>{escape(e['creado_en'])}</td><td>{escape(e['actor_tipo'])}</td>"
        f"<td>{escape(e['hash'][:16])}</td></tr>"
        for e in eventos
    )

    return f"""<div class="constancia">
<h1>Constancia de firma electronica</h1>
<p>Esta constancia forma parte integra del documento y resume la evidencia tecnica
recopilada durante el proceso de firma. La ausencia de alteracion puede verificarse
recalculando los hashes indicados.</p>
<h2>Datos del contrato</h2><table><tbody>
{_fila("Identificador del contrato", contrato["id"])}
{_fila("Titulo", contrato["titulo"])}
{_fila("Referencia del sistema origen", contrato.get("referencia_externa"))}
{_fila("Plantilla", f"{contrato['plantilla_codigo']} version {contrato['numero_version']}")}
{_fila("Hash SHA-256 de las variables", contrato["hash_variables"])}
{_fila("Hash SHA-256 del documento presentado a firma", contrato["hash_documento"])}
{_fila("Generado en (UTC)", contrato["creado_en"])}
{_fila("Completado en (UTC)", contrato.get("completado_en"))}
</tbody></table>
<h2>Firmantes y evidencias</h2>
{"".join(bloques)}
<h2>Linea de auditoria</h2>
<p>Los eventos se registran de forma append-only y cada uno encadena su hash con el
anterior, de modo que eliminar o alterar un evento intermedio rompe la cadena.</p>
<table><thead><tr><th>#</th><th>Evento</th><th>Fecha (UTC)</th><th>Actor</th><th>Hash</th></tr></thead>
<tbody>{filas_eventos}</tbody></table>
</div>"""


def componer_documento_final(html_contrato: str, constancia: str) -> str:
    """El documento final = el contrato tal cual se firmo + la constancia."""
    return html_contrato.replace("</body></html>", f"{constancia}</body></html>")


def iso(momento: datetime | None) -> str | None:
    if momento is None:
        return None
    return momento.isoformat().replace("+00:00", "Z")
