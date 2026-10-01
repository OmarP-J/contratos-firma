"""
Motor de plantillas.

Decisiones de seguridad, todas deliberadas:

  - La unica sintaxis es {{ variable }}. No hay logica, ni bucles, ni
    expresiones. Una plantilla no puede ejecutar nada porque no hay nada que
    ejecutar. Esto cierra de entrada toda la familia de ataques de inyeccion
    en motores de plantillas.
  - Los valores se insertan SIEMPRE escapados. No existe una via para meter
    HTML crudo desde una variable.
  - El cuerpo lo escribe un administrador del tenant, asi que es
    semiconfiable: se valida contra una lista blanca de etiquetas y se RECHAZA
    lo que no este permitido, en vez de intentar limpiarlo. Es preferible un
    error claro al publicar que un saneador con agujeros.
"""
from __future__ import annotations

import re
from html import escape
from typing import Any

from app.dominio.variables import formatear

ETIQUETAS_PERMITIDAS = {
    "h1", "h2", "h3", "h4", "p", "br", "hr", "strong", "b", "em", "i", "u", "small",
    "ul", "ol", "li", "table", "thead", "tbody", "tfoot", "tr", "th", "td",
    "div", "span", "section", "blockquote",
}
ETIQUETAS_VACIAS = {"br", "hr"}
ATRIBUTOS_PERMITIDOS = {"class", "colspan", "rowspan"}

PLACEHOLDER = re.compile(r"\{\{\s*([a-zA-Z][a-zA-Z0-9_.]*)\s*\}\}")
VARIABLES_DEL_SISTEMA = {"documento.id", "documento.fecha", "documento.referencia"}


class PlantillaInvalida(Exception):
    pass


def sanitizar_cuerpo(cuerpo: str) -> str:
    """Valida el cuerpo y devuelve la version normalizada, o lanza PlantillaInvalida."""
    if not isinstance(cuerpo, str) or not cuerpo.strip():
        raise PlantillaInvalida("El cuerpo de la plantilla no puede estar vacio")
    if len(cuerpo) > 200_000:
        raise PlantillaInvalida("El cuerpo de la plantilla es demasiado extenso")

    limpio = re.sub(r"<!--.*?-->", "", cuerpo, flags=re.S)
    if "<!--" in limpio or "-->" in limpio:
        raise PlantillaInvalida("Comentario HTML sin cerrar")

    pila: list[str] = []
    for coincidencia in re.finditer(r"<([^>]*)>", limpio):
        contenido = coincidencia.group(1).strip()
        if "{{" in contenido:
            raise PlantillaInvalida(
                "No se permiten variables dentro de una etiqueta, solo en el texto"
            )
        if contenido.startswith(("!", "?")):
            raise PlantillaInvalida("Declaraciones o instrucciones no permitidas")

        es_cierre = contenido.startswith("/")
        cuerpo_etiqueta = contenido[1:] if es_cierre else contenido
        nombre_match = re.match(r"^([a-zA-Z][a-zA-Z0-9]*)", cuerpo_etiqueta.strip())
        if not nombre_match:
            raise PlantillaInvalida("Etiqueta HTML malformada")
        nombre = nombre_match.group(1).lower()
        if nombre not in ETIQUETAS_PERMITIDAS:
            raise PlantillaInvalida(f"Etiqueta no permitida: <{nombre}>")

        resto = cuerpo_etiqueta[nombre_match.end():].rstrip("/").strip()
        if es_cierre:
            if resto:
                raise PlantillaInvalida(f"Etiqueta de cierre invalida: </{nombre}>")
            if not pila or pila.pop() != nombre:
                raise PlantillaInvalida(f"Etiquetas mal anidadas cerca de </{nombre}>")
        else:
            _validar_atributos(nombre, resto)
            if nombre not in ETIQUETAS_VACIAS and not contenido.endswith("/"):
                pila.append(nombre)

    if pila:
        raise PlantillaInvalida(f"Quedaron etiquetas sin cerrar: <{'>, <'.join(pila)}>")
    return limpio


def _validar_atributos(etiqueta: str, texto: str) -> None:
    if not texto:
        return
    for atributo in re.finditer(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)(\s*=\s*(\"[^\"]*\"|'[^']*'|\S+))?", texto):
        nombre = atributo.group(1).lower()
        if nombre not in ATRIBUTOS_PERMITIDOS:
            raise PlantillaInvalida(
                f"Atributo no permitido en <{etiqueta}>: {nombre}. "
                f"Solo se admiten: {', '.join(sorted(ATRIBUTOS_PERMITIDOS))}"
            )


def extraer_variables(cuerpo: str) -> list[str]:
    return sorted({m.group(1) for m in PLACEHOLDER.finditer(cuerpo)})


def validar_coherencia(cuerpo: str, schema: dict) -> None:
    """Al publicar: no puede quedar una variable usada que no este declarada."""
    desconocidas = [
        ruta for ruta in extraer_variables(cuerpo)
        if ruta not in schema and ruta not in VARIABLES_DEL_SISTEMA
    ]
    if desconocidas:
        raise PlantillaInvalida(
            "La plantilla usa variables no declaradas en el schema: " + ", ".join(desconocidas)
        )


def renderizar(cuerpo: str, schema: dict, valores: dict[str, Any], contexto: dict) -> str:
    """
    Sustituye las variables por sus valores, siempre escapados.

    Determinista: las mismas entradas producen siempre exactamente el mismo
    HTML, que es lo que da valor probatorio al hash del documento.
    """

    def reemplazo(coincidencia: re.Match[str]) -> str:
        ruta = coincidencia.group(1)
        if ruta in VARIABLES_DEL_SISTEMA:
            return escape(str(contexto.get(ruta.split(".", 1)[1], "")))
        if ruta not in schema:
            raise PlantillaInvalida(f"La plantilla referencia una variable no declarada: {ruta}")
        if ruta not in valores:
            return ""
        return escape(formatear(schema[ruta], valores[ruta]))

    return PLACEHOLDER.sub(reemplazo, cuerpo)
