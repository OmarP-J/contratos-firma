"""
Version PDF del documento final.

El HTML congelado sigue siendo el documento de referencia: es el que se firmo y
sobre el que se calcularon los hashes. El PDF es una representacion para
archivar e imprimir. Se genera una vez al completar el contrato, se guarda
junto al HTML y deja su propio hash en la auditoria.

No hace falta un navegador ni WeasyPrint (que en Windows exige instalar GTK):
las plantillas solo admiten una lista blanca corta de etiquetas, asi que basta
con traducir esas etiquetas a elementos de ReportLab. Lo que no se reconoce se
trata como texto; nunca se interpreta.

Con invariant=1 ReportLab no escribe la fecha ni un identificador aleatorio: el
mismo HTML produce siempre los mismos bytes y el hash se puede recalcular.
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field
from html.parser import HTMLParser
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    HRFlowable,
    ListFlowable,
    ListItem,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

INLINE = {"strong", "b", "em", "i", "u", "small", "span", "br"}
VACIAS = {"br", "hr", "meta", "link", "img", "input"}
IGNORADAS = {"head", "style", "script", "title"}
MARGEN = 2 * cm
TAMANO_CELDA = 8.5


@dataclass
class Nodo:
    etiqueta: str
    clases: set[str] = field(default_factory=set)
    hijos: list = field(default_factory=list)


class _Arbol(HTMLParser):
    """Arbol minimo del HTML. Tolera etiquetas mal cerradas sin romperse."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.raiz = Nodo("raiz")
        self.pila = [self.raiz]
        self.ignorando = 0

    def handle_starttag(self, etiqueta, atributos):
        if etiqueta in IGNORADAS:
            self.ignorando += 1
            return
        if self.ignorando:
            return
        clases = set((dict(atributos).get("class") or "").split())
        nodo = Nodo(etiqueta, clases)
        self.pila[-1].hijos.append(nodo)
        if etiqueta not in VACIAS:
            self.pila.append(nodo)

    def handle_endtag(self, etiqueta):
        if etiqueta in IGNORADAS:
            self.ignorando = max(0, self.ignorando - 1)
            return
        if self.ignorando or etiqueta in VACIAS:
            return
        for posicion in range(len(self.pila) - 1, 0, -1):
            if self.pila[posicion].etiqueta == etiqueta:
                del self.pila[posicion:]
                return

    def handle_data(self, texto):
        if not self.ignorando:
            self.pila[-1].hijos.append(texto)


def _estilos() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    parrafo = ParagraphStyle("parrafo", parent=base["BodyText"], fontName="Times-Roman",
                             fontSize=11, leading=15, alignment=TA_JUSTIFY, spaceAfter=6)
    return {
        "h1": ParagraphStyle("h1", parent=base["Title"], fontName="Times-Bold", fontSize=16,
                             alignment=TA_CENTER, spaceAfter=12),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Times-Bold", fontSize=12.5,
                             spaceBefore=10, spaceAfter=4),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName="Times-Bold", fontSize=11.5,
                             spaceBefore=8, spaceAfter=4),
        "h4": ParagraphStyle("h4", parent=base["Heading4"], fontName="Times-Bold", fontSize=11),
        "parrafo": parrafo,
        "cita": ParagraphStyle("cita", parent=parrafo, leftIndent=18, rightIndent=18),
        "pie": ParagraphStyle("pie", parent=parrafo, fontName="Courier", fontSize=7.5,
                              leading=10, textColor=colors.HexColor("#5a5c66")),
        "celda": ParagraphStyle("celda", parent=parrafo, fontName="Helvetica", fontSize=TAMANO_CELDA,
                                leading=11, alignment=0, spaceAfter=0),
        "celda_th": ParagraphStyle("celda_th", parent=parrafo, fontName="Helvetica-Bold",
                                   fontSize=TAMANO_CELDA, leading=11, alignment=0, spaceAfter=0),
    }


def _inline(nodos: list) -> str:
    """Contenido en linea con el marcado minimo de ReportLab. El texto va escapado."""
    partes = []
    for nodo in nodos:
        if isinstance(nodo, str):
            partes.append(escape(nodo))
        elif nodo.etiqueta in {"strong", "b"}:
            partes.append(f"<b>{_inline(nodo.hijos)}</b>")
        elif nodo.etiqueta in {"em", "i"}:
            partes.append(f"<i>{_inline(nodo.hijos)}</i>")
        elif nodo.etiqueta == "u":
            partes.append(f"<u>{_inline(nodo.hijos)}</u>")
        elif nodo.etiqueta == "small":
            partes.append(f'<font size="8">{_inline(nodo.hijos)}</font>')
        elif nodo.etiqueta == "br":
            partes.append("<br/>")
        else:
            # Un bloque dentro de una celda o de un parrafo se aplana a texto.
            partes.append(" " + _inline(nodo.hijos) + " ")
    return "".join(partes)


def _parrafo(nodos: list, estilo: ParagraphStyle) -> list:
    marcado = _inline(nodos).strip()
    return [Paragraph(marcado, estilo)] if marcado else []


def _texto(nodos: list) -> str:
    return "".join(n if isinstance(n, str) else _texto(n.hijos) for n in nodos)


def _anchos(textos: list[list[tuple[str, str]]], columnas: int) -> list[float]:
    """
    Reparte el ancho segun lo que mide el texto mas largo de cada columna,
    acotado para que una columna de hashes no aplaste a las demas.
    """
    disponible = A4[0] - 2 * MARGEN
    naturales = []
    for i in range(columnas):
        medido = max(
            (stringWidth(fila[i][0], fila[i][1], TAMANO_CELDA) for fila in textos if i < len(fila)),
            default=20,
        )
        naturales.append(min(medido + 14, disponible * 0.45))  # 14 = relleno de la celda
    return [disponible * n / sum(naturales) for n in naturales]


def _tabla(nodo: Nodo, estilos: dict) -> list:
    filas, textos, encabezado = [], [], 0
    for seccion in (h for h in nodo.hijos if isinstance(h, Nodo)):
        trs = [seccion] if seccion.etiqueta == "tr" else [
            h for h in seccion.hijos if isinstance(h, Nodo) and h.etiqueta == "tr"
        ]
        for tr in trs:
            celdas = [c for c in tr.hijos if isinstance(c, Nodo) and c.etiqueta in {"td", "th"}]
            if not celdas:
                continue
            estilos_fila = [estilos["celda_th" if c.etiqueta == "th" else "celda"] for c in celdas]
            filas.append([
                Paragraph(_inline(c.hijos).strip(), estilo) for c, estilo in zip(celdas, estilos_fila)
            ])
            textos.append([
                (_texto(c.hijos).strip(), estilo.fontName) for c, estilo in zip(celdas, estilos_fila)
            ])
            encabezado += seccion.etiqueta == "thead"
    if not filas:
        return []
    columnas = max(len(fila) for fila in filas)
    for fila in filas:
        fila.extend([""] * (columnas - len(fila)))
    tabla = Table(filas, colWidths=_anchos(textos, columnas), repeatRows=encabezado)
    estilo = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b9b9c2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if encabezado:
        estilo.append(("BACKGROUND", (0, 0), (-1, encabezado - 1), colors.HexColor("#eeeef2")))
    tabla.setStyle(TableStyle(estilo))
    return [tabla, Spacer(1, 8)]


def _bloques(nodos: list, estilos: dict) -> list:
    salida, suelto = [], []

    def vaciar():
        salida.extend(_parrafo(suelto, estilos["parrafo"]))
        suelto.clear()

    for nodo in nodos:
        if isinstance(nodo, str) or nodo.etiqueta in INLINE:
            suelto.append(nodo)
            continue
        vaciar()
        etiqueta = nodo.etiqueta
        if etiqueta in {"h1", "h2", "h3", "h4"}:
            salida.extend(_parrafo(nodo.hijos, estilos[etiqueta]))
        elif etiqueta == "p":
            salida.extend(_parrafo(nodo.hijos, estilos["pie" if "pie" in nodo.clases else "parrafo"]))
        elif etiqueta == "blockquote":
            salida.extend(_parrafo(nodo.hijos, estilos["cita"]))
        elif etiqueta in {"ul", "ol"}:
            elementos = [
                ListItem(_bloques(li.hijos, estilos) or [Paragraph("", estilos["parrafo"])])
                for li in nodo.hijos if isinstance(li, Nodo) and li.etiqueta == "li"
            ]
            if elementos:
                salida.append(ListFlowable(
                    elementos, bulletType="1" if etiqueta == "ol" else "bullet", leftIndent=14,
                ))
        elif etiqueta == "table":
            salida.extend(_tabla(nodo, estilos))
        elif etiqueta == "hr":
            salida.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#c9c9d2")))
        else:
            if "constancia" in nodo.clases:
                salida += [Spacer(1, 14), HRFlowable(width="100%", thickness=1.5), Spacer(1, 6)]
            salida.extend(_bloques(nodo.hijos, estilos))
    vaciar()
    return salida


def html_a_pdf(html: str, *, titulo: str = "", comprimir: bool = True) -> bytes:
    arbol = _Arbol()
    arbol.feed(html)
    arbol.close()

    def numerar(canvas, documento):
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#71738a"))
        canvas.drawRightString(A4[0] - MARGEN, MARGEN / 2, f"Pagina {documento.page}")

    salida = io.BytesIO()
    documento = SimpleDocTemplate(
        salida, pagesize=A4, leftMargin=MARGEN, rightMargin=MARGEN,
        topMargin=MARGEN, bottomMargin=MARGEN, title=titulo,
        author="Servicio de contratos y firma electronica",
        invariant=1, pageCompression=1 if comprimir else 0,
    )
    documento.build(_bloques(arbol.raiz.hijos, _estilos()) or [Spacer(1, 1)],
                    onFirstPage=numerar, onLaterPages=numerar)
    return salida.getvalue()
