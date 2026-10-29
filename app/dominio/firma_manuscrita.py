"""
Firma manuscrita: el firmante dibuja su firma con el mouse, el dedo o un lapiz.

El navegador no manda una imagen sino los TRAZOS, como listas de puntos en un
lienzo de 600 x 200 unidades. Se hizo asi por tres razones:

  - Se puede comprobar que hay una firma de verdad (que no es un punto ni un
    recuadro vacio) mirando los numeros, sin decodificar archivos que vienen de
    afuera.
  - El dibujo sale siempre igual a partir de los mismos numeros, asi que el hash
    de la evidencia y el del documento final siguen siendo reproducibles.
  - Lo que se incrusta en el documento es un SVG fabricado aqui solo con
    numeros: no hay nada del navegador que pueda colarse en el HTML.

Los trazos forman parte de la evidencia que se sella con la firma criptografica:
quien firmo, con que dibujo y sobre que documento quedan atados.
"""
from __future__ import annotations

import json
import math
from typing import Any

from app.seguridad import json_canonico, sha256

ANCHO = 600
ALTO = 200

MAX_BYTES = 90_000
MAX_TRAZOS = 40
MAX_PUNTOS = 2_500

# Lo minimo para considerar que alguien firmo y no toco el recuadro por error.
LARGO_MINIMO = 60.0
EXTENSION_MINIMA = 40.0


class FirmaInvalida(ValueError):
    """El mensaje esta pensado para mostrarselo al firmante."""


def _numero(valor: Any) -> float:
    if isinstance(valor, bool) or not isinstance(valor, (int, float)) or not math.isfinite(valor):
        raise FirmaInvalida("La firma no es valida. Borrala y dibujala otra vez.")
    return float(valor)


def _medir(trazos: list[list[list[float]]]) -> tuple[float, float]:
    """(largo total recorrido, extension del mayor lado del rectangulo que la contiene)."""
    largo = 0.0
    xs: list[float] = []
    ys: list[float] = []
    for trazo in trazos:
        for (x0, y0), (x1, y1) in zip(trazo, trazo[1:]):
            largo += math.hypot(x1 - x0, y1 - y0)
        xs += [p[0] for p in trazo]
        ys += [p[1] for p in trazo]
    if not xs:
        return 0.0, 0.0
    return largo, max(max(xs) - min(xs), max(ys) - min(ys))


def validar(texto: str) -> dict:
    """
    Recibe lo que manda el navegador y devuelve la firma normalizada:

        {"ancho": 600, "alto": 200, "trazos": [[[x, y], [x, y], ...], ...]}

    Lanza FirmaInvalida, con un mensaje apto para el firmante, si no sirve.
    """
    if not texto or not texto.strip():
        raise FirmaInvalida("Dibuja tu firma en el recuadro para poder firmar.")
    if len(texto.encode("utf-8")) > MAX_BYTES:
        raise FirmaInvalida("La firma es demasiado compleja. Borrala y hazla mas simple.")
    try:
        datos = json.loads(texto)
    except (ValueError, RecursionError):
        raise FirmaInvalida("La firma no es valida. Borrala y dibujala otra vez.") from None

    if (
        not isinstance(datos, dict)
        or datos.get("ancho") != ANCHO
        or datos.get("alto") != ALTO
        or not isinstance(datos.get("trazos"), list)
    ):
        raise FirmaInvalida("La firma no es valida. Borrala y dibujala otra vez.")

    crudos = datos["trazos"]
    if len(crudos) > MAX_TRAZOS:
        raise FirmaInvalida("La firma es demasiado compleja. Borrala y hazla mas simple.")

    trazos: list[list[list[float]]] = []
    puntos = 0
    for crudo in crudos:
        if not isinstance(crudo, list):
            raise FirmaInvalida("La firma no es valida. Borrala y dibujala otra vez.")
        trazo: list[list[float]] = []
        for punto in crudo:
            if not isinstance(punto, list) or len(punto) != 2:
                raise FirmaInvalida("La firma no es valida. Borrala y dibujala otra vez.")
            x, y = _numero(punto[0]), _numero(punto[1])
            if not (-1 <= x <= ANCHO + 1 and -1 <= y <= ALTO + 1):
                raise FirmaInvalida("La firma no es valida. Borrala y dibujala otra vez.")
            trazo.append([round(min(max(x, 0.0), ANCHO), 1), round(min(max(y, 0.0), ALTO), 1)])
        puntos += len(trazo)
        if puntos > MAX_PUNTOS:
            raise FirmaInvalida("La firma es demasiado compleja. Borrala y hazla mas simple.")
        # Un solo punto no dibuja nada: es un toque suelto, no un trazo.
        if len(trazo) >= 2:
            trazos.append(trazo)

    largo, extension = _medir(trazos)
    if not trazos:
        raise FirmaInvalida("Dibuja tu firma en el recuadro para poder firmar.")
    if largo < LARGO_MINIMO or extension < EXTENSION_MINIMA:
        raise FirmaInvalida("La firma es muy corta. Dibuja tu firma completa en el recuadro.")
    return {"ancho": ANCHO, "alto": ALTO, "trazos": trazos}


def hash_de(firma: dict) -> str:
    """Huella de los trazos. Va en la evidencia y en la constancia."""
    return sha256(json_canonico(firma))


def svg(firma: dict, ancho_px: int = 240) -> str:
    """
    La firma como SVG. Se fabrica solo con numeros ya validados, asi que no puede
    arrastrar nada que no sea geometria. Mismos trazos, mismos bytes.
    """
    alto_px = round(ancho_px * firma["alto"] / firma["ancho"])
    lineas = "".join(
        '<polyline points="'
        + " ".join(f"{x:.1f},{y:.1f}" for x, y in trazo)
        + '" fill="none" stroke="#14151a" stroke-width="2.4" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        for trazo in firma["trazos"]
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {firma["ancho"]} {firma["alto"]}" '
        f'width="{ancho_px}" height="{alto_px}" role="img" aria-label="Firma manuscrita">{lineas}</svg>'
    )
