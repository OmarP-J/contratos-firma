"""
Validacion de las variables que envia la plataforma integradora.

Funciona con lista blanca estricta: lo que no esta declarado en el schema de la
version de plantilla se rechaza. Nunca se asigna el cuerpo de una peticion
directamente a una entidad persistente.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

MAX_VARIABLES = 200
MAX_PROFUNDIDAD = 4
MAX_LARGO_TEXTO = 500

# Nombres internos que jamas pueden llegar desde fuera.
PROHIBIDOS = {
    "tenant_id", "estado", "rol", "firmado", "aprobado", "id", "hash",
    "version_plantilla", "plantilla_id", "es_admin", "__proto__", "constructor",
}

RUTA_VALIDA = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,40}(\.[a-zA-Z][a-zA-Z0-9_]{0,40}){0,3}$")

TIPOS = {"texto", "texto_largo", "entero", "numero", "dinero", "booleano", "fecha",
         "cedula", "rnc", "email", "telefono", "opcion"}


class DatosInvalidos(Exception):
    """Lleva TODOS los problemas de una vez, no solo el primero."""

    def __init__(self, detalles: dict[str, str]) -> None:
        self.detalles = detalles
        super().__init__(f"Datos invalidos: {detalles}")


def validar_schema(entrada: Any) -> dict:
    """Comprueba que el schema de una plantilla este bien formado."""
    if not isinstance(entrada, dict):
        raise DatosInvalidos({"schema": "debe ser un objeto"})
    problemas: dict[str, str] = {}
    schema: dict[str, dict] = {}
    for clave, definicion in entrada.items():
        if not RUTA_VALIDA.match(clave):
            problemas[clave] = "nombre de variable invalido"
            continue
        if any(parte.lower() in PROHIBIDOS for parte in clave.split(".")):
            problemas[clave] = "nombre reservado"
            continue
        if not isinstance(definicion, dict) or definicion.get("tipo") not in TIPOS:
            problemas[clave] = f"tipo invalido (admitidos: {', '.join(sorted(TIPOS))})"
            continue
        schema[clave] = definicion
    if problemas:
        raise DatosInvalidos(problemas)
    return schema


def _aplanar(entrada: dict, prefijo: str = "", profundidad: int = 1) -> dict[str, Any]:
    """Convierte {"a": {"b": 1}} en {"a.b": 1}."""
    salida: dict[str, Any] = {}
    if profundidad > MAX_PROFUNDIDAD:
        raise DatosInvalidos({"variables": "estan anidadas demasiado profundo"})
    for clave, valor in entrada.items():
        if clave.lower() in PROHIBIDOS:
            raise DatosInvalidos({clave: "nombre no permitido"})
        ruta = f"{prefijo}.{clave}" if prefijo else clave
        if isinstance(valor, list):
            # Las listas quedan fuera de esta primera version a proposito:
            # no hay plantillas con repeticion todavia.
            raise DatosInvalidos({ruta: "no se admiten listas"})
        if isinstance(valor, dict):
            salida.update(_aplanar(valor, ruta, profundidad + 1))
        else:
            salida[ruta] = valor
        if len(salida) > MAX_VARIABLES:
            raise DatosInvalidos({"variables": "demasiadas variables"})
    return salida


def validar_valores(schema: dict, entrada: Any) -> dict[str, Any]:
    """
    Devuelve los valores normalizados, o lanza DatosInvalidos con el detalle
    completo de todo lo que esta mal.
    """
    if not isinstance(entrada, dict):
        raise DatosInvalidos({"variables": "debe ser un objeto"})

    planas = _aplanar(entrada)
    problemas: dict[str, str] = {}

    # Lista blanca: lo no declarado rompe la peticion.
    for clave in planas:
        if clave not in schema:
            problemas[clave] = "no esta declarada en la plantilla"

    valores: dict[str, Any] = {}
    for clave, definicion in schema.items():
        bruto = planas.get(clave)
        if bruto is None or bruto == "":
            if definicion.get("requerido"):
                problemas[clave] = "es obligatoria"
            continue
        try:
            valores[clave] = _normalizar(definicion, bruto)
        except ValueError as error:
            problemas[clave] = str(error)

    if problemas:
        raise DatosInvalidos(problemas)
    return valores


def _normalizar(definicion: dict, bruto: Any) -> Any:
    tipo = definicion["tipo"]

    if tipo in {"texto", "texto_largo"}:
        texto = str(bruto).strip()
        maximo = definicion.get("max_largo", 5000 if tipo == "texto_largo" else MAX_LARGO_TEXTO)
        if len(texto) > maximo:
            raise ValueError(f"supera {maximo} caracteres")
        return texto

    if tipo in {"entero", "numero", "dinero"}:
        try:
            numero = Decimal(str(bruto).replace(",", ""))
        except InvalidOperation as error:
            raise ValueError("debe ser numerico") from error
        if tipo == "entero" and numero != numero.to_integral_value():
            raise ValueError("debe ser un numero entero")
        minimo = definicion.get("minimo")
        maximo = definicion.get("maximo")
        if minimo is not None and numero < Decimal(str(minimo)):
            raise ValueError(f"debe ser mayor o igual a {minimo}")
        if maximo is not None and numero > Decimal(str(maximo)):
            raise ValueError(f"debe ser menor o igual a {maximo}")
        if tipo == "dinero":
            return numero.quantize(Decimal("0.01"))
        if tipo == "entero":
            return int(numero)
        return numero

    if tipo == "booleano":
        if isinstance(bruto, bool):
            return bruto
        if str(bruto).lower() in {"true", "false"}:
            return str(bruto).lower() == "true"
        raise ValueError("debe ser true o false")

    if tipo == "fecha":
        texto = str(bruto).strip()
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", texto):
            raise ValueError("debe tener formato AAAA-MM-DD")
        from datetime import date

        try:
            date.fromisoformat(texto)
        except ValueError as error:
            raise ValueError("no es una fecha valida") from error
        return texto

    if tipo == "cedula":
        digitos = re.sub(r"[\s-]", "", str(bruto))
        if not re.fullmatch(r"\d{11}", digitos):
            raise ValueError("debe tener 11 digitos")
        if definicion.get("verificar_digito", True) and not cedula_valida(digitos):
            raise ValueError("no pasa la verificacion del digito verificador")
        return digitos

    if tipo == "rnc":
        digitos = re.sub(r"[\s-]", "", str(bruto))
        if not re.fullmatch(r"\d{9}", digitos):
            raise ValueError("debe tener 9 digitos")
        return digitos

    if tipo == "email":
        texto = str(bruto).strip().lower()
        if len(texto) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@.]+(\.[^\s@.]+)+", texto):
            raise ValueError("no es un correo valido")
        return texto

    if tipo == "telefono":
        limpio = re.sub(r"[\s()\-.]", "", str(bruto))
        if not re.fullmatch(r"\+?\d{7,15}", limpio):
            raise ValueError("no es un telefono valido")
        return limpio

    if tipo == "opcion":
        opciones = definicion.get("opciones") or []
        texto = str(bruto)
        if texto not in opciones:
            raise ValueError(f"debe ser uno de: {', '.join(map(str, opciones))}")
        return texto

    raise ValueError(f"tipo no soportado: {tipo}")


def cedula_valida(digitos: str) -> bool:
    """Digito verificador de la cedula dominicana (modulo 10, pesos 1 y 2)."""
    if not re.fullmatch(r"\d{11}", digitos):
        return False
    suma = 0
    for indice in range(10):
        producto = int(digitos[indice]) * (1 if indice % 2 == 0 else 2)
        if producto > 9:
            producto -= 9
        suma += producto
    return (10 - (suma % 10)) % 10 == int(digitos[10])


MESES = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
         "agosto", "septiembre", "octubre", "noviembre", "diciembre"]


def formatear(definicion: dict | None, valor: Any) -> str:
    """
    Formato para mostrar en el documento. Determinista a proposito: no usa
    locale ni nada que dependa del sistema, porque el documento tiene que
    poder regenerarse identico dentro de anos.
    """
    tipo = (definicion or {}).get("tipo")
    if tipo == "dinero" and isinstance(valor, Decimal):
        entera, _, decimal = f"{valor:.2f}".partition(".")
        negativo = entera.startswith("-")
        digitos = entera.lstrip("-")
        grupos = f"{int(digitos):,}"
        return f"{'-' if negativo else ''}{grupos}.{decimal}"
    if tipo == "fecha" and isinstance(valor, str):
        anio, mes, dia = valor.split("-")
        return f"{int(dia)} de {MESES[int(mes) - 1]} de {anio}"
    if tipo == "cedula" and isinstance(valor, str) and len(valor) == 11:
        return f"{valor[:3]}-{valor[3:10]}-{valor[10]}"
    if tipo == "rnc" and isinstance(valor, str) and len(valor) == 9:
        return f"{valor[0]}-{valor[1:3]}-{valor[3:8]}-{valor[8]}"
    if isinstance(valor, bool):
        return "Si" if valor else "No"
    return str(valor)
