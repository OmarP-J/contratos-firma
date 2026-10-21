"""Almacen de documentos: claves validas, travesia de directorios y aislamiento."""
from __future__ import annotations

import pytest

from app.almacenamiento import AlmacenLocal, nueva_clave


@pytest.fixture
def almacen(tmp_path):
    return AlmacenLocal(str(tmp_path / "almacen"))


def test_guarda_y_lee_con_una_clave_generada(almacen):
    clave = nueva_clave("tenant-1", "contrato-1", "contrato.html")
    almacen.guardar(clave, b"<p>hola</p>")
    assert almacen.existe(clave)
    assert almacen.leer(clave) == b"<p>hola</p>"


@pytest.mark.parametrize(
    "clave",
    [
        "../fuera.html",
        "tenant/../../fuera.html",
        "tenant/contrato/../../../fuera.html",
        "",
        "con espacios.html",
        "tenant\\contrato\\x.html",
    ],
)
def test_rechaza_claves_que_salen_del_almacen(almacen, clave):
    with pytest.raises(ValueError):
        almacen.guardar(clave, b"x")


def test_dos_claves_del_mismo_contrato_no_coinciden():
    primera = nueva_clave("t", "c", "contrato.html")
    segunda = nueva_clave("t", "c", "contrato.html")
    assert primera != segunda
