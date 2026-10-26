"""
Da de alta a una persona en el portal administrativo de una empresa.

    python -m scripts.crear_admin --empresa acme --email ana@acme.com --nombre "Ana Gomez"

La clave se pide por teclado, asi no queda en el historial de la terminal. La
primera vez que entre, el portal le pedira registrar su app autenticadora.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select  # noqa: E402

from app.db import FabricaSesion  # noqa: E402
from app.dominio import administradores  # noqa: E402
from app.models import Tenant  # noqa: E402


def main() -> None:
    argumentos = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    argumentos.add_argument("--empresa", required=True, help="slug de la empresa (por ejemplo, acme)")
    argumentos.add_argument("--email", required=True)
    argumentos.add_argument("--nombre", required=True)
    opciones = argumentos.parse_args()

    clave = getpass.getpass("Clave (minimo 12 caracteres): ")
    if clave != getpass.getpass("Repite la clave: "):
        raise SystemExit("Las claves no coinciden")

    with FabricaSesion() as sesion:
        tenant = sesion.scalars(select(Tenant).where(Tenant.slug == opciones.empresa)).first()
        if tenant is None:
            raise SystemExit(f"No existe la empresa {opciones.empresa}")
        try:
            usuario = administradores.crear_usuario(
                sesion, tenant_id=tenant.id, email=opciones.email,
                nombre=opciones.nombre, clave=clave,
            )
        except administradores.DatosDeUsuarioInvalidos as error:
            raise SystemExit(str(error)) from error
        sesion.commit()
        print(f"\nListo: {usuario.email} ya puede entrar en /admin de {tenant.nombre}.\n")


if __name__ == "__main__":
    main()
