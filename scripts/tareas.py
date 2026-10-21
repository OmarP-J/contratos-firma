"""
Proceso de tareas periodicas: vencimiento de contratos y reintento de webhooks.

    python -m scripts.tareas                 # cada 30 segundos, hasta Ctrl+C
    python -m scripts.tareas --intervalo 60
    python -m scripts.tareas --una-vez       # una pasada, util para cron
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db import crear_tablas  # noqa: E402
from app.tareas import ejecutar_ciclo, ejecutar_siempre  # noqa: E402


def main() -> None:
    argumentos = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    argumentos.add_argument("--intervalo", type=float, default=30.0,
                            help="segundos entre pasadas (por defecto 30)")
    argumentos.add_argument("--una-vez", action="store_true",
                            help="hacer una sola pasada y salir")
    opciones = argumentos.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    crear_tablas()

    if opciones.una_vez:
        print(ejecutar_ciclo())
        return
    try:
        ejecutar_siempre(opciones.intervalo)
    except KeyboardInterrupt:
        print("\ndetenido")


if __name__ == "__main__":
    main()
