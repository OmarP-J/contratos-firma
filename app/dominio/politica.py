"""
Politica de firma.

Se declara en la version de plantilla y se CONGELA dentro del contrato al
crearlo. Si manana el administrador cambia la politica, los contratos ya
emitidos siguen rigiendose por la que tenian.
"""
from __future__ import annotations

from typing import Any

POR_DEFECTO = {
    "requiere_otp": True,
    "canal_otp": "EMAIL",
    "requiere_geolocalizacion": False,
    "requiere_firma_empresa": False,
    "horas_vigencia": 72,
    # Mandar el enlace de firma al firmante por correo o SMS. Apagarlo tiene
    # sentido si el integrador prefiere entregar el enlace en su propia app.
    "notificar_invitaciones": True,
}


def normalizar(entrada: Any) -> dict:
    origen = entrada if isinstance(entrada, dict) else {}
    horas = origen.get("horas_vigencia", POR_DEFECTO["horas_vigencia"])
    try:
        horas = int(horas)
    except (TypeError, ValueError):
        horas = POR_DEFECTO["horas_vigencia"]
    return {
        "requiere_otp": bool(origen.get("requiere_otp", True)),
        "canal_otp": "SMS" if origen.get("canal_otp") == "SMS" else "EMAIL",
        "requiere_geolocalizacion": bool(origen.get("requiere_geolocalizacion", False)),
        "requiere_firma_empresa": bool(origen.get("requiere_firma_empresa", False)),
        "horas_vigencia": max(1, min(horas, 24 * 90)),
        "notificar_invitaciones": bool(origen.get("notificar_invitaciones", True)),
    }
