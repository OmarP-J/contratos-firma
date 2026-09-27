"""
Proveedor de firma.

Es la pieza que el documento de la propuesta pide mantener abierta: el dominio
del producto (empresas, plantillas, contratos, estados, API, permisos) es
nuestro, pero el mecanismo criptografico puede ser propio o delegarse en una
entidad especializada sin reescribir el resto.

Todo lo que el resto del servicio conoce de la firma es la clase base.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.seguridad import derivar_clave, json_canonico


@dataclass(frozen=True)
class SolicitudFirma:
    tenant_id: str
    contrato_id: str
    parte_id: str
    hash_documento: str
    hash_evidencia: str
    nombre: str
    documento: str | None
    rol: str
    firmado_en: datetime


@dataclass(frozen=True)
class ResultadoFirma:
    proveedor: str
    algoritmo: str
    valor: str


def payload_firmable(solicitud: SolicitudFirma) -> str:
    """Lo que se firma. Debe ser identico al firmar y al verificar."""
    return json_canonico({
        "contrato": solicitud.contrato_id,
        "documento": solicitud.hash_documento,
        "evidencia": solicitud.hash_evidencia,
        "firmado_en": solicitud.firmado_en.isoformat(),
        "firmante": {
            "documento": solicitud.documento,
            "nombre": solicitud.nombre,
            "rol": solicitud.rol,
        },
        "parte": solicitud.parte_id,
        "tenant": solicitud.tenant_id,
    })


@runtime_checkable
class ProveedorFirma(Protocol):
    nombre: str

    def firmar(self, solicitud: SolicitudFirma) -> ResultadoFirma: ...
    def verificar(self, solicitud: SolicitudFirma, resultado: ResultadoFirma) -> bool: ...
    def clave_publica(self) -> str | None: ...


class ProveedorInterno:
    """
    Firma con Ed25519 el paquete formado por el hash del documento presentado y
    el hash de las evidencias del firmante. Eso permite demostrar despues que
    ese documento exacto, con esa evidencia exacta, fue sellado por este
    servicio y no ha cambiado.

    Lo que NO hace, y conviene tenerlo claro: no emite una firma digital
    respaldada por una entidad de certificacion. Segun el tipo de contrato y lo
    que exija la Ley 126-02 puede hacer falta un proveedor acreditado; para eso
    existe esta interfaz y se cambia solo este archivo.

    La clave se deriva de CLAVE_APP. En un despliegue serio deberia vivir en un
    KMS o HSM y no salir de ahi.
    """

    nombre = "interno"

    def _claves(self) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        privada = Ed25519PrivateKey.from_private_bytes(derivar_clave("firma-ed25519"))
        return privada, privada.public_key()

    def firmar(self, solicitud: SolicitudFirma) -> ResultadoFirma:
        privada, _ = self._claves()
        firma = privada.sign(payload_firmable(solicitud).encode("utf-8"))
        return ResultadoFirma(proveedor=self.nombre, algoritmo="Ed25519", valor=firma.hex())

    def verificar(self, solicitud: SolicitudFirma, resultado: ResultadoFirma) -> bool:
        if resultado.algoritmo != "Ed25519":
            return False
        _, publica = self._claves()
        try:
            publica.verify(bytes.fromhex(resultado.valor), payload_firmable(solicitud).encode("utf-8"))
            return True
        except Exception:
            return False

    def clave_publica(self) -> str:
        _, publica = self._claves()
        return publica.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()


class ProveedorExterno:
    """
    Esqueleto deliberado. Aqui va la integracion con el proveedor acreditado que
    se elija (certificados, PKI, sellado de tiempo, audit trail certificado).

    Lo importante ya esta resuelto: el resto del servicio solo conoce la
    interfaz, asi que cambiar de estrategia es implementar estos tres metodos.
    """

    nombre = "externo"

    def firmar(self, solicitud: SolicitudFirma) -> ResultadoFirma:
        raise NotImplementedError("Proveedor de firma externo no implementado")

    def verificar(self, solicitud: SolicitudFirma, resultado: ResultadoFirma) -> bool:
        raise NotImplementedError("Verificacion contra proveedor externo no implementada")

    def clave_publica(self) -> str | None:
        return None


proveedor_actual: ProveedorFirma = ProveedorInterno()
