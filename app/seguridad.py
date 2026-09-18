"""
Primitivas de seguridad.

Todo lo que tiene que ver con integridad probatoria pasa por aqui: hashes del
contenido, JSON canonico, HMAC, tokens de invitacion, codigos OTP y cifrado de
secretos en reposo.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import ajustes


def sha256(dato: str | bytes) -> str:
    if isinstance(dato, str):
        dato = dato.encode("utf-8")
    return hashlib.sha256(dato).hexdigest()


def json_canonico(valor: Any) -> str:
    """
    JSON determinista: claves ordenadas, sin espacios, Decimal como texto.

    Es lo que permite recalcular el mismo hash dentro de diez anos sobre las
    mismas variables, aunque el orden en que llegaron fuera otro.
    """
    return json.dumps(
        _normalizar(valor), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _normalizar(valor: Any) -> Any:
    from decimal import Decimal

    if isinstance(valor, Decimal):
        return format(valor, "f")
    if isinstance(valor, dict):
        return {clave: _normalizar(v) for clave, v in valor.items()}
    if isinstance(valor, (list, tuple)):
        return [_normalizar(v) for v in valor]
    return valor


def hmac_sha256(clave: bytes | str, mensaje: str) -> str:
    if isinstance(clave, str):
        clave = clave.encode("utf-8")
    return hmac.new(clave, mensaje.encode("utf-8"), hashlib.sha256).hexdigest()


def comparar_seguro(a: str, b: str) -> bool:
    """
    Comparacion en tiempo constante.

    Con == la comparacion se corta en el primer caracter distinto, asi que
    tarda un poco mas cuantos mas aciertos iniciales haya. Eso se puede medir y
    usar para adivinar un codigo caracter por caracter.
    """
    return hmac.compare_digest(a, b)


def derivar_clave(proposito: str) -> bytes:
    """Deriva una clave de uso especifico a partir de la clave maestra."""
    maestra = bytes.fromhex(ajustes().clave_app)
    return hmac.new(maestra, proposito.encode("utf-8"), hashlib.sha256).digest()


def token_aleatorio(bytes_entropia: int = 32) -> str:
    """Token impredecible para URLs. secrets, nunca random."""
    return secrets.token_urlsafe(bytes_entropia)


def hash_de_token(token: str) -> str:
    """Los tokens se guardan hasheados: leer la base de datos no da acceso."""
    return hmac_sha256(derivar_clave("token"), token)


def codigo_otp(digitos: int = 6) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(digitos))


def hash_secreto(secreto: str) -> str:
    """Hash de un secreto de credencial B2B, con sal."""
    sal = secrets.token_bytes(16)
    derivada = hashlib.scrypt(secreto.encode("utf-8"), salt=sal, n=16384, r=8, p=1, dklen=32)
    return f"scrypt${sal.hex()}${derivada.hex()}"


def verificar_secreto(secreto: str, almacenado: str) -> bool:
    try:
        etiqueta, sal_hex, esperado_hex = almacenado.split("$")
        if etiqueta != "scrypt":
            return False
        derivada = hashlib.scrypt(
            secreto.encode("utf-8"), salt=bytes.fromhex(sal_hex), n=16384, r=8, p=1, dklen=32
        )
        return comparar_seguro(derivada.hex(), esperado_hex)
    except (ValueError, AttributeError):
        return False


def cifrar(texto: str) -> str:
    """
    Cifra un secreto que el servicio necesita poder recuperar, como el secreto
    de firma de un webhook. La clave sale de CLAVE_APP, que vive fuera del
    repositorio.
    """
    aesgcm = AESGCM(derivar_clave("cifrado-en-reposo"))
    nonce = secrets.token_bytes(12)
    datos = aesgcm.encrypt(nonce, texto.encode("utf-8"), None)
    return f"v1.{nonce.hex()}.{datos.hex()}"


def descifrar(valor: str) -> str:
    version, nonce_hex, datos_hex = valor.split(".")
    if version != "v1":
        raise ValueError("Formato cifrado desconocido")
    aesgcm = AESGCM(derivar_clave("cifrado-en-reposo"))
    return aesgcm.decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(datos_hex), None).decode("utf-8")


def enmascarar(destino: str) -> str:
    """Para los logs: deja ver lo justo para identificar sin exponer el dato."""
    if "@" in destino:
        usuario, _, dominio = destino.partition("@")
        return f"{usuario[:2]}{'*' * max(1, len(usuario) - 2)}@{dominio}"
    return f"{'*' * max(0, len(destino) - 4)}{destino[-4:]}"
