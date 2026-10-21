"""Limite de peticiones, en memoria y compartido en Redis."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from redis.exceptions import ConnectionError as RedisConnectionError

from app import dependencias
from app.dependencias import LimitadorMemoria, LimitadorRedis


class RedisFalso:
    """Lo justo de Redis para el limitador: INCR y EXPIRE en una tuberia."""

    def __init__(self, caido: bool = False) -> None:
        self.valores: dict[str, int] = {}
        self.caducidad: dict[str, int] = {}
        self.caido = caido

    def pipeline(self):
        return TuberiaFalsa(self)


class TuberiaFalsa:
    def __init__(self, redis: RedisFalso) -> None:
        self.redis = redis
        self.comandos: list[tuple] = []

    def incr(self, llave):
        self.comandos.append(("incr", llave))

    def expire(self, llave, segundos):
        self.comandos.append(("expire", llave, segundos))

    def execute(self):
        if self.redis.caido:
            raise RedisConnectionError("conexion rechazada")
        resultados = []
        for comando in self.comandos:
            if comando[0] == "incr":
                self.redis.valores[comando[1]] = self.redis.valores.get(comando[1], 0) + 1
                resultados.append(self.redis.valores[comando[1]])
            else:
                self.redis.caducidad[comando[1]] = comando[2]
                resultados.append(True)
        return resultados


@pytest.mark.parametrize("fabrica", [LimitadorMemoria, lambda: LimitadorRedis(RedisFalso())])
def test_deja_pasar_hasta_el_limite_y_luego_corta(fabrica):
    limitador = fabrica()
    resultados = [limitador.permitir("otp:parte-1", limite=3, ventana_s=60) for _ in range(5)]
    assert resultados == [True, True, True, False, False]


@pytest.mark.parametrize("fabrica", [LimitadorMemoria, lambda: LimitadorRedis(RedisFalso())])
def test_cada_clave_lleva_su_propia_cuenta(fabrica):
    limitador = fabrica()
    assert limitador.permitir("a", limite=1, ventana_s=60)
    assert not limitador.permitir("a", limite=1, ventana_s=60)
    assert limitador.permitir("b", limite=1, ventana_s=60)


def test_en_redis_la_cuenta_caduca_con_la_ventana():
    redis = RedisFalso()
    LimitadorRedis(redis).permitir("auth:1.2.3.4", limite=30, ventana_s=60)
    [llave] = redis.caducidad
    assert llave.startswith("limite:auth:1.2.3.4:")
    assert redis.caducidad[llave] == 60


def test_en_redis_una_ventana_nueva_empieza_de_cero(monkeypatch):
    limitador = LimitadorRedis(RedisFalso())
    monkeypatch.setattr(dependencias.time, "time", lambda: 1_000_000.0)
    assert limitador.permitir("k", limite=1, ventana_s=60)
    assert not limitador.permitir("k", limite=1, ventana_s=60)
    monkeypatch.setattr(dependencias.time, "time", lambda: 1_000_060.0)
    assert limitador.permitir("k", limite=1, ventana_s=60)


def test_si_redis_se_cae_la_peticion_pasa_y_queda_registrado(caplog):
    limitador = LimitadorRedis(RedisFalso(caido=True))
    with caplog.at_level("WARNING", logger="limites"):
        assert limitador.permitir("k", limite=1, ventana_s=60)
    assert "Redis no responde" in caplog.text


def test_limitar_responde_429(monkeypatch):
    monkeypatch.setattr(dependencias, "_limitador", LimitadorMemoria())
    dependencias.limitar("k", limite=1, ventana_s=60)
    with pytest.raises(HTTPException) as error:
        dependencias.limitar("k", limite=1, ventana_s=60)
    assert error.value.status_code == 429


def test_la_configuracion_elige_redis(monkeypatch):
    from app.config import ajustes

    monkeypatch.setattr(ajustes(), "url_redis", "redis://localhost:6379/0")
    assert isinstance(dependencias._crear_limitador(), LimitadorRedis)
    monkeypatch.setattr(ajustes(), "url_redis", "")
    assert isinstance(dependencias._crear_limitador(), LimitadorMemoria)
