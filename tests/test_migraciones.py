"""Las migraciones de Alembic producen exactamente el esquema de los modelos."""
from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app.db import Base

RAIZ = Path(__file__).resolve().parent.parent


@pytest.fixture
def base_vacia(tmp_path):
    url = f"sqlite:///{(tmp_path / 'migrada.db').as_posix()}"
    config = Config(str(RAIZ / "alembic.ini"))
    config.set_main_option("script_location", str(RAIZ / "migraciones"))
    config.set_main_option("sqlalchemy.url", url)
    config.attributes["configurar_logs"] = False
    motor = create_engine(url)
    yield config, motor
    motor.dispose()


def test_upgrade_head_deja_el_mismo_esquema_que_los_modelos(base_vacia):
    config, motor = base_vacia
    command.upgrade(config, "head")

    with motor.connect() as conexion:
        diferencias = compare_metadata(
            MigrationContext.configure(conexion, opts={"compare_type": True}), Base.metadata
        )
    assert diferencias == [], "hay cambios en los modelos sin migracion: alembic revision --autogenerate"


def test_downgrade_base_deshace_todo(base_vacia):
    config, motor = base_vacia
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert set(inspect(motor).get_table_names()) == {"alembic_version"}


def test_hay_una_sola_cabeza():
    from alembic.script import ScriptDirectory

    config = Config(str(RAIZ / "alembic.ini"))
    config.set_main_option("script_location", str(RAIZ / "migraciones"))
    assert len(ScriptDirectory.from_config(config).get_heads()) == 1


def test_en_produccion_no_se_crean_tablas_por_fuera_de_alembic(monkeypatch):
    from app import db
    from app.config import ajustes

    llamadas = []
    monkeypatch.setattr(ajustes(), "entorno", "produccion")
    monkeypatch.setattr(db.Base.metadata, "create_all", lambda *a, **k: llamadas.append(1))
    db.crear_tablas()
    assert llamadas == []
