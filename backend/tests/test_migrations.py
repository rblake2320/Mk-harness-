"""Alembic coverage for fresh installs and pre-v1.7 database upgrades."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect

from app.models import Base

_AGENT_TABLES = {
    "agent_ops_audit_entries",
    "agent_ops_audit_heads",
    "agent_ops_contact_permissions",
    "agent_ops_contact_suppressions",
    "agent_ops_tasks",
    "mobile_agents",
    "mobile_callback_nonces",
}


def _alembic(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    executable = Path(sys.executable).with_name(
        "alembic.exe" if os.name == "nt" else "alembic"
    )
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    return subprocess.run(
        [str(executable), *args],
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )


def _tables(tmp_path: Path) -> set[str]:
    engine = create_engine(f"sqlite:///{(tmp_path / 'migration.db').as_posix()}")
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_fresh_database_upgrade_downgrade_and_schema_check(tmp_path):
    _alembic(tmp_path, "upgrade", "head")
    assert _AGENT_TABLES <= _tables(tmp_path)
    checked = _alembic(tmp_path, "check")
    assert "No new upgrade operations detected" in checked.stdout

    _alembic(tmp_path, "downgrade", "base")
    assert _tables(tmp_path) <= {"alembic_version"}
    _alembic(tmp_path, "upgrade", "head")
    assert _AGENT_TABLES <= _tables(tmp_path)


def test_existing_core_schema_can_stamp_baseline_then_upgrade(tmp_path):
    database_url = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    engine = create_engine(database_url)
    try:
        core_tables = [
            table
            for table in Base.metadata.sorted_tables
            if table.name not in _AGENT_TABLES
        ]
        Base.metadata.create_all(engine, tables=core_tables)
    finally:
        engine.dispose()

    _alembic(tmp_path, "stamp", "0001")
    _alembic(tmp_path, "upgrade", "head")
    assert _AGENT_TABLES <= _tables(tmp_path)
