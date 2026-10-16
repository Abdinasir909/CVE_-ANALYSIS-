# Tests for load_to_snowflake: statement building and cursor lifecycle, against a
# fake connection rather than a real account.

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.warehouse.load_to_snowflake import (
    build_copy_command,
    build_put_command,
    load_parquet,
    main,
    parse_args,
)


class _FakeCursor:
    def __init__(self, raise_on_execute=False, count=727):
        self.statements = []
        self.closed = False
        self.raise_on_execute = raise_on_execute
        self.count = count

    def execute(self, sql):
        if self.raise_on_execute:
            raise RuntimeError("synthetic Snowflake failure")
        self.statements.append(sql)

    def fetchone(self):
        return (self.count,)

    def close(self):
        self.closed = True


class _FakeConnection:
    def __init__(self, raise_on_execute=False, count=727):
        self.cursor_obj = _FakeCursor(raise_on_execute=raise_on_execute, count=count)
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


# Config-shaped stand-in with sensible Snowflake values.
def _fake_config(**overrides) -> SimpleNamespace:
    values = {
        "snowflake_account": "acct",
        "snowflake_user": "usr",
        "snowflake_password": "pw",
        "snowflake_warehouse": "cve_analysis_wh",
        "snowflake_database": "cve_analysis",
        "log_level": "INFO",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_build_put_command_uses_parquet_glob():
    command = build_put_command("data/processed/cves_cleaned.parquet")
    assert "file://data/processed/cves_cleaned.parquet/*.parquet" in command
    assert "@raw.cve_stage" in command
    assert "OVERWRITE = TRUE" in command


def test_build_copy_command_uses_parquet_format():
    command = build_copy_command()
    assert command.startswith("COPY INTO raw.cve_raw")
    assert "FORMAT_NAME = 'raw.cve_parquet_format'" in command
    assert "PATTERN = '.*[.]parquet'" in command
    assert "MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE" in command


# load_parquet runs REMOVE, TRUNCATE, PUT, COPY INTO and COUNT, then closes its cursor.
def test_load_parquet_runs_remove_truncate_put_copy_count():
    conn = _FakeConnection(count=727)
    count = load_parquet(conn, "data/processed/cves_cleaned.parquet")

    assert count == 727
    remove, truncate, put, copy, count_sql = conn.cursor_obj.statements
    assert remove == "REMOVE @raw.cve_stage"
    assert truncate == "TRUNCATE TABLE raw.cve_raw"
    assert put == "PUT file://data/processed/cves_cleaned.parquet/*.parquet @raw.cve_stage OVERWRITE = TRUE"
    assert copy.startswith("COPY INTO raw.cve_raw")
    assert count_sql == "SELECT COUNT(*) FROM raw.cve_raw"
    assert conn.cursor_obj.closed is True
    # The connection belongs to the caller, so load_parquet must leave it open.
    assert conn.closed is False


# The TRUNCATE must precede the COPY INTO, or the reload would clear the new rows.
def test_full_reload_truncates_before_copy():
    conn = _FakeConnection()
    load_parquet(conn, "data/processed/cves_cleaned.parquet")

    statements = conn.cursor_obj.statements
    truncate_at = statements.index("TRUNCATE TABLE raw.cve_raw")
    copy_at = next(i for i, s in enumerate(statements) if s.startswith("COPY INTO"))
    assert truncate_at < copy_at


# --no-full-reload appends: no TRUNCATE is issued at all.
def test_no_full_reload_omits_truncate():
    conn = _FakeConnection()
    load_parquet(conn, "data/processed/cves_cleaned.parquet", full_reload=False)

    assert not any(s.startswith("TRUNCATE") for s in conn.cursor_obj.statements)


# The flag defaults to a full reload, so a bare invocation cannot double the table.
def test_full_reload_defaults_to_true():
    assert parse_args([]).full_reload is True
    assert parse_args(["--no-full-reload"]).full_reload is False
    assert parse_args(["--full-reload"]).full_reload is True


# A failing statement still closes the cursor in the finally block.
def test_load_parquet_closes_cursor_on_error():
    conn = _FakeConnection(raise_on_execute=True)
    with pytest.raises(RuntimeError):
        load_parquet(conn, "data/processed/cves_cleaned.parquet")
    assert conn.cursor_obj.closed is True


# main owns the connection, so it closes it even when the load raises.
def test_main_closes_connection_on_error():
    conn = _FakeConnection(raise_on_execute=True)
    with patch("src.warehouse.load_to_snowflake.Config", return_value=_fake_config()), patch(
        "src.warehouse.load_to_snowflake._connect", return_value=conn
    ), patch("src.warehouse.load_to_snowflake.Path.exists", return_value=True):
        assert main([]) == 1
    assert conn.closed is True


def test_main_errors_without_credentials():
    config = _fake_config(
        snowflake_account="", snowflake_user="", snowflake_password=""
    )
    with patch("src.warehouse.load_to_snowflake.Config", return_value=config):
        assert main([]) == 2
