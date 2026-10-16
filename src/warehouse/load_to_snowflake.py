# Load the cleaned Parquet output into Snowflake (stage, truncate, COPY INTO, verify count).
# Parquet, not CSV: descriptions contain commas, quotes and newlines.

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.utils.config import Config
from src.utils.logging_config import get_logger, setup_logging

logger = get_logger(__name__)

SCHEMA = "raw"
STAGE = "raw.cve_stage"
TABLE = "raw.cve_raw"
FILE_FORMAT = "raw.cve_parquet_format"

DEFAULT_INPUT = "data/processed/cves_cleaned.parquet"


def build_remove_command() -> str:
    return f"REMOVE @{STAGE}"


def build_truncate_command(table: str = TABLE) -> str:
    return f"TRUNCATE TABLE {table}"


def build_put_command(file_path: str) -> str:
    return f"PUT file://{file_path}/*.parquet @{STAGE} OVERWRITE = TRUE"


# Columns are matched by name, so the Parquet field order does not have to match.
def build_copy_command(table: str = TABLE) -> str:
    return (
        f"COPY INTO {table} "
        f"FROM @{STAGE} "
        f"FILE_FORMAT = (FORMAT_NAME = '{FILE_FORMAT}') "
        f"PATTERN = '.*[.]parquet' "
        f"MATCH_BY_COLUMN_NAME = CASE_INSENSITIVE"
    )


def build_count_command(table: str = TABLE) -> str:
    return f"SELECT COUNT(*) FROM {table}"


def _connect(config: Config):
    # Imported here so the module stays importable without a live account.
    import snowflake.connector

    return snowflake.connector.connect(
        account=config.snowflake_account,
        user=config.snowflake_user,
        password=config.snowflake_password,
        warehouse=config.snowflake_warehouse,
        database=config.snowflake_database,
        schema=SCHEMA,
    )


# Run REMOVE, TRUNCATE, PUT, COPY INTO and COUNT; returns the verified row count.
# Closes the cursor it opens; the connection belongs to the caller.
def load_parquet(conn, file_path: str, full_reload: bool = True, table: str = TABLE) -> int:
    cursor = conn.cursor()
    try:
        cursor.execute(build_remove_command())

        # TRUNCATE first: COPY INTO appends, so a rerun would otherwise double the table.
        if full_reload:
            cursor.execute(build_truncate_command(table))
            logger.info("TRUNCATE complete", extra={"table": table})
        else:
            logger.warning(
                "appending without TRUNCATE — COPY INTO adds to existing rows",
                extra={"table": table},
            )

        cursor.execute(build_put_command(file_path))
        logger.info("PUT complete", extra={"stage": STAGE, "path": file_path})

        cursor.execute(build_copy_command(table))
        logger.info("COPY INTO complete", extra={"table": table})

        cursor.execute(build_count_command(table))
        count = cursor.fetchone()[0]
        logger.info("verification count", extra={"table": table, "count": count})
        return count
    finally:
        cursor.close()


# CLI flags: the parquet input and whether to replace the table or append to it.
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Load cleaned CVE parquet into Snowflake (raw schema)."
    )
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help="Path to the cleaned parquet directory produced by batch_etl.py.",
    )
    parser.add_argument(
        "--full-reload",
        dest="full_reload",
        action="store_true",
        default=True,
        help="TRUNCATE the table before loading (default).",
    )
    parser.add_argument(
        "--no-full-reload",
        dest="full_reload",
        action="store_false",
        help="Append to the table instead of replacing its contents.",
    )
    return parser.parse_args(argv)


# Entry point: validate credentials and input, then run the load, owning the connection.
def main(argv=None) -> int:
    args = parse_args(argv)
    config = Config()
    setup_logging(config.log_level)

    # Snowflake credentials are optional in Config; require them here before connecting.
    if not (
        config.snowflake_account
        and config.snowflake_user
        and config.snowflake_password
    ):
        logger.error(
            "Snowflake credentials not set — copy .env.example to .env and fill in "
            "SNOWFLAKE_ACCOUNT, SNOWFLAKE_USER and SNOWFLAKE_PASSWORD"
        )
        return 2

    input_path = Path(args.input)
    if not input_path.exists():
        logger.error("input parquet not found", extra={"path": str(input_path)})
        return 2

    try:
        conn = _connect(config)
    except Exception as exc:
        logger.error(
            "cannot connect to Snowflake — check SNOWFLAKE_* env vars",
            extra={"account": config.snowflake_account, "error": str(exc)},
        )
        return 2

    try:
        count = load_parquet(conn, str(input_path), full_reload=args.full_reload)
    except Exception as exc:
        logger.error("Snowflake load failed", extra={"error": str(exc)})
        return 1
    finally:
        conn.close()

    logger.info("Snowflake load complete", extra={"table": TABLE, "count": count})
    return 0


if __name__ == "__main__":
    sys.exit(main())
