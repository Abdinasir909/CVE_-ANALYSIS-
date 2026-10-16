# Daily incremental CVE batch: fetch new or modified CVEs -> PySpark ETL -> optional
# Snowflake load. The Snowflake step is off by default because the loader truncates.

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from src.ingestion.ingest_nvd_batch import (
    API_URL,
    MAX_RANGE_DAYS,
    NvdApiError,
    _build_headers,
    _fetch_page,
    _merge_pages,
    _split_range,
)
from src.utils.config import Config
from src.utils.logging_config import get_logger, setup_logging

logger = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent
STATE_FILE = PROJECT_ROOT / "state" / "last_run.json"
INCREMENTAL_DIR = PROJECT_ROOT / "data" / "incremental"
LOGS_DIR = PROJECT_ROOT / "logs"
DEFAULT_BACKFILL_HOURS = 24


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# Treat a naive datetime as UTC.
def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# Read the end time of the last successful run, or None if there is no state yet.
def _read_state() -> "datetime | None":
    if not STATE_FILE.exists():
        return None
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return _as_utc(datetime.fromisoformat(data["last_successful_end"]))
    except (ValueError, KeyError, OSError, json.JSONDecodeError):
        logger.warning("state file unreadable; defaulting to the backfill window")
        return None


# Persist the end time only after the whole run has succeeded.
def _write_state(end: datetime) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps({"last_successful_end": end.isoformat()}, indent=2),
        encoding="utf-8",
    )


# Resolve the window: --since/--until override, else the state file, else the last 24h.
def _resolve_window(since: str | None, until: str | None) -> tuple[datetime, datetime]:
    end = _as_utc(datetime.fromisoformat(until)) if until else _now_utc()
    if since:
        start = _as_utc(datetime.fromisoformat(since))
    else:
        start = _read_state() or (end - timedelta(hours=DEFAULT_BACKFILL_HOURS))
    if start > end:
        raise SystemExit(f"--since ({start.isoformat()}) is after --until ({end.isoformat()})")
    return start, end


# NVD lastModified params; both are required full ISO-8601 UTC timestamps.
def _build_lastmod_params(start: datetime, end: datetime, results_per_page: int) -> dict:
    return {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.999"),
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }


# Fetch one lastModified window (paginated) into a single JSON file; returns the record count.
def _fetch_lastmod_range(start, end, output_path, api_url, results_per_page, headers, delay) -> int:
    base_params = _build_lastmod_params(start, end, results_per_page)
    pages = []
    start_index = 0
    total_results = None

    while True:
        params = dict(base_params)
        params["startIndex"] = start_index
        logger.info("fetching page", extra={"startIndex": start_index, "resultsPerPage": results_per_page})
        page = _fetch_page(api_url, params, headers)
        total_results = int(page.get("totalResults", 0))
        page_count = len(page.get("vulnerabilities", []) or [])
        pages.append(page)
        logger.info("page received", extra={"records": page_count, "totalResults": total_results})
        if total_results is None or page_count == 0:
            break
        start_index += page_count
        if start_index >= total_results:
            break
        time.sleep(delay)

    merged = _merge_pages(pages)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(merged.get("vulnerabilities", []))


# Append a line to the run log and echo it to stdout.
def _log(log_file: Path, message: str) -> None:
    print(message, flush=True)
    if log_file is not None:
        with log_file.open("a", encoding="utf-8") as fh:
            fh.write(message + "\n")


# Run one subprocess stage and return its exit code.
def _run_stage(cmd: list[str], log_file: Path) -> int:
    _log(log_file, "  + " + " ".join(cmd))
    proc = subprocess.run(cmd, cwd=PROJECT_ROOT)
    return proc.returncode


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run the daily incremental CVE batch pipeline.")
    parser.add_argument("--dry-run", action="store_true", help="Print what would run, change nothing.")
    parser.add_argument("--since", help="Override window start (ISO-8601 UTC, e.g. 2026-10-11T00:00:00).")
    parser.add_argument("--until", help="Override window end (ISO-8601 UTC).")
    parser.add_argument("--load-snowflake", action="store_true", help="Run the Snowflake load (off by default; full reload).")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    config = Config()
    setup_logging(config.log_level)

    start, end = _resolve_window(args.since, args.until)
    run_id = _now_utc().strftime("%Y-%m-%d")
    run_dir = INCREMENTAL_DIR / run_id
    raw_dir = run_dir / "raw"

    api_url = config.nvd_api_url or API_URL
    results_per_page = config.nvd_results_per_page
    headers = _build_headers(config.nvd_api_key)
    delay = 0.6 if config.nvd_api_key else max(6.0, config.nvd_request_delay_seconds)
    chunks = _split_range(start, end, MAX_RANGE_DAYS)

    if args.dry_run:
        print("DRY RUN (no fetch, no ETL, no load, no state write)")
        print(f"range:  {start.isoformat()} .. {end.isoformat()}")
        print(f"chunks: {len(chunks)}")
        for cs, ce in chunks:
            print(f"  fetch lastMod {cs.isoformat()} .. {ce.isoformat()}")
        print(f"etl -> {run_dir}")
        print(f"snowflake load: {'ON' if args.load_snowflake else 'OFF (default)'}")
        return 0

    log_file = LOGS_DIR / f"pipeline_{run_id}.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    _log(log_file, f"=== run {run_id} ===")
    _log(log_file, f"start: {_now_utc().isoformat()}")
    _log(log_file, f"range: {start.isoformat()} .. {end.isoformat()}")
    _log(log_file, f"run dir: {run_dir}")

    stage_times: dict[str, float] = {}

    # Fetch stage.
    t0 = time.monotonic()
    total_fetched = 0
    try:
        for cs, ce in chunks:
            out = raw_dir / f"nvd_cves_lastmod_{cs.strftime('%Y%m%dT%H%M%S')}_{ce.strftime('%Y%m%dT%H%M%S')}.json"
            total_fetched += _fetch_lastmod_range(cs, ce, out, api_url, results_per_page, headers, delay)
    except (NvdApiError, requests.RequestException) as exc:
        _log(log_file, f"FAILED at fetch: {exc}")
        _log(log_file, "result: FAILURE")
        return 2
    stage_times["fetch"] = round(time.monotonic() - t0, 1)
    _log(log_file, f"fetch: {total_fetched} records in {stage_times['fetch']}s")

    # ETL stage.
    t0 = time.monotonic()
    etl_input = str(raw_dir / "*.json")
    etl_rc = _run_stage(
        [sys.executable, "-m", "src.transformation.batch_etl", "--input", etl_input, "--output-dir", str(run_dir)],
        log_file,
    )
    stage_times["etl"] = round(time.monotonic() - t0, 1)
    if etl_rc != 0:
        _log(log_file, f"FAILED at ETL (exit {etl_rc})")
        _log(log_file, "result: FAILURE")
        return etl_rc

    # Report the ETL output counts read back from the quality report.
    report_path = run_dir / "quality_report.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        _log(log_file, "etl counts: " + json.dumps({
            "input_records": report.get("input_records"),
            "output_records": report.get("output_records"),
            "missing_cvss": report.get("records_missing_cvss"),
            "missing_vendor": report.get("records_missing_vendor"),
        }))
    _log(log_file, f"etl: done in {stage_times['etl']}s")

    # Optional Snowflake load (off by default).
    if args.load_snowflake:
        t0 = time.monotonic()
        load_rc = _run_stage(
            [sys.executable, "-m", "src.warehouse.load_to_snowflake", "--input", str(run_dir / "cves_cleaned.parquet")],
            log_file,
        )
        stage_times["load"] = round(time.monotonic() - t0, 1)
        if load_rc != 0:
            _log(log_file, f"FAILED at Snowflake load (exit {load_rc})")
            _log(log_file, "result: FAILURE")
            return load_rc
        _log(log_file, f"load: done in {stage_times['load']}s")

    # Success: write the state file only now.
    _write_state(end)
    _log(log_file, f"end: {_now_utc().isoformat()}")
    _log(log_file, f"stages: {stage_times}")
    _log(log_file, "result: SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
