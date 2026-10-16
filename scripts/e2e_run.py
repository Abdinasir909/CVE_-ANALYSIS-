"""Time all five pipeline stages end to end for one evaluation run.

Every figure is a wall-clock measurement taken around the stage as it ran.

Usage:
  python scripts/e2e_run.py --run three-day
  python scripts/e2e_run.py --run one-year  --etl-repeats 1
  python scripts/e2e_run.py --run eight-year --etl-repeats 2 --with-load
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Patches platform.libc_ver so the Snowflake connector can authenticate.
import _snowflake_compat  # noqa: E402,F401

LOG_DIR = PROJECT_ROOT / "logs"
E2E_RAW_DIR = PROJECT_ROOT / "data" / "raw_e2e"

# Chunks are named explicitly rather than globbed: data/raw/ holds both windows,
# and a wildcard would mix them.
ONE_YEAR_CHUNKS = (
    "2025-09-22_to_2025-12-21",
    "2025-12-22_to_2026-03-21",
    "2026-03-22_to_2026-06-21",
    "2026-06-22_to_2026-09-21",
)

RUNS = {
    "three-day": {
        "window": ("2026-08-28", "2026-08-30"),
        "fetch": False,
        "etl_input": "data/raw_windows/three_day_2026-08-28_to_2026-08-30.json",
        "output_dir": "data/processed_e2e/three_day",
    },
    "one-year": {
        "window": ("2025-09-22", "2026-09-21"),
        "fetch": True,
        "etl_input": None,  # built from ONE_YEAR_CHUNKS
        "output_dir": "data/processed_e2e/one_year",
    },
    "eight-year": {
        "window": ("2018-09-22", "2026-09-21"),
        "fetch": True,
        "etl_input": None,  # every chunk that is not a one-year chunk
        "output_dir": "data/processed_e2e/eight_year",
    },
}


# Paths this harness must never write to: the frozen raw input and the cleaned
# output the analysis reads.
PROTECTED_PATHS = (
    PROJECT_ROOT / "data" / "raw",
    PROJECT_ROOT / "data" / "processed_8y",
    PROJECT_ROOT / "data" / "processed_8y_frozen_13oct",
)


def assert_not_protected(*paths) -> None:
    """Refuse to run if any output path resolves inside a protected directory."""
    for raw_path in paths:
        if raw_path is None:
            continue
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        candidate = candidate.resolve()
        for protected in PROTECTED_PATHS:
            guarded = protected.resolve()
            if candidate == guarded or guarded in candidate.parents:
                raise SystemExit(
                    f"refusing to run: output path {candidate} resolves inside "
                    f"the protected directory {guarded}. e2e fetches belong in "
                    f"data/raw_e2e/ and e2e ETL output in data/processed_e2e/<run>/."
                )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


# Build the Hadoop brace glob naming exactly the chunks belonging to this run.
def build_etl_input(run: str) -> str:
    spec = RUNS[run]
    if spec["etl_input"]:
        return spec["etl_input"]

    # The one-year and eight-year runs take complementary halves of data/raw/.
    raw = PROJECT_ROOT / "data" / "raw"
    keys = sorted(
        m.group(1)
        for m in (re.match(r"nvd_cves_(.*)\.json$", p.name) for p in raw.glob("nvd_cves_*.json"))
        if m
    )
    if run == "one-year":
        chosen = [k for k in keys if k in ONE_YEAR_CHUNKS]
    else:
        chosen = [k for k in keys if k not in ONE_YEAR_CHUNKS]
    if not chosen:
        raise SystemExit(f"no raw chunks found for {run}")
    return "data/raw/nvd_cves_{%s}.json" % ",".join(chosen)


def run_cmd(args: list, label: str) -> tuple:
    """Run a subprocess, returning (returncode, stdout, stderr, started, ended)."""
    started = utc_now()
    clock = time.perf_counter()
    proc = subprocess.run(
        args, cwd=str(PROJECT_ROOT), capture_output=True, text=True, errors="replace"
    )
    duration = time.perf_counter() - clock
    ended = utc_now()
    print(f"  {label}: rc={proc.returncode} in {duration:.1f}s", flush=True)
    return proc, duration, started, ended


# One stage entry for the run log, with throughput derived from records and duration.
def stage(name, started, ended, duration, records, extra=None, note=None, measured=True):
    entry = {
        "stage": name,
        "measured": measured,
        "start": iso(started) if started else None,
        "end": iso(ended) if ended else None,
        "duration_seconds": round(duration, 1) if duration is not None else None,
        "records": records,
        "throughput_per_second": (
            round(records / duration, 1) if records and duration and duration > 0 else None
        ),
    }
    if note:
        entry["note"] = note
    if extra:
        entry.update(extra)
    return entry


# Last JSON object emitted by a structured logger carrying all of `keys`.
def parse_log_summary(text: str, keys: tuple):
    found = None
    for line in text.splitlines():
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if all(k in obj for k in keys):
            found = obj
    return found


# Machine, version and input facts recorded with every run, so two runs can be
# compared only when they were measured under the same conditions.
def collect_environment(run: str, etl_input: str) -> dict:
    def first_line(args):
        try:
            out = subprocess.run(args, capture_output=True, text=True, errors="replace")
            return (out.stdout + out.stderr).strip().splitlines()[0]
        except Exception:
            return "unavailable"

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(PROJECT_ROOT),
            capture_output=True, text=True,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=str(PROJECT_ROOT),
            capture_output=True, text=True,
        ).stdout.strip())
    except Exception:
        commit, dirty = "unavailable", None

    try:
        import pyspark
        spark_version = pyspark.__version__
    except Exception:
        spark_version = "unavailable"

    total_ram = None
    try:
        out = subprocess.run(
            ["wmic", "ComputerSystem", "get", "TotalPhysicalMemory"],
            capture_output=True, text=True,
        ).stdout
        digits = [int(t) for t in out.split() if t.isdigit()]
        if digits:
            total_ram = round(digits[0] / 1024**3, 1)
    except Exception:
        pass

    return {
        "run": run,
        "commit": commit,
        "working_tree_dirty": dirty,
        "etl_input": etl_input,
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "pyspark": spark_version,
        "java": first_line(["java", "-version"]),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "total_ram_gb": total_ram,
        "spark_config": {
            "master": "local[*]",
            "driver_memory": "8g",
            "executor_memory": "8g",
            "shuffle_partitions": 20,
        },
        "nvd_api_key_present": bool(os.environ.get("NVD_API_KEY")),
    }


# ---------------------------------------------------------------- stage 1
def stage_ingest(run: str) -> dict:
    spec = RUNS[run]
    if not spec["fetch"]:
        return stage(
            "ingest", None, None, None, None, measured=False,
            note="not fetched (slice): the three-day input is a published-date slice "
                 "cut from an existing raw chunk by scripts/extract_published_window.py, "
                 "so no fetch belongs to this run",
        )

    start_date, end_date = spec["window"]
    E2E_RAW_DIR.mkdir(parents=True, exist_ok=True)
    out_dir = E2E_RAW_DIR / run
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    # One chunk per call: ingest_nvd_batch honours --output only for a range that
    # fits in a single chunk, and writes into data/raw/ for anything longer.
    from src.ingestion.ingest_nvd_batch import MAX_RANGE_DAYS, _split_range

    start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    chunks = _split_range(start_dt, end_dt, MAX_RANGE_DAYS)

    print(f"  fetching {start_date}..{end_date} as {len(chunks)} chunk(s) "
          f"into {out_dir.relative_to(PROJECT_ROOT)}", flush=True)

    started = utc_now()
    clock = time.perf_counter()
    failures = []
    for index, (chunk_start, chunk_end) in enumerate(chunks, 1):
        cs = chunk_start.strftime("%Y-%m-%d")
        ce = chunk_end.strftime("%Y-%m-%d")
        target = out_dir / f"nvd_cves_{cs}_to_{ce}.json"
        chunk_proc, chunk_duration, _cs_started, _cs_ended = run_cmd(
            [
                sys.executable, "-m", "src.ingestion.ingest_nvd_batch",
                "--start-date", cs, "--end-date", ce,
                "--output", str(target),
            ],
            f"ingest chunk {index}/{len(chunks)} {cs}..{ce}",
        )
        if chunk_proc.returncode != 0:
            failures.append({"chunk": f"{cs}..{ce}",
                             "stderr_tail": chunk_proc.stderr[-1500:]})
            break
        # Guard against the flag being ignored despite the single-chunk call.
        if not target.exists():
            failures.append({"chunk": f"{cs}..{ce}",
                             "stderr_tail": "ingest wrote nothing to --output"})
            break

    duration = time.perf_counter() - clock
    ended = utc_now()

    class _Result:
        returncode = 1 if failures else 0
        stderr = json.dumps(failures) if failures else ""

    proc = _Result()
    print(f"  ingest total: {duration:.1f}s across {len(chunks)} chunk(s)", flush=True)

    records, files, total_bytes = None, [], 0
    for path in sorted(out_dir.glob("*.json")):
        files.append(path.name)
        total_bytes += path.stat().st_size
    if files:
        records = 0
        for path in sorted(out_dir.glob("*.json")):
            try:
                with open(path, encoding="utf-8") as fh:
                    records += len(json.load(fh).get("vulnerabilities") or [])
            except Exception:
                records = None
                break

    if proc.returncode != 0:
        return stage(
            "ingest", started, ended, duration, records,
            extra={"failed": True, "stderr_tail": proc.stderr[-2000:],
                   "files": files, "bytes": total_bytes},
            note="fetch failed; see stderr_tail",
        )

    return stage(
        "ingest", started, ended, duration, records,
        extra={"files": len(files), "bytes": total_bytes,
               "output_dir": str(out_dir.relative_to(PROJECT_ROOT))},
        note="timed on a fresh fetch into data/raw_e2e/; stages 2-5 read the frozen "
             "snapshot in data/raw/, so this record count reflects NVD backfill since "
             "the snapshot was taken and is not the analytical record count",
    )


# ---------------------------------------------------------------- stage 2
def stage_etl(run: str, etl_input: str, repeats: int) -> dict:
    spec = RUNS[run]
    output_dir = PROJECT_ROOT / spec["output_dir"]
    durations, starts, ends, report = [], [], [], None

    # Every repetition is timed, and the last quality report gives the record count.
    for i in range(1, repeats + 1):
        proc, duration, started, ended = run_cmd(
            [
                sys.executable, "-m", "src.transformation.batch_etl",
                "--input", etl_input, "--output-dir", str(output_dir),
            ],
            f"etl run {i}/{repeats}",
        )
        if proc.returncode != 0:
            return stage(
                "etl", started, ended, duration, None,
                extra={"failed": True, "stderr_tail": proc.stderr[-3000:]},
                note=f"ETL failed on repetition {i}",
            )
        durations.append(round(duration, 1))
        starts.append(started)
        ends.append(ended)
        qr = output_dir / "quality_report.json"
        if qr.exists():
            report = json.loads(qr.read_text(encoding="utf-8"))

    mean = statistics.mean(durations)
    extra = {
        "repeats": repeats,
        "durations_s": durations,
        "mean_seconds": round(mean, 1),
        "min_seconds": min(durations),
        "max_seconds": max(durations),
        "spread_seconds": round(max(durations) - min(durations), 1),
        "output_dir": spec["output_dir"],
    }
    if len(durations) > 1:
        extra["stdev_seconds"] = round(statistics.stdev(durations), 1)
    if report:
        extra["input_records"] = report.get("input_records")
        extra["output_records"] = report.get("output_records")
        extra["records_missing_cvss"] = report.get("records_missing_cvss")
        extra["records_missing_vendor"] = report.get("records_missing_vendor")

    records = (report or {}).get("output_records")
    entry = stage("etl", starts[0], ends[-1], mean, records, extra=extra)
    entry["duration_seconds"] = round(mean, 1)
    if repeats > 1:
        entry["note"] = f"mean of {repeats} repetitions; spread {extra['spread_seconds']} s"
    else:
        entry["note"] = "single measurement"
    return entry


# stages 3 and 4
def reset_mongo() -> str:
    """Empty cve_events so the replay and consume counts are per run."""
    try:
        from pymongo import MongoClient
        from src.utils.config import Config

        config = Config()
        client = MongoClient(config.mongodb_uri, serverSelectionTimeoutMS=5000)
        coll = client[config.mongodb_database][config.mongodb_collection]
        before = coll.count_documents({})
        coll.drop()
        client.close()
        return f"dropped collection, {before} documents removed"
    except Exception as exc:
        return f"could not reset MongoDB: {exc}"


def stage_replay(csv_path: Path, expected: int) -> dict:
    # Both flags are passed explicitly: the config defaults throttle the producer,
    # which would measure the sleep rather than the pipeline.
    proc, duration, started, ended = run_cmd(
        [
            sys.executable, "-m", "src.streaming.replay_cves",
            "--input", str(csv_path),
            "--max-events", str(expected),
            "--delay-seconds", "0",
        ],
        "replay",
    )
    summary = parse_log_summary(proc.stdout + proc.stderr, ("sent", "skipped")) or {}
    sent = summary.get("sent")
    if proc.returncode != 0:
        return stage(
            "replay", started, ended, duration, sent,
            extra={"failed": True, "stderr_tail": proc.stderr[-2000:]},
            note="replay failed; Kafka reachable?",
        )
    return stage(
        "replay", started, ended, duration, sent,
        extra={"skipped": summary.get("skipped"), "input_csv": str(csv_path.name),
               "max_events": expected, "delay_seconds": 0},
        note="single measurement",
    )


def stage_consume(expected: int, attempts: int = 5) -> dict:
    """Time the consumer, retrying a race in kafka-python-ng where the heartbeat
    thread closes a socket mid-select. The attempts used are recorded.
    """
    tried = 0
    for attempt in range(1, attempts + 1):
        tried = attempt
        proc, duration, started, ended = run_cmd(
            [
                sys.executable, "-m", "src.streaming.kafka_consumer_mongo",
                "--max-events", str(expected),
            ],
            f"consume attempt {attempt}/{attempts}",
        )
        blob = proc.stdout + proc.stderr
        raced = "Invalid file descriptor" in blob
        summary_ok = parse_log_summary(
            blob, ("inserted", "duplicates", "invalid", "failed")
        )
        if proc.returncode == 0 and not raced and summary_ok:
            break
        if attempt < attempts:
            print("    client race, retrying", flush=True)
            time.sleep(3)
    summary = parse_log_summary(
        proc.stdout + proc.stderr, ("inserted", "duplicates", "invalid", "failed")
    ) or {}
    inserted = summary.get("inserted")
    if proc.returncode != 0:
        return stage(
            "consume", started, ended, duration, inserted,
            extra={"failed": True, "stderr_tail": proc.stderr[-2000:]},
            note="consumer failed; Kafka and MongoDB reachable?",
        )
    return stage(
        "consume", started, ended, duration, inserted,
        extra={
            "duplicates": summary.get("duplicates"),
            "invalid": summary.get("invalid"),
            "failed_inserts": summary.get("failed"),
            "max_events": expected,
            "client_attempts": tried,
        },
        note=("single measurement" if tried == 1 else
              f"single measurement; {tried} attempts needed, the earlier ones lost "
              f"the kafka-python-ng heartbeat race"),
    )


# ---------------------------------------------------------------- stage 5
E2E_TABLE = "raw.cve_raw_e2e"


def stage_load(parquet_dir: Path) -> dict:
    """PUT and COPY INTO, timed separately from Snowflake's own query history."""
    from src.utils.config import Config
    from src.warehouse.load_to_snowflake import TABLE, _connect, load_parquet

    # Full reload, so a measurement run targets raw.cve_raw_e2e, never raw.cve_raw.
    if E2E_TABLE.lower() == TABLE.lower():
        raise SystemExit(
            f"refusing to run: the e2e load target resolves to {TABLE}, the table "
            "the report depends on. It must be a separate table."
        )

    config = Config()
    started = utc_now()
    clock = time.perf_counter()
    conn = _connect(config)
    try:
        rows = load_parquet(conn, str(parquet_dir), full_reload=True, table=E2E_TABLE)
        duration = time.perf_counter() - clock
        ended = utc_now()

        # Snowflake's own query history separates the PUT from the COPY INTO.
        per_statement = {}
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT query_type, ROUND(total_elapsed_time / 1000.0, 1) "
                "FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION()) "
                "WHERE query_type IN ('PUT_FILES', 'COPY') ORDER BY start_time"
            )
            for qtype, seconds in cursor.fetchall():
                # Snowflake returns Decimal for ROUND(), which json.dumps cannot take.
                per_statement[str(qtype).lower()] = (
                    float(seconds) if seconds is not None else None
                )
            cursor.close()
        except Exception as exc:
            per_statement = {"unavailable": str(exc)}
    finally:
        conn.close()

    print(f"  load: {rows} rows in {duration:.1f}s", flush=True)
    return stage(
        "load", started, ended, duration, rows,
        extra={"per_statement_seconds": per_statement,
               "parquet_dir": str(parquet_dir.relative_to(PROJECT_ROOT)),
               "table": E2E_TABLE},
        note="single measurement; PUT and COPY INTO timed separately from "
             "Snowflake query history",
    )


# CLI flags: which window to run, how many ETL repetitions, and which stages to skip.
def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, choices=sorted(RUNS))
    parser.add_argument("--etl-repeats", type=int, default=1)
    parser.add_argument("--skip-ingest", action="store_true",
                        help="Skip the live fetch and record stage 1 as not measured.")
    parser.add_argument("--skip-streaming", action="store_true",
                        help="Skip replay and consume (Kafka or MongoDB unavailable).")
    parser.add_argument("--with-load", action="store_true",
                        help="Run stage 5. Writes to Snowflake: TRUNCATE then COPY INTO.")
    return parser.parse_args(argv)


# Entry point: run the five stages in order and write one JSON log for the run.
def main(argv=None) -> int:
    args = parse_args(argv)
    run = args.run
    spec = RUNS[run]
    etl_input = build_etl_input(run)
    output_dir = PROJECT_ROOT / spec["output_dir"]

    # Checked before any stage runs, so a misconfigured path cannot reach a write.
    assert_not_protected(output_dir, E2E_RAW_DIR / run)

    LOG_DIR.mkdir(exist_ok=True)
    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    out_path = LOG_DIR / f"e2e_{run}_{stamp}.json"

    print(f"=== end-to-end run: {run} ===", flush=True)
    result = {
        "environment": collect_environment(run, etl_input),
        "window": {"start": spec["window"][0], "end": spec["window"][1]},
        "started": iso(utc_now()),
        "stages": [],
    }

    # 1 ingest
    print("[1/5] ingest", flush=True)
    if args.skip_ingest and spec["fetch"]:
        result["stages"].append(stage(
            "ingest", None, None, None, None, measured=False,
            note="skipped with --skip-ingest; not measured for this run",
        ))
    else:
        result["stages"].append(stage_ingest(run))

    # 2 etl
    print("[2/5] etl", flush=True)
    etl = stage_etl(run, etl_input, max(1, args.etl_repeats))
    result["stages"].append(etl)
    if etl.get("failed"):
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"ETL failed; wrote {out_path}", file=sys.stderr)
        return 1

    csv_path = PROJECT_ROOT / spec["output_dir"] / "cves_cleaned.csv"
    parquet_dir = PROJECT_ROOT / spec["output_dir"] / "cves_cleaned.parquet"

    # 3 replay and 4 consume
    if args.skip_streaming:
        for name in ("replay", "consume"):
            result["stages"].append(stage(
                name, None, None, None, None, measured=False,
                note="skipped with --skip-streaming; Kafka or MongoDB unavailable",
            ))
    else:
        print("[3/5] replay", flush=True)
        result["mongo_reset"] = reset_mongo()
        print(f"  mongo: {result['mongo_reset']}", flush=True)
        expected_events = int(etl.get("output_records") or 0)
        result["stages"].append(stage_replay(csv_path, expected_events))
        published = result["stages"][-1].get("records") or expected_events
        print("[4/5] consume", flush=True)
        result["stages"].append(stage_consume(int(published)))

    # 5 load
    if args.with_load:
        print("[5/5] load", flush=True)
        try:
            result["stages"].append(stage_load(parquet_dir))
        except Exception as exc:
            result["stages"].append(stage(
                "load", None, None, None, None, measured=False,
                extra={"failed": True, "error": str(exc)},
                note="Snowflake load raised before completing",
            ))
    else:
        result["stages"].append(stage(
            "load", None, None, None, None, measured=False,
            note="not run: stage 5 requires --with-load because it TRUNCATEs "
                 "RAW.CVE_RAW and replaces whatever the warehouse holds",
        ))

    result["ended"] = iso(utc_now())
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(f"\n=== {run} summary ===", flush=True)
    for entry in result["stages"]:
        if not entry["measured"]:
            print(f"  {entry['stage']:<8} not measured ({entry.get('note','')[:60]})", flush=True)
            continue
        tp = entry["throughput_per_second"]
        print(
            f"  {entry['stage']:<8} {entry['duration_seconds']:>8.1f}s  "
            f"{str(entry['records']):>10} rec  "
            f"{(str(tp) + '/s') if tp else '-':>12}",
            flush=True,
        )
    print(f"\nwrote {out_path.relative_to(PROJECT_ROOT)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
