"""Time the batch ETL over several repetitions and report mean and spread.

Each repetition is a fresh subprocess, so every run pays its own Spark session
startup, which is what the pipeline does in normal use.

Usage:
  python scripts/repeat_etl_timing.py --input "data/raw_windows/three_day_*.json" \
      --label three-day --repeats 3 --output logs/etl_timing_three_day.json
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent



# Free physical RAM at the start of each repetition, because these timings are
# sensitive to co-resident load.
def free_ram_gb():
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
        return round(int(out) / 1024 / 1024, 2)
    except Exception:
        return None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="ETL input path or glob.")
    parser.add_argument("--label", required=True, help="Name for this run in the output.")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", required=True, help="Where to write the timing JSON.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    durations = []
    records = None

    free_before = []
    for i in range(1, args.repeats + 1):
        # A throwaway output directory per repetition: writing is part of what is
        # timed, but keeping the outputs would overwrite the canonical ones.
        with tempfile.TemporaryDirectory(prefix="etl_timing_") as tmp:
            free_before.append(free_ram_gb())
            # The timer brackets the whole subprocess, so Spark startup is included.
            started = time.perf_counter()
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.transformation.batch_etl",
                    "--input",
                    args.input,
                    "--output-dir",
                    tmp,
                ],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True,
            )
            elapsed = time.perf_counter() - started

            if proc.returncode != 0:
                print(f"run {i} FAILED (rc={proc.returncode})", flush=True)
                print(proc.stderr[-3000:], file=sys.stderr)
                return 1

            # Take the record count from the ETL's own report rather than recounting.
            report = Path(tmp) / "quality_report.json"
            if report.exists():
                records = json.loads(report.read_text(encoding="utf-8"))["output_records"]

        durations.append(round(elapsed, 1))
        print(f"run {i}: {elapsed:.1f}s (free RAM before: {free_before[-1]} GB)", flush=True)

    summary = {
        "label": args.label,
        "input": args.input,
        "spark_driver_memory": os.environ.get("SPARK_DRIVER_MEMORY", "<config default>"),
        "free_ram_gb_before_each_run": free_before,
        "records": records,
        "repeats": args.repeats,
        "durations_s": durations,
        "mean_s": round(statistics.mean(durations), 1),
        "min_s": min(durations),
        "max_s": max(durations),
        "spread_s": round(max(durations) - min(durations), 1),
    }
    if len(durations) > 1:
        summary["stdev_s"] = round(statistics.stdev(durations), 1)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
