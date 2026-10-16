"""Pandas implementation of the batch ETL, for a like-for-like comparison.

Does the same work as src/transformation/batch_etl.py in the same order, reusing the
same pure functions, so what differs is the engine rather than the logic.

Usage:
  python scripts/pandas_baseline.py --input data/raw/nvd_cves_*.json \
      --output logs/pandas_baseline_one_year.json
"""

from __future__ import annotations

import argparse
import glob
import json
import subprocess
import sys
import time
import tempfile
import tracemalloc
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402

from src.transformation.batch_etl import FINAL_COLS, _resolve_affected  # noqa: E402
from src.transformation.quality_checks import (  # noqa: E402
    classify_source_type,
    is_valid_cve_id,
    severity_rank,
)

# Same order the Spark job coalesces in: 4.0 is the last fallback, not the first.
_VERSION_KEYS = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2", "cvssMetricV40"]


# First non-null value across the metric blocks, in preference order.
def _pick(metrics: dict, field: str, metric_level: bool = False):
    for key in _VERSION_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0]
        # v2 carries baseSeverity on the metric, not inside cvssData, as in the Spark job.
        source = entry if metric_level else (entry.get("cvssData") or {})
        value = source.get(field)
        if value is not None:
            return value
    return None


def _english_description(cve: dict):
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value")
    return None


# Every CWE id on the record, deduplicated, as one comma-separated string.
def _cwe_ids(cve: dict) -> str:
    seen, out = set(), []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    return ",".join(out)


# One cleaned row per CVE, in the same shape and column order as the Spark job.
def _row(cve: dict, today: date) -> dict:
    metrics = cve.get("metrics") or {}
    resolved = _resolve_affected(
        json.dumps(cve.get("affected")) if cve.get("affected") is not None else None,
        json.dumps(cve.get("configurations")) if cve.get("configurations") is not None else None,
    )
    published = cve.get("published")
    published_date = None
    if published:
        published_date = datetime.fromisoformat(published.replace("Z", "")).date()

    severity = _pick(metrics, "baseSeverity") or _pick(metrics, "baseSeverity", metric_level=True)
    source_identifier = cve.get("sourceIdentifier")

    return {
        "cve_id": cve.get("id"),
        "published": published,
        "published_date": published_date,
        "year": published_date.year if published_date else None,
        "month": published_date.month if published_date else None,
        "quarter": (published_date.month - 1) // 3 + 1 if published_date else None,
        "days_since_published": (today - published_date).days if published_date else None,
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description_en": _english_description(cve),
        "cvss_version": _pick(metrics, "version"),
        "cvss_score": _pick(metrics, "baseScore"),
        "severity": severity,
        "severity_rank": severity_rank(severity),
        "attack_vector": _pick(metrics, "attackVector"),
        "attack_complexity": _pick(metrics, "attackComplexity"),
        "privileges_required": _pick(metrics, "privilegesRequired"),
        "user_interaction": _pick(metrics, "userInteraction"),
        "cwe_ids": _cwe_ids(cve),
        "vendor": resolved[0],
        "product": resolved[1],
        "cpe_uri": resolved[2],
        "source_identifier": source_identifier,
        "cve_source_type": classify_source_type(source_identifier),
        "affected_status": resolved[3],
        "affected_version_range": resolved[4],
    }


# Free physical RAM at the start: these timings are sensitive to co-resident load.
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
    parser.add_argument("--input", required=True, action="append",
                        help="Raw JSON path or glob (repeatable).")
    parser.add_argument("--output", required=True, help="Where to write the result JSON.")
    return parser.parse_args(argv)


# Entry point: parse every input file with Pandas, time it, and write the summary.
def main(argv=None) -> int:
    args = parse_args(argv)

    # Expand every --input pattern and stop if nothing matched.
    paths = sorted({p for pattern in args.input for p in glob.glob(pattern)})
    if not paths:
        print(f"No input files matched: {args.input}", file=sys.stderr)
        return 2
    input_bytes = sum(Path(p).stat().st_size for p in paths)
    print(f"{len(paths)} file(s), {input_bytes / 1e6:.1f} MB", flush=True)

    free_before = free_ram_gb()
    print(f"free RAM before run: {free_before} GB", flush=True)
    # Peak Python heap is measured alongside wall time, because the memory ceiling
    # is what the comparison is testing.
    tracemalloc.start()
    started = time.perf_counter()
    failure = None
    result = {}

    try:
        today = date.today()
        # json.load reads each file whole, which is the single-machine approach
        # being measured.
        rows = []
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                payload = json.load(fh)
            for vuln in payload.get("vulnerabilities") or []:
                cve = vuln.get("cve") or {}
                rows.append(_row(cve, today))

        df = pd.DataFrame(rows, columns=FINAL_COLS)
        input_records = len(df)

        # Same identifier validation as the ETL, so both engines drop the same rows.
        valid = df[df["cve_id"].map(lambda v: bool(v) and is_valid_cve_id(v))]
        dropped_invalid = input_records - len(valid)

        # Newest last_modified wins, same rule as the Spark window function.
        deduped = (
            valid.sort_values("last_modified", ascending=False, na_position="last")
            .drop_duplicates(subset="cve_id", keep="first")
            .reset_index(drop=True)
        )

        # Null and whitespace-only both count as missing, matching the ETL.
        def _blank(series):
            return series.isna() | (series.astype("string").str.strip() == "")

        # The same quality counts the ETL writes, so the two outputs compare directly.
        result = {
            "input_records": input_records,
            "output_records": len(deduped),
            "duplicate_records_removed": len(valid) - len(deduped),
            "records_dropped_invalid_cve_id": dropped_invalid,
            "records_missing_cvss": int(deduped["cvss_score"].isna().sum()),
            "records_missing_description": int(_blank(deduped["description_en"]).sum()),
            "records_missing_vendor": int(_blank(deduped["vendor"]).sum()),
            "severity_distribution": {
                k: int(v) for k, v in
                deduped["severity"].fillna("null").value_counts().items()
            },
        }

        # Write both outputs, as the Spark job does, since writing is part of the work.
        with tempfile.TemporaryDirectory(prefix="pandas_baseline_") as tmp:
            deduped.to_csv(Path(tmp) / "cves_cleaned.csv", index=False)
            deduped.to_parquet(Path(tmp) / "cves_cleaned.parquet", index=False)

    except MemoryError as exc:
        # A MemoryError here is the result, not an error to hide.
        failure = {"type": "MemoryError", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        failure = {"type": type(exc).__name__, "message": str(exc)}

    # Timed and measured even when the run failed, so a MemoryError still reports
    # what it cost.
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    summary = {
        "engine": "pandas",
        "pandas_version": pd.__version__,
        "input_files": len(paths),
        "input_bytes": input_bytes,
        "wall_seconds": round(elapsed, 1),
        "free_ram_gb_before": free_before,
        "peak_python_heap_mb": round(peak / 1e6, 1),
        "failed": failure is not None,
    }
    if failure:
        summary["failure"] = failure
    else:
        summary.update(result)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
