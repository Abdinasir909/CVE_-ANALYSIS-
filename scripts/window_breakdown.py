"""Break the cleaned CSV into twelve-month publication windows.

Counts distinct cve_id per window, with the missing-CVSS and missing-vendor counts
inside each. Windows are counted backwards from --end.

Usage:
  python scripts/window_breakdown.py --input data/processed_8y/cves_cleaned.csv \
      --end 2026-09-21 --windows 8
"""

import argparse
import csv
import json
from datetime import date, timedelta
from pathlib import Path


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--end", required=True, help="Last day of the newest window, YYYY-MM-DD.")
    parser.add_argument("--windows", type=int, default=8)
    return parser.parse_args(argv)


# Inclusive twelve-month window boundaries, oldest first.
def build_windows(end: date, count: int):
    bounds = []
    stop = end
    for _ in range(count):
        start = stop.replace(year=stop.year - 1) + timedelta(days=1)
        bounds.append((start, stop))
        stop = start - timedelta(days=1)
    return list(reversed(bounds))


def main(argv=None) -> int:
    args = parse_args(argv)
    windows = build_windows(date.fromisoformat(args.end), args.windows)
    # Per-window accumulators. "seen" holds distinct cve_id values.
    seen = {w: set() for w in windows}
    missing_cvss = {w: 0 for w in windows}
    missing_vendor = {w: 0 for w in windows}
    outside = 0

    # One pass over the cleaned CSV, bucketing each row into its window.
    with Path(args.input).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            published = row["published_date"][:10]
            if not published:
                outside += 1
                continue
            day = date.fromisoformat(published)
            window = next((w for w in windows if w[0] <= day <= w[1]), None)
            if window is None:
                outside += 1
                continue
            # Count each cve_id once per window.
            cve_id = row["cve_id"]
            if cve_id in seen[window]:
                continue
            seen[window].add(cve_id)
            if not row["cvss_score"].strip():
                missing_cvss[window] += 1
            if not row["vendor"].strip():
                missing_vendor[window] += 1

    # JSON report, one entry per window, oldest first.
    report = {
        "input": args.input,
        "records_outside_windows": outside,
        "windows": [
            {
                "window": f"{start.isoformat()}..{stop.isoformat()}",
                "records": len(seen[(start, stop)]),
                "missing_cvss": missing_cvss[(start, stop)],
                "missing_vendor": missing_vendor[(start, stop)],
                "missing_cvss_pct": round(100 * missing_cvss[(start, stop)] / len(seen[(start, stop)]), 2),
                "missing_vendor_pct": round(100 * missing_vendor[(start, stop)] / len(seen[(start, stop)]), 2),
            }
            for start, stop in windows
        ],
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
