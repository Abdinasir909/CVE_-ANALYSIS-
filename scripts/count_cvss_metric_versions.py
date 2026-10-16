# Count which CVSS metric versions the raw NVD JSON carries, per published-date window.
# Reads the raw layer directly, so the count is independent of what the ETL reads.

from __future__ import annotations

import argparse
import glob
import json
import sys

import ijson

METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# Versions the ETL actually reads (src/transformation/batch_etl.py).
ETL_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


# True when the metric list exists and its first entry carries a base score.
def _has_score(metrics: dict, key: str) -> bool:
    entries = metrics.get(key) or []
    if not entries:
        return False
    return (entries[0].get("cvssData") or {}).get("baseScore") is not None


def scan(paths: list[str], start: str, end: str) -> dict:
    # cve_id -> (last_modified, flags); newest lastModified wins, as in the ETL.
    seen: dict[str, tuple[str, tuple[bool, ...]]] = {}
    for path in paths:
        with open(path, "rb") as handle:
            for cve in ijson.items(handle, "vulnerabilities.item.cve", use_float=True):
                published = cve.get("published") or ""
                published_date = published[:10]
                if not (start <= published_date <= end):
                    continue
                metrics = cve.get("metrics") or {}
                flags = tuple(_has_score(metrics, key) for key in METRIC_KEYS)
                cve_id = cve.get("id")
                last_modified = cve.get("lastModified") or ""
                previous = seen.get(cve_id)
                if previous is None or last_modified > previous[0]:
                    seen[cve_id] = (last_modified, flags)

    # Positions in the flags tuple, so the counts below read the right versions.
    total = len(seen)
    etl_offsets = [METRIC_KEYS.index(key) for key in ETL_KEYS]
    v40_offset = METRIC_KEYS.index("cvssMetricV40")

    # How many records the ETL would score as missing, and how many of those
    # carry a v4.0 score it never looks at.
    missing_for_etl = 0
    missing_but_has_v40 = 0
    has_v40_any = 0
    for _last_modified, flags in seen.values():
        if flags[v40_offset]:
            has_v40_any += 1
        if not any(flags[i] for i in etl_offsets):
            missing_for_etl += 1
            if flags[v40_offset]:
                missing_but_has_v40 += 1

    def share(count: int) -> float:
        return round(100.0 * count / total, 2) if total else 0.0

    return {
        "window": f"{start}..{end}",
        "files": len(paths),
        "records": total,
        "missing_cvss_for_etl": missing_for_etl,
        "missing_cvss_for_etl_pct": share(missing_for_etl),
        "missing_but_has_v40": missing_but_has_v40,
        "missing_but_has_v40_pct": share(missing_but_has_v40),
        "has_v40_any": has_v40_any,
        "has_v40_any_pct": share(has_v40_any),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, action="append", help="Raw JSON path or glob (repeatable).")
    parser.add_argument("--from", dest="start", required=True, help="Window start, YYYY-MM-DD inclusive.")
    parser.add_argument("--to", dest="end", required=True, help="Window end, YYYY-MM-DD inclusive.")
    args = parser.parse_args(argv)

    # Expand every --input pattern in order, and stop if nothing matched.
    paths: list[str] = []
    for pattern in args.input:
        paths.extend(sorted(glob.glob(pattern)))
    if not paths:
        print("no input files matched", file=sys.stderr)
        return 2

    print(json.dumps(scan(paths, args.start, args.end), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
