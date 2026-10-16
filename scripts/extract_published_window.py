"""Cut a published-date window out of an existing raw NVD JSON chunk.

The output keeps the NVD CVE API 2.0 response shape, so the ETL reads it unchanged.

Usage:
  python scripts/extract_published_window.py --input data/raw/<chunk>.json \
      --start 2026-08-28 --end 2026-08-30 --output data/raw_windows/three_day.json
"""

import argparse
import json
from pathlib import Path


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--start", required=True, help="Inclusive published date, YYYY-MM-DD.")
    parser.add_argument("--end", required=True, help="Inclusive published date, YYYY-MM-DD.")
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    # Keep only the records whose published date falls inside the window.
    kept = [
        item
        for item in payload.get("vulnerabilities", [])
        if args.start <= str(item.get("cve", {}).get("published", ""))[:10] <= args.end
    ]
    # Rebuild the NVD response envelope so the ETL reads the slice unchanged.
    out = {
        "resultsPerPage": len(kept),
        "startIndex": 0,
        "totalResults": len(kept),
        "vulnerabilities": kept,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out), encoding="utf-8")
    print(json.dumps({"input": args.input, "output": str(out_path), "records": len(kept)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
