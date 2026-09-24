# Fetch a date range of CVEs from the NVD API 2.0 and save the raw JSON.

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from src.utils.config import Config
from src.utils.logging_config import get_logger, setup_logging

logger = get_logger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 2000  # NVD maximum for resultsPerPage
_HTTP_TIMEOUT_SECONDS = 30

# Statuses treated as transient -> retried with exponential backoff.
_TRANSIENT_STATUS = {429, 500, 502, 503, 504}


# Raised for a non-200 NVD response after retries are exhausted.
class NvdApiError(RuntimeError):

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


# Retry only on timeouts, connection errors and transient HTTP statuses.
def _should_retry(exc: BaseException) -> bool:
    if isinstance(exc, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
        return True
    if isinstance(exc, NvdApiError):
        return exc.status_code in _TRANSIENT_STATUS
    return False


# GET one page of CVEs, retries transient failures and returns parsed JSON.
@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    retry=retry_if_exception(_should_retry),
    reraise=True,
)
def _fetch_page(api_url: str, params: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    response = requests.get(api_url, params=params, headers=headers, timeout=_HTTP_TIMEOUT_SECONDS)
    if response.status_code != 200:
        raise NvdApiError(response.status_code, f"NVD API returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError as exc:
        raise NvdApiError(response.status_code, "NVD returned non-JSON payload") from exc


# CLI flags for date range, page size and output path.
def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Fetch CVEs from the NVD CVE API 2.0.")
    parser.add_argument("--start-date", help="Inclusive start date (YYYY-MM-DD, UTC).")
    parser.add_argument("--end-date", help="Inclusive end date (YYYY-MM-DD, UTC).")
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=None,
        help="Page size (1..2000). Default: NVD_RESULTS_PER_PAGE env or config.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON path. Default: data/raw/nvd_cves_<start>_to_<end>.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned request(s) without contacting the NVD API.",
    )
    return parser.parse_args(argv)


# Parse a YYYY-MM-DD string as UTC.
def _parse_date(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SystemExit(f"Invalid date {value!r}: expected YYYY-MM-DD") from exc


# Resolve the (start, end) date window, both are UTC date strings YYYY-MM-DD.
def _resolve_dates(start_date: Optional[str], end_date: Optional[str], default_days_back: int):
    if start_date and end_date:
        start = _parse_date(start_date)
        end = _parse_date(end_date)
    elif start_date or end_date:
        raise SystemExit("Provide both --start-date and --end-date, or neither.")
    else:
        end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=default_days_back - 1)
    if start > end:
        raise SystemExit(f"--start-date ({start.date()}) must be <= --end-date ({end.date()})")
    return start, end


# Include the apiKey header only when we have one.
def _build_headers(api_key: str) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


# Query params for the NVD API date range.
def _build_params(start: datetime, end: datetime, results_per_page: int) -> Dict[str, Any]:
    return {
        "pubStartDate": f"{start.date()}T00:00:00.000",
        "pubEndDate": f"{end.date()}T23:59:59.999",
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }


# Merge paginated NVD responses into one response-shaped JSON object.
def _merge_pages(pages: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not pages:
        return {}
    first = pages[0]
    vulnerabilities: List[Any] = []
    for page in pages:
        vulnerabilities.extend(page.get("vulnerabilities", []) or [])
    merged = {
        "resultsPerPage": first.get("resultsPerPage"),
        "startIndex": 0,
        "totalResults": first.get("totalResults"),
        "format": first.get("format", "NVD_CVE"),
        "version": first.get("version", "2.0"),
        "timestamp": first.get("timestamp"),
        "vulnerabilities": vulnerabilities,
    }
    return merged


# CLI entrypoint: fetch all pages and write one merged JSON file.
def main(argv=None) -> int:
    args = parse_args(argv)
    config = Config()
    setup_logging(config.log_level)

    api_url = config.nvd_api_url or API_URL

    start, end = _resolve_dates(args.start_date, args.end_date, config.nvd_default_days_back)

    results_per_page = args.results_per_page or config.nvd_results_per_page
    if not 1 <= results_per_page <= 2000:
        raise SystemExit(f"--results-per-page must be 1..2000, got {results_per_page}")

    headers = _build_headers(config.nvd_api_key)
    base_params = _build_params(start, end, results_per_page)

    start_str = start.strftime("%Y-%m-%d")
    end_str = end.strftime("%Y-%m-%d")

    output_path = Path(args.output) if args.output else config.raw_dir() / f"nvd_cves_{start_str}_to_{end_str}.json"

    if args.dry_run:
        print(f"NVD API URL: {api_url}")
        print(f"Params: {json.dumps(base_params, indent=2)}")
        print(f"Headers: {list(headers.keys())} (apiKey {'present' if headers.get('apiKey') else 'absent'})")
        print(f"Output would be: {output_path}")
        return 0

    # Delay between requests: >=6s without a key, ca 0.6s with a key.
    delay = 0.6 if config.nvd_api_key else max(6.0, config.nvd_request_delay_seconds)

    pages: List[Dict[str, Any]] = []
    start_index = 0
    total_results: Optional[int] = None

    try:
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
    except (NvdApiError, requests.RequestException) as exc:
        logger.error("NVD ingestion failed", extra={"error": str(exc)})
        return 2

    merged = _merge_pages(pages)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")

    logger.info(
        "ingestion complete",
        extra={
            "total_records": len(merged.get("vulnerabilities", [])),
            "output_path": str(output_path),
            "start": start_str,
            "end": end_str,
        },
    )
    print(f"Saved {len(merged.get('vulnerabilities', []))} CVE records to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
