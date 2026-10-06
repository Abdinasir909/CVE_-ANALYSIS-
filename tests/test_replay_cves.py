# Tests for replay_cves helpers without kafka.

from src.streaming.replay_cves import _coerce_cvss, build_event_from_row
from src.transformation.batch_etl import FINAL_COLS
from src.transformation.quality_checks import validate_event_contract


# CSV gives numbers as strings, so they must coerce to float.
def test_coerce_cvss_valid():
    assert _coerce_cvss("9.8") == 9.8
    assert _coerce_cvss("0") == 0.0


# Null, blank, whitespace and non-numeric values coerce to None.
def test_coerce_cvss_invalid():
    assert _coerce_cvss(None) is None
    assert _coerce_cvss("") is None
    assert _coerce_cvss("   ") is None
    assert _coerce_cvss("N/A") is None
    assert _coerce_cvss("abc") is None


# BLOCKER regression: replay must read the ETL's cleaned column names (description_en/cpe_uri), not the contract names (description/raw_cpe_uri).
def test_build_event_from_row_maps_cleaned_columns():
    # Every column batch_etl.py writes, present (empty) so the row is a faithful
    # cves_cleaned.csv row.
    row = {col: "" for col in FINAL_COLS}
    row.update(
        {
            "cve_id": "CVE-2026-12345",
            "published": "2026-08-25T00:00:00.000",
            "last_modified": "2026-08-30T00:00:00.000",
            "cvss_score": "9.8",
            "severity": "CRITICAL",
            "vendor": "microsoft",
            "product": "word",
            "description_en": "A description from the cleaned layer.",
            "cpe_uri": "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*",
        }
    )
    event = build_event_from_row(row)
    assert event["description"] == "A description from the cleaned layer."
    assert event["raw_cpe_uri"] == "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*"
    # NVD naive timestamps are normalized to UTC offset so the contract passes.
    assert event["published"].endswith("+00:00")
    assert event["last_modified"].endswith("+00:00")
    valid, errors = validate_event_contract(event)
    assert valid, errors
