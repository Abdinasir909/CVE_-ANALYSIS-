# Tests for quality_checks without kafka.

from src.transformation.quality_checks import (
    SEVERITY_RANK_MAP,
    classify_source_type,
    find_duplicate_cve_ids,
    is_valid_cve_id,
    is_valid_cvss_score,
    severity_rank,
    source_type_distribution,
    source_type_distribution_counts,
    vendor_resolution,
    vendor_resolution_counts,
)


# Rank map and severity_rank map names to ranks, case-insensitively.
def test_severity_rank():
    assert SEVERITY_RANK_MAP == {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    assert severity_rank("CRITICAL") == 4
    assert severity_rank("critical") == 4
    assert severity_rank(" High ") == 3
    assert severity_rank(None) is None
    assert severity_rank("") is None
    assert severity_rank("UNKNOWN") is None


# Valid and malformed CVE ids.
def test_is_valid_cve_id():
    assert is_valid_cve_id("CVE-2026-12345")
    assert is_valid_cve_id("CVE-1999-1")
    assert not is_valid_cve_id("CVE-202-123")       # wrong year width
    assert not is_valid_cve_id("CVE-2026-ABC")      # non-numeric id
    assert not is_valid_cve_id("cve-2026-12345")    # lowercase
    assert not is_valid_cve_id("CVE-2026")          # missing id number
    assert not is_valid_cve_id("CVE-2026--1")       # negative number
    assert not is_valid_cve_id(None)


# CVSS score: boundaries, out of range, null, non-numeric, bool rejected.
def test_is_valid_cvss_score():
    assert is_valid_cvss_score(0.0)
    assert is_valid_cvss_score(10.0)
    assert is_valid_cvss_score(5.5)
    assert not is_valid_cvss_score(-0.1)
    assert not is_valid_cvss_score(10.1)
    assert is_valid_cvss_score(None)
    assert is_valid_cvss_score("7.5")  # numeric string
    assert not is_valid_cvss_score("abc")
    assert not is_valid_cvss_score(True)  # bool is a subclass of int


# Duplicate cve_ids are returned, none otherwise.
def test_find_duplicate_cve_ids():
    records = [
        {"cve_id": "CVE-2026-1"},
        {"cve_id": "CVE-2026-2"},
        {"cve_id": "CVE-2026-1"},
    ]
    assert find_duplicate_cve_ids(records) == ["CVE-2026-1"]
    assert find_duplicate_cve_ids([{"cve_id": "CVE-2026-1"}, {"cve_id": "CVE-2026-2"}]) == []


# sourceIdentifier falls into one of four buckets.
def test_classify_source_type():
    assert classify_source_type("secure@microsoft.com") == "vendor_direct"
    assert classify_source_type("cna@vuldb.com") == "third_party_db"
    assert classify_source_type("ics-cert@hq.dhs.gov") == "cert_national"
    assert classify_source_type("cve@mitre.org") == "other"
    assert classify_source_type(None) == "other"


# The ETL passes pre-aggregated (value, count) pairs, so both variants must agree.
def test_vendor_resolution_counts_matches_row_by_row():
    rows = ["affected"] * 5 + ["cpe_fallback"] * 3 + [None, "", "unresolved"]
    pairs = [("affected", 5), ("cpe_fallback", 3), (None, 1), ("", 1), ("unresolved", 1)]

    assert vendor_resolution_counts(pairs) == vendor_resolution(rows)
    assert vendor_resolution_counts(pairs) == {
        "resolved_via_affected": 5,
        "resolved_via_cpe_fallback": 3,
        "still_unresolved": 3,
    }


def test_source_type_distribution_counts_matches_row_by_row():
    rows = ["vendor_direct"] * 4 + ["cert_national"] * 2 + ["something_else", None]
    pairs = [("vendor_direct", 4), ("cert_national", 2), ("something_else", 1), (None, 1)]

    assert source_type_distribution_counts(pairs) == source_type_distribution(rows)
    # An unrecognised value and a null both fall into "other", not into a new key.
    assert source_type_distribution_counts(pairs) == {
        "vendor_direct": 4,
        "third_party_db": 0,
        "cert_national": 2,
        "other": 2,
    }


# Whitespace is trimmed before bucketing, on the pre-aggregated path too.
def test_counts_variants_trim_whitespace():
    assert vendor_resolution_counts([(" affected ", 2)])["resolved_via_affected"] == 2
    assert source_type_distribution_counts([(" vendor_direct ", 2)])["vendor_direct"] == 2
