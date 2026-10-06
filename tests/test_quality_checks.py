# Tests for quality_checks without kafka.

from src.transformation.quality_checks import (
    SEVERITY_RANK_MAP,
    classify_source_type,
    find_duplicate_cve_ids,
    is_valid_cve_id,
    is_valid_cvss_score,
    severity_distribution,
    severity_rank,
    source_type_distribution,
    vendor_resolution,
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


# Severity distribution counts each bucket and sends missing values to "null".
def test_severity_distribution():
    records = [
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "CRITICAL"},
        {"severity": None},
        {"severity": "LOW"},
    ]
    dist = severity_distribution(records)
    assert dist["HIGH"] == 2
    assert dist["CRITICAL"] == 1
    assert dist["LOW"] == 1
    assert dist["null"] == 1


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


# Distribution counts each type and puts unknowns in "other".
def test_source_type_distribution():
    values = ["vendor_direct", "vendor_direct", "third_party_db", "cert_national", None]
    assert source_type_distribution(values) == {
        "vendor_direct": 2,
        "third_party_db": 1,
        "cert_national": 1,
        "other": 1,
    }


# Vendor resolution counts affected / cpe_fallback / unresolved.
def test_vendor_resolution():
    sources = ["affected", "affected", "cpe_fallback", "unresolved", None]
    assert vendor_resolution(sources) == {
        "resolved_via_affected": 2,
        "resolved_via_cpe_fallback": 1,
        "still_unresolved": 2,
    }
