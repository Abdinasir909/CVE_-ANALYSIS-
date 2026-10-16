# Tests for _resolve_affected and the CVSS version preference order in batch_etl.

import json

import pytest

from src.transformation.batch_etl import (
    _ensure_hadoop_home,
    _matches_glob,
    _resolve_affected,
    transform,
)

CPE = "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*"


# A populated affected structure resolves into the six-tuple with source "affected".
def test_resolve_affected_from_affected():
    affected = [{"source": "s", "affectedData": [{"vendor": "ceph", "product": "ceph"}]}]
    assert _resolve_affected(json.dumps(affected), None) == ("ceph", "ceph", "", "", "", "affected")


# Empty affected falls back to the configurations CPE with source "cpe_fallback".
def test_resolve_affected_cpe_fallback():
    configs = [{"nodes": [{"cpeMatch": [{"criteria": CPE}]}]}]
    result = _resolve_affected(None, json.dumps(configs))
    assert result[:3] == ("microsoft", "word", CPE)
    assert result[5] == "cpe_fallback"


# A CVE record shaped like the NVD API 2.0 response, carrying only the metric
# versions in `versions`. Scores differ per version so the winner is identifiable.
_SCORES = {
    "cvssMetricV40": (9.1, "CRITICAL", "4.0"),
    "cvssMetricV31": (7.5, "HIGH", "3.1"),
    "cvssMetricV30": (5.5, "MEDIUM", "3.0"),
    "cvssMetricV2": (3.3, "LOW", "2.0"),
}


def _metric_entry(key: str) -> dict:
    score, severity, version = _SCORES[key]
    data = {
        "version": version,
        "baseScore": score,
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
    }
    # v2.0 carries baseSeverity on the metric, not inside cvssData.
    if key == "cvssMetricV2":
        return {"cvssData": data, "baseSeverity": severity}
    data["baseSeverity"] = severity
    data["privilegesRequired"] = "NONE"
    data["userInteraction"] = "NONE"
    return {"cvssData": data}


def _record(cve_id: str, versions: list) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-01-15T10:00:00.000",
            "lastModified": "2026-01-16T10:00:00.000",
            "vulnStatus": "Analyzed",
            "sourceIdentifier": "cve@mitre.org",
            "descriptions": [{"lang": "en", "value": "test record"}],
            "metrics": {key: [_metric_entry(key)] for key in versions},
            "weaknesses": [{"description": [{"value": "CWE-79"}]}],
            "affected": [{"source": "s", "affectedData": [{"vendor": "acme", "product": "widget"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": CPE}]}]}],
        }
    }


@pytest.fixture(scope="module")
def spark():
    from pyspark.sql import SparkSession

    _ensure_hadoop_home()
    session = (
        SparkSession.builder.appName("CveAnalysisPreferenceOrderTest")
        .master("local[1]")
        .config("spark.sql.shuffle.partitions", "1")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    yield session
    session.stop()


# transform() must resolve CVSS as v3.1 -> v3.0 -> v2.0 -> v4.0, with v4.0 last
# because it is a different scale from v3.1.
@pytest.mark.parametrize(
    "cve_id,present,expected_version",
    [
        ("CVE-2026-0001", ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"], "3.1"),
        ("CVE-2026-0002", ["cvssMetricV40", "cvssMetricV30", "cvssMetricV2"], "3.0"),
        ("CVE-2026-0003", ["cvssMetricV40", "cvssMetricV2"], "2.0"),
        # Only v4.0 present, so it is taken rather than leaving the record unscored.
        ("CVE-2026-0004", ["cvssMetricV40"], "4.0"),
        ("CVE-2026-0005", [], None),
    ],
)
def test_cvss_preference_order(spark, tmp_path_factory, cve_id, present, expected_version):
    records = [
        _record("CVE-2026-0001", ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]),
        _record("CVE-2026-0002", ["cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]),
        _record("CVE-2026-0003", ["cvssMetricV40", "cvssMetricV2"]),
        _record("CVE-2026-0004", ["cvssMetricV40"]),
        _record("CVE-2026-0005", []),
    ]
    path = tmp_path_factory.mktemp("nvd") / "cves.json"
    path.write_text(json.dumps({"vulnerabilities": records}), encoding="utf-8")

    rows = {r["cve_id"]: r for r in transform(spark, str(path)).collect()}
    row = rows[cve_id]

    assert row["cvss_version"] == expected_version
    if expected_version is None:
        assert row["cvss_score"] is None
        assert row["severity"] is None
    else:
        score, severity, _ = next(v for v in _SCORES.values() if v[2] == expected_version)
        assert row["cvss_score"] == score
        assert row["severity"] == severity


# Brace globs carry no wildcard character, so they must be matched explicitly or
# transform() rejects the path before Spark reads it.
@pytest.mark.parametrize(
    "path,is_glob",
    [
        ("data/raw/*.json", True),
        ("data/raw/nvd_cves_2026-0?-01.json", True),
        ("data/raw/nvd_cves_[0-9].json", True),
        ("data/raw/nvd_cves_{2025-09-22_to_2025-12-21,2025-12-22_to_2026-03-21}.json", True),
        ("data/raw/nvd_cves_2026-08-11_to_2026-09-21.json", False),
        ("data/processed", False),
    ],
)
def test_matches_glob(path, is_glob):
    assert _matches_glob(path) is is_glob
