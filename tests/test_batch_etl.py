# Tests for _resolve_affected from batch_etl, no Spark needed.

import json

from src.transformation.batch_etl import _resolve_affected

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


# Nothing to resolve yields empty fields with source "unresolved".
def test_resolve_affected_nothing():
    assert _resolve_affected(None, None) == ("", "", "", "", "", "unresolved")
