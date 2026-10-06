# Tests for the CVE event contract (build_event, validate_event_contract).

import uuid
from datetime import datetime, timedelta

from src.streaming.kafka_producer import build_event
from src.transformation.quality_checks import validate_event_contract


def _valid_event():
    return build_event(
        cve_id="CVE-2026-12345",
        published="2026-08-25T00:00:00.000",
        last_modified="2026-08-30T00:00:00.000",
        cvss_score=9.8,
        severity="CRITICAL",
        vendor="microsoft",
        product="word",
        description="A test description.",
        raw_cpe_uri="cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*",
    )


# A valid event passes, has the fixed enums, and each event gets a fresh uuid4.
def test_valid_event_contract():
    event = _valid_event()
    valid, errors = validate_event_contract(event)
    assert valid, errors

    assert event["event_type"] == "cve_published"
    assert event["source"] == "nvd_replay"
    assert event["cve_id"] == "CVE-2026-12345"
    assert _valid_event()["event_id"] != _valid_event()["event_id"]


# Missing required fields (event_id, description) make the event invalid.
def test_required_fields_invalid():
    event = _valid_event()
    del event["event_id"]
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("event_id" in e for e in errors)

    event = _valid_event()
    del event["description"]
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("description" in e for e in errors)


# Malformed cve_id and wrong event_type are rejected.
def test_invalid_cve_id_and_type():
    event = _valid_event()
    event["cve_id"] = "not-a-cve"
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("cve_id" in e for e in errors)

    event = _valid_event()
    event["event_type"] = "cve_updated"
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("event_type" in e for e in errors)


# Nullable fields (cvss/severity/vendor/product) may be null and still pass.
def test_nullable_fields_are_valid():
    event = _valid_event()
    event["cvss_score"] = None
    event["severity"] = None
    event["vendor"] = None
    event["product"] = None
    valid, errors = validate_event_contract(event)
    assert valid, errors


# Out-of-range cvss and invalid severity are rejected.
def test_invalid_cvss_and_severity():
    event = _valid_event()
    event["cvss_score"] = 12.0
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("cvss_score" in e for e in errors)

    event = _valid_event()
    event["severity"] = "MEGA"
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("severity" in e for e in errors)


# event_id must be a uuid4 and event_timestamp ISO-8601 UTC.
def test_event_id_and_timestamp():
    event = _valid_event()
    assert uuid.UUID(event["event_id"]).version == 4

    dt = datetime.fromisoformat(event["event_timestamp"])
    assert dt.tzinfo is not None
    assert dt.utcoffset() == timedelta(0)

    event["event_id"] = str(uuid.uuid1())  # valid UUID, wrong version
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("event_id" in e for e in errors)


# Naive timestamps are normalized to UTC by build_event, then rejected by the contract.
def test_naive_timestamps():
    event = _valid_event()
    assert event["published"] == "2026-08-25T00:00:00.000+00:00"

    event["published"] = "2026-08-25T00:00:00.000"  # naive, no offset
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("published" in e for e in errors)


# Null/blank description, non-dict, and missing keys are all rejected.
def test_contract_rejections():
    event = _valid_event()
    event["description"] = None
    valid, errors = validate_event_contract(event)
    assert not valid
    assert any("description" in e for e in errors)

    event = _valid_event()
    event["description"] = "   "
    valid, errors = validate_event_contract(event)
    assert not valid

    valid, errors = validate_event_contract("not a dict")
    assert not valid

    payload = {"event_id": str(uuid.uuid4())}
    valid, errors = validate_event_contract(payload)
    assert not valid
    assert any("cve_id" in e for e in errors)
