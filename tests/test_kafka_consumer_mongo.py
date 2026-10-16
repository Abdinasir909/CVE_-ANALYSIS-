# Tests for kafka_consumer_mongo: insert_event + ensure_unique_index + helpers.
# Exercises duplicate-detection / unique-index intent without MongoDB, via a fake collection.

import pytest
from pymongo.errors import DuplicateKeyError, PyMongoError

from src.streaming.kafka_consumer_mongo import (
    _redact_uri,
    _safe_json_deserializer,
    ensure_unique_index,
    insert_event,
)


class _FakeCollection:
    def __init__(self, raise_duplicate=False, raise_pymongo=False, raise_index_duplicate=False):
        self.inserted = []
        self.indexes = []
        self.raise_duplicate = raise_duplicate
        self.raise_pymongo = raise_pymongo
        self.raise_index_duplicate = raise_index_duplicate

    def insert_one(self, document):
        if self.raise_duplicate:
            raise DuplicateKeyError("E11000 duplicate key error collection: cve_events")
        if self.raise_pymongo:
            raise PyMongoError("AutoReconnect: connection refused")
        self.inserted.append(document)

    def create_index(self, *args, **kwargs):
        if self.raise_index_duplicate:
            raise DuplicateKeyError("E11000 duplicate key error index: event_id_1")
        self.indexes.append((args, kwargs))


# A normal insert returns "inserted" and appends the document.
def test_insert_event_inserted():
    coll = _FakeCollection()
    assert insert_event(coll, {"event_id": "abc"}) == "inserted"
    assert coll.inserted == [{"event_id": "abc"}]


# A DuplicateKeyError maps to "duplicate" and nothing is inserted.
def test_insert_event_duplicate_key_returns_duplicate():
    coll = _FakeCollection(raise_duplicate=True)
    assert insert_event(coll, {"event_id": "abc"}) == "duplicate"
    assert coll.inserted == []


# Any other PyMongo error maps to "failed".
def test_insert_event_other_pymongo_error_returns_failed():
    coll = _FakeCollection(raise_pymongo=True)
    assert insert_event(coll, {"event_id": "abc"}) == "failed"
    assert coll.inserted == []


# ensure_unique_index creates the unique index on event_id.
def test_ensure_unique_index_on_event_id():
    coll = _FakeCollection()
    ensure_unique_index(coll)
    assert len(coll.indexes) == 1
    args, kwargs = coll.indexes[0]
    assert args == ("event_id",)
    assert kwargs.get("unique") is True


# Pre-existing duplicate event_id values are logged, not raised.
def test_ensure_unique_index_duplicate_values_does_not_raise():
    coll = _FakeCollection(raise_index_duplicate=True)
    ensure_unique_index(coll)
    assert coll.indexes == []


def test_safe_json_deserializer_valid_json():
    assert _safe_json_deserializer(b'{"a": 1}') == {"a": 1}


def test_safe_json_deserializer_invalid_json_returns_none():
    assert _safe_json_deserializer(b"not-json") is None


# Credentials in the URI are stripped; a URI without them is unchanged.
@pytest.mark.parametrize(
    "uri,expected",
    [
        ("mongodb://user:secret@localhost:27017", "mongodb://localhost:27017"),
        ("mongodb://localhost:27017", "mongodb://localhost:27017"),
    ],
)
def test_redact_uri(uri, expected):
    assert _redact_uri(uri) == expected
