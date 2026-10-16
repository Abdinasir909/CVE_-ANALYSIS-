# Consume CVE events from Kafka and insert into MongoDB (debug-only local sink).
# Pipeline: Kafka cve_events -> validate contract -> insert into cve_analysis_dev.cve_events,
# catching DuplicateKeyError so a replayed event is idempotent (no crash).

from __future__ import annotations

import argparse
import json
import signal
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlsplit

from src.transformation.quality_checks import validate_event_contract
from src.utils.config import Config
from src.utils.logging_config import get_logger, setup_logging

logger = get_logger(__name__)

GROUP_ID = "cve-analysis-mongo-debug-consumer"


# Deserialize a Kafka message value; return None on non-JSON input.
def _safe_json_deserializer(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError:
        return None


# Return a URI with any user:pass@ userinfo removed (host/port only).
def _redact_uri(uri: str) -> str:
    try:
        parts = urlsplit(uri)
    except ValueError:
        return "<unparseable uri>"
    host = parts.hostname or ""
    if parts.port:
        return f"{parts.scheme}://{host}:{parts.port}"
    return f"{parts.scheme}://{host}"


# Drop duplicate event_id values within a batch, return (unique, duplicate_count).
def dedupe_by_event_id(events: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    duplicates = 0
    for event in events:
        event_id = event.get("event_id") if isinstance(event, dict) else None
        if event_id is None:
            unique.append(event)
            continue
        if event_id in seen:
            duplicates += 1
        else:
            seen.add(event_id)
            unique.append(event)
    return unique, duplicates


# Insert one document; return 'inserted', 'duplicate', or 'failed'. Never raises.
def insert_event(collection, document: Dict[str, Any]) -> str:
    from pymongo.errors import DuplicateKeyError, PyMongoError

    try:
        collection.insert_one(document)
        return "inserted"
    except DuplicateKeyError:
        return "duplicate"
    except PyMongoError:
        return "failed"


# Create the unique index on event_id that backs idempotent inserts.
def ensure_unique_index(collection) -> None:
    from pymongo.errors import DuplicateKeyError

    try:
        collection.create_index("event_id", unique=True)
    except DuplicateKeyError as exc:
        logger.error(
            "collection has pre-existing duplicate event_id values — unique index not created",
            extra={"error": str(exc)},
        )


# CLI flags: --max-events bounds the run so it can be scripted and timed.
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Consume cve_events from Kafka and insert into MongoDB."
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Exit after consuming this many messages (default: run until Ctrl+C).",
    )
    return parser.parse_args(argv)


# Consume cve_events, validate each event and insert it into MongoDB. Duplicate
# key errors are caught rather than raised, which is what makes redelivery idempotent.
def main(argv=None) -> int:
    args = parse_args(argv)
    config = Config()
    setup_logging(config.log_level)

    from kafka import KafkaConsumer

    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    mongo_client = MongoClient(config.mongodb_uri, serverSelectionTimeoutMS=5000)
    try:
        mongo_client.admin.command("ping")
    except PyMongoError as exc:
        logger.error(
            "cannot reach MongoDB — start it with 'docker compose up -d'",
            extra={"uri": _redact_uri(config.mongodb_uri), "error": str(exc)},
        )
        mongo_client.close()
        return 2

    db = mongo_client[config.mongodb_database]
    collection = db[config.mongodb_collection]
    ensure_unique_index(collection)

    try:
        consumer = KafkaConsumer(
            config.kafka_topic,
            bootstrap_servers=config.kafka_bootstrap_servers,
            group_id=GROUP_ID,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            value_deserializer=_safe_json_deserializer,
        )
    except Exception as exc:
        logger.error(
            "cannot connect to Kafka — start it with 'docker compose up -d'",
            extra={"bootstrap": config.kafka_bootstrap_servers, "error": str(exc)},
        )
        mongo_client.close()
        return 2

    shutdown = {"requested": False}

    def _handle_signal(signum, frame):
        logger.warning("shutdown signal received", extra={"signal": int(signum)})
        shutdown["requested"] = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    consumed = 0
    inserted = 0
    duplicates = 0
    invalid = 0
    failed = 0
    errored = False

    try:
        while not shutdown["requested"]:
            batch = consumer.poll(timeout_ms=1000, max_records=100)
            if not batch:
                continue
            for messages in batch.values():
                for msg in messages:
                    if shutdown["requested"]:
                        break
                    # A None value means the deserializer hit a non-JSON message.
                    if msg.value is None:
                        logger.warning(
                            "skipping non-JSON message",
                            extra={"partition": msg.partition, "offset": msg.offset},
                        )
                        continue
                    if not isinstance(msg.value, dict):
                        logger.warning(
                            "skipping non-object message",
                            extra={"partition": msg.partition, "offset": msg.offset},
                        )
                        continue

                    consumed += 1
                    event = msg.value

                    valid, errors = validate_event_contract(event)
                    if not valid:
                        invalid += 1
                        logger.warning("invalid event skipped", extra={"errors": errors})
                    else:
                        document = dict(event)
                        document["mongo_ingested_at"] = datetime.now(timezone.utc).isoformat()
                        document["kafka_topic"] = msg.topic
                        document["kafka_partition"] = msg.partition
                        document["kafka_offset"] = msg.offset

                        result = insert_event(collection, document)
                        if result == "inserted":
                            inserted += 1
                            logger.info(
                                "inserted",
                                extra={"event_id": event["event_id"], "cve_id": event["cve_id"]},
                            )
                        elif result == "duplicate":
                            duplicates += 1
                            logger.info(
                                "duplicate event_id skipped",
                                extra={"event_id": event["event_id"], "cve_id": event["cve_id"]},
                            )
                        else:
                            failed += 1
                            logger.error(
                                "insert failed",
                                extra={"event_id": event["event_id"], "cve_id": event["cve_id"]},
                            )

                    if args.max_events is not None and consumed >= args.max_events:
                        logger.info("reached --max-events", extra={"consumed": consumed})
                        shutdown["requested"] = True
                        break
    except KeyboardInterrupt:
        logger.warning("interrupted — shutting down", extra={"consumed": consumed})
    except Exception as exc:
        errored = True
        logger.error("consumer error", extra={"error": str(exc)})
    finally:
        try:
            consumer.close()
        except Exception as exc:
            logger.warning("failed to close consumer cleanly", extra={"error": str(exc)})
        mongo_client.close()

    logger.info(
        "consumer finished",
        extra={
            "consumed": consumed,
            "inserted": inserted,
            "duplicates": duplicates,
            "invalid": invalid,
            "failed": failed,
        },
    )
    return 1 if errored else 0


if __name__ == "__main__":
    sys.exit(main())
