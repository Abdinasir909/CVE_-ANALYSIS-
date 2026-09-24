# Replay the cleaned CSV onto the Kafka cve_events topic.

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

from src.streaming.kafka_producer import CVEProducer, build_event
from src.transformation.quality_checks import validate_event_contract
from src.utils.config import Config
from src.utils.logging_config import get_logger, setup_logging

logger = get_logger(__name__)


# CLI flags for input path, delay and event limit.
def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Replay cleaned CVEs onto Kafka.")
    parser.add_argument(
        "--input",
        default="data/processed/cves_cleaned.csv",
        help="Path to the cleaned CSV produced by batch_etl.py.",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=None,
        help="Seconds to sleep between messages (default: from config).",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=None,
        help="Stop after sending this many events (default: from config).",
    )
    return parser.parse_args(argv)


# CSV values are strings, turn into a float, or None if blank/invalid.
def _coerce_cvss(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


# Map one cleaned CSV row to the event contract.
def build_event_from_row(row: dict) -> dict:
    return build_event(
        cve_id=row.get("cve_id"),
        published=row.get("published"),
        last_modified=row.get("last_modified"),
        cvss_score=_coerce_cvss(row.get("cvss_score")),
        severity=row.get("severity"),
        vendor=row.get("vendor"),
        product=row.get("product"),
        description=row.get("description_en"),
        raw_cpe_uri=row.get("cpe_uri"),
    )


# CLI entrypoint: stream the CSV row by row onto Kafka.
def main(argv=None) -> int:
    args = parse_args(argv)
    config = Config()
    setup_logging(config.log_level)

    delay = args.delay_seconds if args.delay_seconds is not None else config.producer_delay_seconds
    max_events = args.max_events if args.max_events is not None else config.producer_max_events

    input_path = Path(args.input)
    if not input_path.exists():
        logger.error("input CSV not found", extra={"path": str(input_path)})
        return 2

    producer = CVEProducer(config.kafka_bootstrap_servers, config.kafka_topic)

    # Fail fast: force a broker connection before streaming the whole file.
    try:
        producer._ensure_connected()
    except Exception as exc:
        logger.error(
            "cannot reach Kafka broker — start it with 'docker compose up -d'",
            extra={"bootstrap": config.kafka_bootstrap_servers, "error": str(exc)},
        )
        producer.close()
        return 2

    sent = 0
    skipped = 0
    try:
        with input_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if max_events is not None and sent >= max_events:
                    break

                event = build_event_from_row(row)

                valid, errors = validate_event_contract(event)
                if not valid:
                    logger.warning(
                        "skipping invalid row",
                        extra={"cve_id": row.get("cve_id"), "errors": errors},
                    )
                    skipped += 1
                    continue

                if producer.send_event(event):
                    logger.info("sent", extra={"cve_id": event["cve_id"]})
                    sent += 1

                if delay > 0:
                    time.sleep(delay)

        producer.flush()
    except KeyboardInterrupt:
        logger.warning("interrupted — flushing before exit", extra={"sent": sent})
    finally:
        producer.close()

    logger.info("replay complete", extra={"sent": sent, "skipped": skipped})
    return 0


if __name__ == "__main__":
    sys.exit(main())
