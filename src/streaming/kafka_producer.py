# Build CVE events and publish them to a Kafka topic.

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.transformation.quality_checks import validate_event_contract
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


# Treat None and blank strings as null.
def _nullify(value: Any) -> Optional[Any]:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return value


# Add a UTC offset to naive NVD timestamps, leave anything else alone.
def _coerce_utc_timestamp(value: Any) -> Any:
    if not isinstance(value, str) or not value.strip():
        return value
    text = value.strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return value
    if dt.utcoffset() is None:
        return text + "+00:00"
    return text


def build_event(
    *,
    cve_id: str,
    published: str,
    last_modified: str,
    cvss_score: Any,
    severity: Any,
    vendor: Any,
    product: Any,
    description: str,
    raw_cpe_uri: Any,
    event_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    # Build one event matching the contract, fresh uuid4 and UTC timestamp.
    cvss = _nullify(cvss_score)
    if cvss is not None:
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            pass  # leave as-is, validate_event_contract will flag it

    severity_value = _nullify(severity)
    if severity_value is not None:
        severity_value = str(severity_value).strip().upper()

    return {
        "event_id": str(uuid.uuid4()),
        "event_timestamp": event_timestamp or datetime.now(timezone.utc).isoformat(),
        "event_type": "cve_published",
        "source": "nvd_replay",
        "cve_id": cve_id,
        "published": _coerce_utc_timestamp(published),
        "last_modified": _coerce_utc_timestamp(last_modified),
        "cvss_score": cvss,
        "severity": severity_value,
        "vendor": _nullify(vendor),
        "product": _nullify(product),
        "description": description,
        "raw_cpe_uri": _nullify(raw_cpe_uri),
    }


# Thin Kafka producer wrapper with validation and graceful failure.
class CVEProducer:

    def __init__(self, bootstrap_servers: str, topic: str) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self._producer = None

    # Lazily create the KafkaProducer on first use.
    def _ensure_connected(self):
        if self._producer is not None:
            return self._producer
        from kafka import KafkaProducer

        self._producer = KafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            acks="all",
            request_timeout_ms=10000,
        )
        return self._producer

    # Validate and send one event, returns True on success.
    def send_event(self, event: Dict[str, Any]) -> bool:
        valid, errors = validate_event_contract(event)
        if not valid:
            logger.error(
                "refusing to send invalid event",
                extra={"cve_id": event.get("cve_id"), "errors": errors},
            )
            return False

        try:
            producer = self._ensure_connected()
            producer.send(self.topic, key=event["cve_id"], value=event)
        except Exception as exc:  # KafkaError subclasses + connection errors
            logger.error(
                "failed to send event (is Kafka running?)",
                extra={"cve_id": event.get("cve_id"), "topic": self.topic, "error": str(exc)},
            )
            return False

        logger.debug("produced", extra={"cve_id": event["cve_id"], "topic": self.topic})
        return True

    # Block until all buffered messages are sent.
    def flush(self) -> None:
        if self._producer is not None:
            self._producer.flush()

    # Flush and shut the producer down cleanly.
    def close(self) -> None:
        if self._producer is not None:
            try:
                self._producer.flush()
                self._producer.close()
            finally:
                self._producer = None
