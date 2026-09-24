# Quality checks and the event contract for CVE records.

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Constants

# Severity names mapped to a numeric rank, so we can sort and aggregate them.
SEVERITY_RANK_MAP: Dict[str, int] = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITIES = frozenset(SEVERITY_RANK_MAP)

CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")

# Fields every event must have, and must not be empty.
_EVENT_REQUIRED_FIELDS = (
    "event_id",
    "event_timestamp",
    "event_type",
    "source",
    "cve_id",
    "published",
    "last_modified",
    "description",
)

# Fields that are allowed to be null or empty.
_EVENT_NULLABLE_FIELDS = ("cvss_score", "severity", "vendor", "product", "raw_cpe_uri")

EVENT_TYPE = "cve_published"
EVENT_SOURCE = "nvd_replay"


# Validators

# Map a severity string to its rank, or None for null/unknown.
def severity_rank(severity: Any) -> Optional[int]:
    if severity is None:
        return None
    if isinstance(severity, str) and not severity.strip():
        return None
    return SEVERITY_RANK_MAP.get(str(severity).strip().upper())


# Check the CVE-YYYY-NNNN format.
def is_valid_cve_id(cve_id: Any) -> bool:
    if not isinstance(cve_id, str):
        return False
    return bool(CVE_ID_PATTERN.match(cve_id.strip()))


# Score must be null, or a number in 0.0..10.0 (bool rejected).
def is_valid_cvss_score(score: Any) -> bool:
    if score is None:
        return True
    if isinstance(score, bool):
        return False
    if isinstance(score, str) and not score.strip():
        return True  # empty string == null in CSV-derived data
    try:
        value = float(score)
    except (TypeError, ValueError):
        return False
    return 0.0 <= value <= 10.0


# None and blank strings both count as missing.
def _is_non_empty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True


# Validate the event, returns (is_valid, list of errors).
def validate_event_contract(event: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors: List[str] = []

    if not isinstance(event, dict):
        return False, ["event must be a dict"]

    for field in _EVENT_REQUIRED_FIELDS:
        if field not in event or not _is_non_empty(event.get(field)):
            errors.append(f"missing or empty required field: {field}")

    if event.get("event_type") != EVENT_TYPE:
        errors.append(f"event_type must be {EVENT_TYPE!r}, got {event.get('event_type')!r}")
    if event.get("source") != EVENT_SOURCE:
        errors.append(f"source must be {EVENT_SOURCE!r}, got {event.get('source')!r}")

    cve_id = event.get("cve_id")
    if _is_non_empty(cve_id) and not is_valid_cve_id(cve_id):
        errors.append(f"malformed cve_id: {cve_id!r}")

    event_id = event.get("event_id")
    if _is_non_empty(event_id):
        try:
            parsed = uuid.UUID(str(event_id))
            if parsed.version != 4:
                errors.append(f"event_id is not a UUID4: {event_id!r}")
        except (ValueError, AttributeError, TypeError):
            errors.append(f"event_id is not a valid UUID: {event_id!r}")

    for ts_field in ("event_timestamp", "published", "last_modified"):
        value = event.get(ts_field)
        if _is_non_empty(value) and not _is_iso8601(value):
            errors.append(f"{ts_field} is not ISO-8601 (with UTC offset): {value!r}")

    if "cvss_score" in event and event["cvss_score"] is not None and not is_valid_cvss_score(event["cvss_score"]):
        errors.append(f"cvss_score out of range 0..10: {event['cvss_score']!r}")

    severity = event.get("severity")
    if _is_non_empty(severity) and str(severity).strip().upper() not in SEVERITIES:
        errors.append(f"severity not in {sorted(SEVERITIES)}: {severity!r}")

    return (len(errors) == 0, errors)


# Alias matching the R7 spec name.
validate_event = validate_event_contract


# Require an ISO-8601 timestamp with a UTC offset.
def _is_iso8601(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return False
    return dt.utcoffset() is not None


# Tally severities, missing values go in a "null" bucket.
def severity_distribution(records: Iterable[Any]) -> Dict[str, int]:
    distribution: Dict[str, int] = {s: 0 for s in SEVERITY_RANK_MAP}
    distribution["null"] = 0
    for record in records:
        if isinstance(record, dict):
            severity = record.get("severity")
        else:
            severity = getattr(record, "severity", None)
        if severity is None:
            distribution["null"] += 1
            continue
        key = str(severity).strip().upper()
        if key in distribution:
            distribution[key] += 1
        else:
            distribution["null"] += 1
    return distribution


# Return ids seen more than once, to verify dedup worked.
def find_duplicate_cve_ids(records: Iterable[Any]) -> List[str]:
    seen: Dict[str, int] = {}
    for record in records:
        if isinstance(record, dict):
            cve_id = record.get("cve_id")
        else:
            cve_id = getattr(record, "cve_id", None)
        if cve_id is None:
            continue
        key = str(cve_id)
        seen[key] = seen.get(key, 0) + 1
    return sorted(k for k, count in seen.items() if count > 1)


# Spark column expressions

# Spark expression that maps a severity string to its rank.
def severity_rank_expr(col):
    from pyspark.sql import functions as F

    expr = F.lit(None).cast("int")
    for name, rank in SEVERITY_RANK_MAP.items():
        expr = F.when(F.upper(F.trim(F.coalesce(col, F.lit("")))) == name, F.lit(rank)).otherwise(expr)
    return expr


# Spark expression: does the CVE id match the regex?
def is_valid_cve_id_expr(col):
    from pyspark.sql import functions as F

    return col.rlike(r"^CVE-[0-9]{4}-[0-9]+$")


# Spark expression: null or within 0..10.
def is_valid_cvss_score_expr(col):
    from pyspark.sql import functions as F

    score = col.cast("double")
    return score.isNull() | ((score >= 0.0) & (score <= 10.0))
