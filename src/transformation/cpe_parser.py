# Parse CPE 2.3 URIs into vendor/product fields.

from __future__ import annotations

import json
from typing import Any, Dict, Optional

_CPE23_PREFIX = "cpe:2.3:"
# 13 components: cpe, 2.3, part, vendor, product, version, update, edition,
# language, sw_edition, target_sw, target_hw, other
_CPE23_COMPONENT_COUNT = 13

# Indices into the colon-split URI.
_IDX_PART = 2
_IDX_VENDOR = 3
_IDX_PRODUCT = 4
_IDX_VERSION = 5

# Wildcard / NA values that mean "no value".
_NULL_COMPONENTS = {"*", "-"}


# All fields empty, used for null or invalid input.
def _empty_result() -> Dict[str, str]:
    return {"vendor": "", "product": "", "version": "", "part": "", "cpe_uri": ""}


# Split a CPE 2.3 URI into vendor/product/version/part (blank when invalid).
def parse_cpe23_uri(cpe_uri: Optional[str]) -> Dict[str, str]:
    if not cpe_uri or not isinstance(cpe_uri, str):
        return _empty_result()

    uri = cpe_uri.strip()
    if not uri.startswith(_CPE23_PREFIX):
        return _empty_result()

    parts = uri.split(":")
    if len(parts) != _CPE23_COMPONENT_COUNT:
        return _empty_result()

    def _value(index: int) -> str:
        component = parts[index]
        return "" if component in _NULL_COMPONENTS else component

    return {
        "vendor": _value(_IDX_VENDOR),
        "product": _value(_IDX_PRODUCT),
        "version": _value(_IDX_VERSION),
        "part": parts[_IDX_PART],
        "cpe_uri": uri,
    }


# Walk the configurations nodes and return the first CPE 2.3 URI found.
def find_primary_cpe23_uri(configurations: Any) -> Optional[str]:
    if configurations is None:
        return None

    if isinstance(configurations, str):
        text = configurations.strip()
        if not text:
            return None
        try:
            configurations = json.loads(text)
        except (ValueError, TypeError):
            return None

    if not isinstance(configurations, (list, tuple)):
        return None

    for config in configurations:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes", []) or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch", []) or []:
                if not isinstance(match, dict):
                    continue
                criteria = match.get("criteria")
                if (
                    criteria
                    and isinstance(criteria, str)
                    and criteria.strip().startswith(_CPE23_PREFIX)
                ):
                    return criteria.strip()
    return None

# Vendor/product values that mean "no value" in the "affected" structure.
_AFFECTED_NA_VALUES = frozenset({"", "n/a", "na", "unknown", "none", "-", "*", "not available"})

# defaultStatus values that are meaningful for the per-CVE affected_status.
_AFFECTED_STATUSES = frozenset({"affected", "unaffected", "unknown"})


# Return a usable string from an affectedData value, or "" for placeholders.
def _clean_affected(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    return "" if text.lower() in _AFFECTED_NA_VALUES else text


# Return the first version-constraint string from a versions list.
def _first_version(versions: Any) -> str:
    if isinstance(versions, list):
        for entry in versions:
            if isinstance(entry, dict):
                version = entry.get("version")
                if isinstance(version, str) and version.strip():
                    return version.strip()
    return ""


# Return the first CPE reference (2.2 or 2.3 form) from a cpes list.
def _first_cpe(cpes: Any) -> str:
    if isinstance(cpes, list):
        for cpe in cpes:
            if isinstance(cpe, str) and cpe.strip():
                return cpe.strip()
    return ""


def _iter_affected_data(affected: Any):
    if isinstance(affected, str):
        text = affected.strip()
        if not text:
            return
        try:
            affected = json.loads(text)
        except (ValueError, TypeError):
            return
    if not isinstance(affected, list):
        return
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        for data in entry.get("affectedData", []) or []:
            if isinstance(data, dict):
                yield data


# Aggregate per-entry defaultStatus values, "affected" taking precedence.
def _aggregate_status(statuses: Any) -> str:
    statuses = statuses or set()
    if "affected" in statuses:
        return "affected"
    if "unaffected" in statuses:
        return "unaffected"
    if "unknown" in statuses:
        return "unknown"
    return ""


# Pull vendor/product/cpe_uri/status/version-range out of the "affected" structure.
def extract_affected(affected: Any) -> Dict[str, str]:
    primary = None
    product_fallback = None
    statuses = set()
    for data in _iter_affected_data(affected):
        status = _clean_affected(data.get("defaultStatus")).lower()
        if status in _AFFECTED_STATUSES:
            statuses.add(status)
        vendor = _clean_affected(data.get("vendor"))
        product = _clean_affected(data.get("product"))
        if vendor and primary is None:
            primary = data
        elif product and product_fallback is None:
            product_fallback = data

    selected = primary if primary is not None else product_fallback
    if selected is None:
        return {
            "vendor": "",
            "product": "",
            "cpe_uri": "",
            "affected_status": _aggregate_status(statuses),
            "affected_version_range": "",
        }

    return {
        "vendor": _clean_affected(selected.get("vendor")),
        "product": _clean_affected(selected.get("product")),
        "cpe_uri": _first_cpe(selected.get("cpes")),
        "affected_status": _aggregate_status(statuses),
        "affected_version_range": _first_version(selected.get("versions")),
    }


# Resolve vendor/product from "affected" first, falling back to the old CPE path.
def resolve_vendor_product(affected: Any, configurations: Any = None) -> Dict[str, str]:
    extracted = extract_affected(affected)
    vendor = extracted["vendor"]
    product = extracted["product"]
    cpe_uri = extracted["cpe_uri"]
    vendor_source = "affected" if vendor else "unresolved"

    uri = find_primary_cpe23_uri(configurations)
    parsed = parse_cpe23_uri(uri) if uri else None
    if not vendor and parsed and parsed["vendor"]:
        vendor = parsed["vendor"]
        vendor_source = "cpe_fallback"
    if not product and parsed and parsed["product"]:
        product = parsed["product"]
    if not cpe_uri and uri:
        cpe_uri = uri

    return {
        "vendor": vendor,
        "product": product,
        "cpe_uri": cpe_uri,
        "affected_status": extracted["affected_status"],
        "affected_version_range": extracted["affected_version_range"],
        "vendor_source": vendor_source,
    }
