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
