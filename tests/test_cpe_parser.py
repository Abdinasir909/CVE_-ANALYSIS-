# Tests for cpe_parser.

from src.transformation.cpe_parser import (
    extract_affected,
    find_primary_cpe23_uri,
    parse_cpe23_uri,
    resolve_vendor_product,
)

VALID_URI = "cpe:2.3:a:microsoft:word:2016:*:*:*:*:*:*:*"


# Valid app and OS CPEs split into vendor/product/version/part.
def test_parse_valid_cpe():
    app = parse_cpe23_uri(VALID_URI)
    assert app["vendor"] == "microsoft"
    assert app["product"] == "word"
    assert app["version"] == "2016"
    assert app["part"] == "a"
    assert app["cpe_uri"] == VALID_URI

    os_uri = parse_cpe23_uri("cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*")
    assert os_uri["part"] == "o"
    assert os_uri["product"] == "linux_kernel"


# Null, empty, non-CPE, CPE 2.2 and wrong component count all yield empty fields.
def test_parse_invalid_or_empty():
    assert parse_cpe23_uri(None)["vendor"] == ""
    assert parse_cpe23_uri("")["vendor"] == ""
    assert parse_cpe23_uri("not-a-cpe-at-all")["cpe_uri"] == ""
    # CPE 2.2 (12 components, 'cpe:/') is not a 2.3 URI.
    assert parse_cpe23_uri("cpe:/a:microsoft:word:2016")["cpe_uri"] == ""
    assert parse_cpe23_uri("cpe:2.3:a:microsoft:word")["cpe_uri"] == ""


# Wildcard/dash components map to empty, the real vendor stays.
def test_parse_wildcard_components():
    result = parse_cpe23_uri("cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*")
    assert result["vendor"] == "microsoft"
    assert result["product"] == ""
    assert result["version"] == ""


# Finds the first CPE 2.3 URI, skipping non-CPE criteria, from a structure or JSON string.
def test_find_primary_uri():
    configurations = [
        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.2:old-style"}, {"criteria": VALID_URI}]}]}
    ]
    assert find_primary_cpe23_uri(configurations) == VALID_URI

    import json

    assert find_primary_cpe23_uri(json.dumps(configurations)) == VALID_URI


# None/empty/dict input returns None.
def test_find_primary_empty():
    assert find_primary_cpe23_uri(None) is None
    assert find_primary_cpe23_uri([]) is None
    assert find_primary_cpe23_uri("[]") is None
    assert find_primary_cpe23_uri({}) is None


# Pulls vendor and product from the first affectedData entry.
def test_extract_affected_basic():
    affected = [{"source": "s", "affectedData": [{"vendor": "ceph", "product": "ceph"}]}]
    result = extract_affected(affected)
    assert result["vendor"] == "ceph"
    assert result["product"] == "ceph"


# NA placeholders are skipped, "Unknown" vendor keeps the product, missing input yields empty.
def test_extract_affected_edge_cases():
    affected = [
        {"affectedData": [{"vendor": "n/a", "product": "n/a"}]},
        {"affectedData": [{"vendor": "redhat", "product": "openshift"}]},
    ]
    result = extract_affected(affected)
    assert result["vendor"] == "redhat"
    assert result["product"] == "openshift"

    unknown = extract_affected([{"affectedData": [{"vendor": "Unknown", "product": "Shared Files"}]}])
    assert unknown["vendor"] == ""
    assert unknown["product"] == "Shared Files"

    assert extract_affected(None)["vendor"] == ""
    assert extract_affected([])["product"] == ""


# Version range and defaultStatus are read, and "affected" wins the aggregation.
def test_extract_affected_status_version():
    affected = [
        {
            "affectedData": [
                {
                    "vendor": "ceph",
                    "product": "ceph",
                    "defaultStatus": "affected",
                    "versions": [{"version": "< 19.2.6", "status": "affected"}],
                }
            ]
        }
    ]
    result = extract_affected(affected)
    assert result["affected_status"] == "affected"
    assert result["affected_version_range"] == "< 19.2.6"

    mixed = [
        {
            "affectedData": [
                {"vendor": "x", "product": "a", "defaultStatus": "unaffected"},
                {"vendor": "y", "product": "b", "defaultStatus": "affected"},
            ]
        }
    ]
    assert extract_affected(mixed)["affected_status"] == "affected"


# resolve_vendor_product prefers "affected" and falls back to CPE configurations.
def test_resolve_vendor_product():
    affected = [{"affectedData": [{"vendor": "ceph", "product": "ceph"}]}]
    configs = [{"nodes": [{"cpeMatch": [{"criteria": VALID_URI}]}]}]

    resolved = resolve_vendor_product(affected, configs)
    assert resolved["vendor"] == "ceph"
    assert resolved["vendor_source"] == "affected"

    fallback = resolve_vendor_product(None, configs)
    assert fallback["vendor"] == "microsoft"
    assert fallback["vendor_source"] == "cpe_fallback"
