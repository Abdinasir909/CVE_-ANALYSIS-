# Data Dictionary

## Conceptual layers

| Layer | Local stand-in (this repo) | Future production home |
|-------|----------------------------|------------------------|
| **RAW** | `data/raw/nvd_cves_<start>_to_<end>.json` (verbatim NVD API 2.0 response, pagination merged) | Snowflake `RAW` (via Snowpipe Streaming / batch loader) |
| **CLEANED** | `data/processed/cves_cleaned.parquet` + `.csv` (one row per CVE, deduped, enriched) | Snowflake `CLEANED` |
| **ANALYTICS** | built in Snowflake by `sql/star_schema.sql` | Snowflake `ANALYTICS` (star schema read by Power BI) |

The raw JSON stays local. The cleaned output is loaded into Snowflake as `RAW.CVE_RAW`,
and `sql/star_schema.sql` builds the `ANALYTICS` star schema on top of it. The `CLEANED`
schema is created by `sql/create_warehouse.sql` but is not populated, because the loader
writes the cleaned output straight into `RAW.CVE_RAW`.

## CLEANED fields (`cves_cleaned.parquet` / `cves_cleaned.csv`)

One row per CVE, deduplicated by `cve_id` keeping the newest `last_modified`.

| Field | Type | Source / derivation | Notes |
|-------|------|---------------------|-------|
| `cve_id` | string | `cve.id` | Matches `^CVE-[0-9]{4}-[0-9]+$`; records failing this are dropped (reported) |
| `published` | string (ISO-8601) | `cve.published` | NVD publish timestamp |
| `published_date` | date | `to_date(published)` | Derived |
| `year` | int | `year(published_date)` | Derived |
| `month` | int | `month(published_date)` | Derived |
| `quarter` | int | `quarter(published_date)` | Derived |
| `days_since_published` | int | `datediff(current_date, published_date)` | Derived (0..N) |
| `last_modified` | string (ISO-8601) | `cve.lastModified` | Used as the dedup tie-breaker |
| `vuln_status` | string | `cve.vulnStatus` | `Analyzed` / `Modified` / `Rejected` … |
| `description_en` | string | first `descriptions[].value` where `lang == 'en'` | Null when no English description |
| `cvss_version` | string | coalesce(v3.1 → v3.0 → v2) `cvssData.version` | Preference order: 3.1, 3.0, 2.0 |
| `cvss_score` | double | coalesce(v3.1 → v3.0 → v2) `baseScore` | Null if no metric |
| `severity` | string | coalesce(v3.1/v3.0 `cvssData.baseSeverity`, v2 metric `baseSeverity`) | `NONE`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` (null when absent) |
| `severity_rank` | int | severity → rank | `NONE=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4` |
| `attack_vector` | string | coalesce(v3.1 → v3.0) `cvssData.attackVector` | v3-only; null for v2-only CVEs |
| `attack_complexity` | string | coalesce(v3.1 → v3.0) `cvssData.attackComplexity` | v3-only |
| `privileges_required` | string | coalesce(v3.1 → v3.0) `cvssData.privilegesRequired` | v3-only |
| `user_interaction` | string | coalesce(v3.1 → v3.0) `cvssData.userInteraction` | v3-only |
| `cwe_ids` | string | all CWE values across `weaknesses[].description[].value`, deduped, comma-joined | `""` when none |
| `vendor` | string | first CPE 2.3 URI in `configurations` → `vendor` | Null when no CPE |
| `product` | string | first CPE 2.3 URI → `product` | Null when no CPE |
| `cpe_uri` | string | first valid CPE 2.3 URI (raw, unmodified) | Null when no CPE |
| `source_identifier` | string | `cve.sourceIdentifier` | NVD CNA identifier |

CVSS preference: **v3.1 → v3.0 → v2** via Spark `coalesce` (first non-null wins).

## Event contract (`cve_events` Kafka topic → MongoDB)

`build_event()` / `validate_event_contract()` enforce this shape. `event_id` is a
fresh `uuid4` per produced event; `cve_id` is the Kafka message **key**.

| Field | Type | Notes |
|-------|------|-------|
| `event_id` | string (UUID4) | generated per event; unique-indexed in Mongo (idempotency) |
| `event_timestamp` | string (ISO-8601 UTC) | "now" at build time |
| `event_type` | string | always `cve_published` |
| `source` | string | always `nvd_replay` |
| `cve_id` | string | Kafka message key; must match CVE regex |
| `published` | string (ISO-8601, UTC offset) | required, non-empty |
| `last_modified` | string (ISO-8601, UTC offset) | required, non-empty |
| `cvss_score` | number or null | null OR 0.0..10.0 |
| `severity` | string or null | one of `NONE/LOW/MEDIUM/HIGH/CRITICAL` |
| `vendor` | string or null | nullable |
| `product` | string or null | nullable |
| `description` | string | required, non-empty |
| `raw_cpe_uri` | string or null | raw CPE 2.3 URI |

Bounded payload: the event never carries the full NVD `vulnerabilities` object —
only these 13 fields.

## CLEANED → EVENT field mapping

`replay_cves.py` reads `cves_cleaned.csv` (the CLEANED layer) and passes each row
to `build_event()` in `kafka_producer.py`, which produces the EVENT contract. The
field mapping is:

| CLEANED field (`cves_cleaned.csv`) | EVENT field | Notes |
|------------------------------------|-------------|-------|
| `cve_id` | `cve_id` | also set as the Kafka message **key** |
| `published` | `published` | NVD emits a naive UTC timestamp; normalized to an explicit UTC offset (`+00:00`) |
| `last_modified` | `last_modified` | same normalization as `published` |
| `cvss_score` | `cvss_score` | CSV string coerced to float (empty → null) |
| `severity` | `severity` | uppercased |
| `vendor` | `vendor` | verbatim (empty → null) |
| `product` | `product` | verbatim (empty → null) |
| `description_en` | `description` | **renamed** |
| `cpe_uri` | `raw_cpe_uri` | **renamed** |
| *(generated)* | `event_id` | fresh UUID4 per event |
| *(generated)* | `event_timestamp` | "now" in UTC ISO-8601 |
| *(generated)* | `event_type` | always `cve_published` |
| *(generated)* | `source` | always `nvd_replay` |

Note the two renames: the cleaned `description_en` becomes the event `description`,
and the cleaned `cpe_uri` becomes the event `raw_cpe_uri`. Only the 9 mapped
cleaned fields are carried across; the remaining CLEANED columns
(`published_date`, `year`, `month`, `quarter`, `days_since_published`,
`vuln_status`, `cvss_version`, `severity_rank`, `attack_vector`,
`attack_complexity`, `privileges_required`, `user_interaction`, `cwe_ids`,
`source_identifier`) are not part of the event contract and are dropped by the
replay producer.

## Mongo-only ingestion metadata (added by `kafka_consumer_mongo.py`)

| Field | Type | Notes |
|-------|------|-------|
| `mongo_ingested_at` | string (ISO-8601 UTC) | insert time |
| `kafka_topic` | string | `cve_events` |
| `kafka_partition` | int | source partition |
| `kafka_offset` | int | source offset |

## Quality report (`quality_report.json`)

| Field | Meaning |
|-------|---------|
| `input_records` | vulnerabilities read from raw JSON |
| `output_records` | rows written after invalid-CVE filter + dedup |
| `duplicate_records_removed` | rows removed by `cve_id` dedup (newest `last_modified` kept) |
| `records_dropped_invalid_cve_id` | rows whose `cve_id` failed the CVE regex |
| `records_missing_cvss` | output rows with null `cvss_score` |
| `records_missing_description` | output rows with null/empty `description_en` |
| `records_missing_vendor` | output rows with null/empty `vendor` |
| `severity_distribution` | counts per severity (`NONE..CRITICAL` + `null`) |
| `min_published_date` / `max_published_date` | range of `published_date` |
| `generated_at` | report creation time (ISO-8601 UTC) |
