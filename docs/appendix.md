  # Appendix

  Supporting material for the CS4010 report.

  Every figure and listing here is taken from the artefacts in this repository, not
  retyped.

## Repository Structure
The layout below is the project as submitted. Section 3.6 discusses the reasoning behind it; this is the full listing, including the files referenced elsewhere in the report.

```
CVE_ANALYSIS/
  src/
    ingestion/        ingest_nvd_batch.py
    transformation/   batch_etl.py  cpe_parser.py  quality_checks.py
    streaming/        replay_cves.py  kafka_producer.py
                      kafka_consumer_mongo.py
    warehouse/        load_to_snowflake.py
    utils/            config.py  logging_config.py
  tests/              8 test modules, 63 tests
  sql/                create_warehouse.sql  star_schema.sql
                      verify_load.sql
  scripts/            count_cvss_metric_versions.py  window_breakdown.py
                      extract_published_window.py
                      repeat_etl_timing.py  pandas_baseline.py
                      e2e_run.py
  docs/               runbook.md  data_dictionary.md
  data/
    raw/              25 eight-year chunks + 4 one-year chunks (3.10 GB)
    raw_windows/      three-day slice used for the baseline
    processed/        one-year cleaned output + quality report
    processed_3day/   three-day cleaned output + quality report
    processed_8y/     eight-year cleaned output + quality report
  logs/               pipeline and timing artefacts
  run_pipeline.py     orchestration: fetch -> ETL -> optional load
  docker-compose.yml  Kafka, MongoDB, Kafka UI, Mongo Express
  requirements.txt    pinned dependencies
  .env.example        required environment variables
```

## Running the Pipeline End to End
From a clean checkout. The by-hand Windows prerequisites are in `docs/runbook.md` and are not repeated here. They are `winutils.exe`, the page file, and the Python install needed by the Snowflake connector.

```
pip install -r requirements.txt
pytest -q                      # 63 tests, no external services

# Batch path
python -m src.ingestion.ingest_nvd_batch --from 2026-08-28 --to 2026-08-30
python -m src.transformation.batch_etl \
    --input "data/raw/*.json" --output-dir data/processed

# Streaming path (needs Docker)
docker compose up -d
python -m src.streaming.replay_cves --input data/processed/cves_cleaned.csv
python -m src.streaming.kafka_consumer_mongo

# Warehouse: run sql/create_warehouse.sql once in Snowsight, then load,
# then run sql/star_schema.sql and sql/verify_load.sql in Snowsight
python -m src.warehouse.load_to_snowflake \
    --input data/processed_8y/cves_cleaned.parquet
```

## Test Suite Output
The suite needs no Docker, Kafka, MongoDB, NVD network access or Snowflake, which is what allowed it to be run after every change.

```
$ pytest -q
.............................................................
63 passed, 1 warning in 31.90s
```

The single warning is PySpark's `Cannot infer the eval type from type hints` notice, raised when a Python function is registered as a UDF without type annotations. It is a style notice from PySpark, not a failure.

## Eight-Year Quality Report
`data/processed_8y/quality_report.json`, written by the ETL run that produced every eight-year figure in this report. It is reproduced in full because most of the numbers in Section 4 are read directly from it.

```
{
  "input_records": 282755,
  "output_records": 282755,
  "duplicate_records_removed": 0,
  "records_dropped_invalid_cve_id": 0,
  "records_missing_cvss": 15147,
  "records_missing_description": 0,
  "records_missing_vendor": 17539,
  "vendor_resolution": {
    "resolved_via_affected": 206049,
    "resolved_via_cpe_fallback": 59167,
    "still_unresolved": 17539
  },
  "source_type_distribution": {
    "vendor_direct": 76475,
    "third_party_db": 61296,
    "cert_national": 11317,
    "other": 133667
  },
  "severity_distribution": {
    "NONE": 70, "LOW": 10474, "MEDIUM": 119725,
    "HIGH": 105281, "CRITICAL": 32058, "null": 15147
  },
  "min_published_date": "2018-09-22",
  "max_published_date": "2026-09-21",
  "generated_at": "<run timestamp, elided>"
}
```

The `vendor_resolution` block is worth reading alongside Section 4.2: of 282,755 records, 206,049 vendors came from the CNA-supplied `affected` array and 59,167 from the CPE fallback, leaving 17,539 unresolved. The fallback therefore does most of the work the `affected` array cannot, which is why the missing-vendor share is as low as it is.

## Star-Schema SQL
Abridged from `sql/star_schema.sql`: one dimension, the fact table, and the key construction. The remaining three dimensions follow the same pattern.

```
-- Surrogate keys use HASH(value), so a value maps to the same key on every
-- rebuild. Every statement is CREATE OR REPLACE ... AS SELECT, so the whole
-- file is re-runnable.
CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.dim_vendor AS
SELECT
    HASH(vendor) AS vendor_key,
    vendor
FROM (
    SELECT DISTINCT vendor
    FROM CVE_ANALYSIS.RAW.CVE_RAW
    WHERE vendor IS NOT NULL AND vendor <> "
    UNION
    SELECT 'UNKNOWN'
);

CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.fact_cve AS
SELECT
    cve_id,
    HASH(COALESCE(NULLIF(vendor, "), 'UNKNOWN'))   AS vendor_key,
    HASH(COALESCE(NULLIF(product, "), 'UNKNOWN'))  AS product_key,
    HASH(COALESCE(NULLIF(severity, "), 'MISSING')) AS severity_key,
    HASH(published_date)                            AS date_key,
    cvss_score,
    severity_rank,
    days_since_published
FROM CVE_ANALYSIS.RAW.CVE_RAW;
```

The two halves have to agree on the fallback value, and that is the detail worth noticing: the dimension `UNION`s in a literal `'UNKNOWN'` row, and the fact table maps a null or empty vendor to `HASH('UNKNOWN')`. Because both sides hash the same string, every CVE joins and no record is lost from the fact table. `dim_severity` does the same with `'MISSING'`, which is how the 15,147 unscored records stay in the schema instead of dropping out of the dashboard.

## Counting CVSS Metric Versions in the Raw JSON
`scripts/count_cvss_metric_versions.py`. This is the script that found the omission described in Section 4.2.1. It reads the raw JSON directly and counts which `cvssMetric*` blocks each record carries, independently of the ETL, which is the whole point. A quality report that counts nulls in its own output cannot detect a field its own reader never reads.

```
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31",
               "cvssMetricV30", "cvssMetricV2")

# Versions the ETL actually reads (src/transformation/batch_etl.py).
ETL_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# True when the metric list exists and its first entry carries a base score.
def _has_score(metrics: dict, key: str) -> bool:
    entries = metrics.get(key) or []
    if not entries:
        return False
    return (entries[0].get("cvssData") or {}).get("baseScore") is not None

def scan(paths: list[str], start: str, end: str) -> dict:
    seen: dict[str, tuple[str, tuple[bool, ...]]] = {}
    for path in paths:
        with open(path, "rb") as handle:
            for cve in ijson.items(handle, "vulnerabilities.item.cve",
                                   use_float=True):
                published_date = (cve.get("published") or "")[:10]
                if not (start <= published_date <= end):
                    continue
                metrics = cve.get("metrics") or {}
                flags = tuple(_has_score(metrics, k) for k in METRIC_KEYS)
                cve_id = cve.get("id")
                last_modified = cve.get("lastModified") or ""
                previous = seen.get(cve_id)
                # Dedupe by cve_id keeping newest lastModified, as the ETL does.
                if previous is None or last_modified > previous[0]:
                    seen[cve_id] = (last_modified, flags)
    ...
```

Two details make the count trustworthy. It deduplicates by `cve_id` keeping the newest `lastModified`, exactly as the ETL does, so the denominator is the same population the quality report describes rather than the raw record count. And it reads the JSON with `ijson`, a streaming parser, because the eight-year chunks do not fit in memory as a single parsed object, the same constraint that motivates Spark for the transformation itself.

## Measurement Scripts
Two scripts produce the performance figures in Section 4.6, so that neither the mean nor the comparison is read off a terminal.

`scripts/repeat_etl_timing.py` runs the ETL as a fresh subprocess $n$ times and writes the per-run durations with their mean and spread to JSON. Each repetition pays its own Spark startup deliberately: startup is most of the duration at these volumes, and timing repetitions inside one long-lived session would measure something the pipeline never does.

`scripts/pandas_baseline.py` is a Pandas implementation of the same transformation, used for the comparison in Section 4.6. It imports `_resolve_affected`, `classify_source_type` and `severity_rank` from the Spark job rather than reimplementing them, so the two engines are compared on identical logic. It is not part of the pipeline; the pipeline uses no Pandas.

## Records per twelve-month window (eight-year dataset)

Source: `scripts/window_breakdown.py` reading `data/processed_8y/cves_cleaned.csv`.
Counts are distinct `cve_id` values; `records_outside_windows` is 0.

| Window | Records | Missing CVSS | Missing vendor |
|---|---|---|---|
| 2018-09-22..2019-09-21 | 16,847 | 1,119 (6.64%) | 1,133 (6.73%) |
| 2019-09-22..2020-09-21 | 20,156 | 1,186 (5.88%) | 1,197 (5.94%) |
| 2020-09-22..2021-09-21 | 20,804 | 1,465 (7.04%) | 1,476 (7.09%) |
| 2021-09-22..2022-09-21 | 25,111 | 1,300 (5.18%) | 1,311 (5.22%) |
| 2022-09-22..2023-09-21 | 29,903 | 2,667 (8.92%) | 2,676 (8.95%) |
| 2023-09-22..2024-09-21 | 37,514 | 815 (2.17%) | 1,020 (2.72%) |
| 2024-09-22..2025-09-21 | 47,273 | 1,502 (3.18%) | 2,670 (5.65%) |
| 2025-09-22..2026-09-21 | 85,147 | 5,093 (5.98%) | 6,056 (7.11%) |

These are the figures Section 4.2 quotes. The table was moved here because the
report is capped at 25 pages including any appendix.

## Provenance of the raw chunks

The eight-year window is 25 raw chunks fetched in one session. The first of
them, `nvd_cves_2018-09-22_to_2019-01-19.json`, was later refetched during
the performance measurements, because `src/ingestion/ingest_nvd_batch.py` honours
`--output` only when a range fits in one 120-day chunk and otherwise writes into
`config.raw_dir()`. That is a defect in the ingestion script, recorded in
`docs/runbook.md`, and it is why the harness now fetches one chunk per call.

Two consequences:

- The ingestion lower bound for the eight-year fetch is computed from the 24
  chunks whose original timestamps survive, giving at least 1,414 seconds. The
  refetched chunk carries a later timestamp and is excluded.
- The one-year run reports 4,389 v4.0 recoveries for the newest published window where
  the eight-year run reports 4,390. Its four raw chunks were fetched one day before
  the twenty-five eight-year chunks and NVD scored one more record in between, so the
  figures are one day apart rather than inconsistent.
- The refetch changed four records out of 282,755, where Siemens had since filed
  affected-product data against four 2018 and 2019 CVEs. That moves their vendor,
  product and affected-version-range fields and shifts the vendor-resolution split
  by four, from 206,049 records resolved through the affected array to 206,053. No
  record count, missing-value count or severity figure changes.

Every analytical figure in the report comes from the preserved cleaned output in
`data/processed_8y/`, which predates the refetch.

## Streaming verification screenshots

`docs/screenshots/kafka-ui.png` shows the `cve_events` topic after the
ten-record correctness run, and `docs/screenshots/cve-events.png` shows the
same ten events stored in MongoDB. They are kept here rather than in the report,
which is capped at 25 pages; Section 4.3 states the counts they show, namely ten
events published, ten consumed, ten duplicates rejected on replay and zero
failures.
