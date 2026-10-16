# CVE_-ANALYSIS-

A local big-data pipeline over the NVD CVE feed: ingestion to a preserved raw
layer, a PySpark batch ETL with data-quality reporting, a Kafka replay into
MongoDB, a Snowflake batch load modelled as a star schema, and a Power BI
dashboard on top of it.

Setup steps that have to be done by hand on Windows — winutils, the page file,
and the `snowflake-connector` crash under Microsoft Store Python — are in
[`docs/runbook.md`](docs/runbook.md). The field-by-field output schema is in
[`docs/data_dictionary.md`](docs/data_dictionary.md).

## Prerequisites

| Requirement | Notes |
| --- | --- |
| Python 3.11 | verified on 3.11.9 |
| Java 17 or later | PySpark 4 runs on the JVM; verified on Java 23 |
| Docker Desktop | only for the streaming stage (Kafka, MongoDB) |
| A Snowflake account | only for the warehouse load and the dashboard |

The tests need none of these except Python. Ingestion and the batch ETL need
Python and Java only. On Windows there are three setup steps that have to be done
by hand first, all in [`docs/runbook.md`](docs/runbook.md).

`data/` is not versioned, so from a fresh clone the raw layer has to be fetched
from the NVD API. The eight-year window is about 2.9 GB and the public rate limit
makes it roughly a 25-minute job. A short range is enough to exercise the pipeline.

## Running it end to end

```bash
pip install -r requirements.txt
cp .env.example .env                 # then fill it in
pytest -q                            # needs no external services
```

Create the warehouse objects once, before the first load:

```
sql/create_warehouse.sql             # warehouse, database, schemas, RAW.CVE_RAW,
                                     # stage, CSV + Parquet file formats
```

**Ingestion** — writes the untouched API response to `data/raw/`. A range longer
than 120 days (`MAX_RANGE_DAYS`) is split into consecutive chunks.

```bash
python -m src.ingestion.ingest_nvd_batch --from 2018-09-22 --to 2026-09-21
```

**Batch ETL** — reads a path or glob, writes `cves_cleaned.parquet`,
`cves_cleaned.csv` and `quality_report.json`.

```bash
python -m src.transformation.batch_etl \
    --input "data/raw/*.json" \
    --output-dir data/processed
```

**Streaming** — needs the Docker stack (`docker compose up -d`). The replay reads
the cleaned CSV and publishes to the `cve_events` topic with the CVE id as the
message key; the consumer validates each event and inserts it into MongoDB.

```bash
python -m src.streaming.replay_cves --input data/processed/cves_cleaned.csv
python -m src.streaming.kafka_consumer_mongo
```

**Snowflake load** — PUTs the Parquet part files to the stage and `COPY INTO`s
them by column name.

```bash
python -m src.warehouse.load_to_snowflake --input data/processed/cves_cleaned.parquet
```

`--full-reload` is the **default**: the loader issues an explicit
`TRUNCATE TABLE raw.cve_raw` before `COPY INTO`. This matters because `REMOVE`
clears the stage but not the table and `COPY INTO` appends, so without the
truncate a second load doubles the table. Pass `--no-full-reload` only to append
deliberately.

Then build the analytics layer:

```
sql/star_schema.sql                  # star schema + the Power BI views
sql/verify_load.sql                  # row counts, date range, quality counts
```

## Event contract

The producer and consumer share one contract so the two sides cannot drift, and
it carries a bounded set of fields, so the topic never carries the full NVD
record. It is defined by `_EVENT_REQUIRED_FIELDS` and `_EVENT_NULLABLE_FIELDS` in
`src/transformation/quality_checks.py` and validated by `validate_event_contract`
on both sides.

Required, and must not be empty:

| Field | Meaning |
| --- | --- |
| `event_id` | UUID4, fresh per event; the MongoDB unique index is on this |
| `event_timestamp` | ISO-8601 UTC, when the event was produced |
| `event_type` | always `cve_published` |
| `source` | always `nvd_replay` |
| `cve_id` | matches `^CVE-[0-9]{4}-[0-9]+$` |
| `published` | ISO-8601 UTC, from NVD |
| `last_modified` | ISO-8601 UTC, from NVD |
| `description` | English description |

Allowed to be null or empty, because NVD itself leaves them unset:

| Field | Meaning |
| --- | --- |
| `cvss_score` | float, 0.0–10.0 |
| `severity` | one of `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `vendor` | resolved vendor |
| `product` | resolved product |
| `raw_cpe_uri` | CPE string the vendor fallback came from |

Idempotency rests on `event_id`: the consumer creates a unique index on it, so a
redelivered event raises `DuplicateKeyError` and is counted as a duplicate rather
than inserted twice.

## Analysis scripts

`scripts/count_cvss_metric_versions.py` counts which CVSS metric versions the raw
NVD JSON carries per published-date window, straight from the raw layer. It exists to
measure how many records carry only a CVSS v4.0 score, independently of which
versions the ETL reads.

```bash
python scripts/count_cvss_metric_versions.py \
    --input "data/raw/*.json" --from 2025-09-22 --to 2026-09-21
```

## Daily incremental batch (scheduled, shipped disabled)

`run_pipeline.py` orchestrates the batch pipeline in order: fetch -> PySpark ETL ->
optional Snowflake load, stopping on the first error with a non-zero exit code.

**Incremental fetch** follows NVD's guidance: it queries `lastModStartDate` and
`lastModEndDate` (both required, ISO-8601 UTC). `lastModStartDate` is the end time of the
last successful run (read from `state/last_run.json`), and `lastModEndDate` is now. If the
state file is missing it defaults to the last 24 hours. If the range exceeds roughly
120 days it is split into chunks. Without an NVD API key it keeps the >=6-second delay
between requests.

**Flags:**
- `--dry-run` — print what would run, change nothing.
- `--since <ISO-8601>` / `--until <ISO-8601>` — override the range (for testing).
- `--load-snowflake` — run the Snowflake load. **OFF by default**, because the loader does
  a full reload (truncate) of `raw.cve_raw`.

**Output:** everything goes to `data/incremental/YYYY-MM-DD/` (never `data/processed/`),
and a log is written to `logs/pipeline_YYYY-MM-DD.log` (start/end time, range, records
fetched, ETL counts, durations, success/failure). The state file is written only after a
fully successful run.

**Environment variables** (read from `.env`, see `.env.example`): `NVD_API_KEY`,
`NVD_RESULTS_PER_PAGE`, `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PASSWORD`,
`SNOWFLAKE_WAREHOUSE`, `SNOWFLAKE_DATABASE`.

**Scheduled task** `CVE_Analysis_Daily_Batch` (daily 00:00 local time) is created but
**DISABLED on purpose**, so it does not run unattended. Its definition is exported to
`docs/scheduled_task_CVE_Analysis_Daily_Batch.xml`.

Enable it:
    schtasks /Change /TN "CVE_Analysis_Daily_Batch" /ENABLE

Remove it:
    schtasks /Delete /TN "CVE_Analysis_Daily_Batch" /F

## Supporting material for the report

[docs/appendix.md](docs/appendix.md) holds the repository tree, end-to-end run
instructions, the pytest output, the eight-year quality report, the star-schema
SQL, the per-window table and the measurement scripts. The report refers to it by
path rather than carrying an appendix, because the assignment caps the report at
25 pages including appendices.

See also [docs/runbook.md](docs/runbook.md) for the by-hand Windows setup steps
and the measurement pitfalls found while timing the pipeline.
