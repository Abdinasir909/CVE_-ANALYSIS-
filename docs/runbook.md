# Runbook

Everything in this file is a step that had to be carried out by hand before the
pipeline would run on a clean Windows machine. Each one is here because it caused
an actual failure, with the error it produces, so the failure can be recognised
rather than diagnosed from scratch.

Verified on: Windows 11, Python 3.11.9, PySpark 4.2.0, Java 23 (`23+37-2369`).

---

## 1. Windows Spark setup (winutils)

`src/transformation/batch_etl.py` calls `_ensure_hadoop_home()` before the JVM
starts. That function sets `HADOOP_HOME` (defaulting to
`%TEMP%\cve-analysis-hadoop`), creates `%HADOOP_HOME%\bin`, and prepends it to
`PATH` so the JVM can find `hadoop.dll`. It does **not** supply the binaries, and
they are not committed to this repository. If they are absent the ETL logs

```
winutils.exe not found — Spark may fail to write files on Windows.
```

and then fails when Spark tries to write the CSV or Parquet output.

Place two files in `%HADOOP_HOME%\bin`:

- `winutils.exe`
- `hadoop.dll`

Use the pair built for Hadoop 3.3.x. They must match each other; a `hadoop.dll`
from a different build raises `UnsatisfiedLinkError` in the JVM rather than a
missing-file error, which is harder to recognise.

To use a location other than `%TEMP%`, set `HADOOP_HOME` before running the ETL
and put the two files in its `bin` subdirectory.

## 2. Windows page file

`get_spark_session()` requests `spark.driver.memory=8g` and
`spark.executor.memory=8g`. Windows commits that memory up front, so the page
file must be large enough even on a machine with plenty of installed RAM. When
it is not, the JVM fails to start:

```
Error occurred during initialization of VM
Could not reserve enough space for object heap
```

This stopped a re-run of the eight-year ETL that had previously succeeded, so it
is not limited to first-time setup — a page file that Windows has shrunk will
reintroduce it.

Fix: System Properties → Advanced → Performance Settings → Advanced → Virtual
memory → Change, and set a managed or fixed page file of at least 16 GB on the
system drive. A reboot is required.

The 8 GB setting itself is required: Spark's default heap ran out of memory at
around 282,000 records during the eight-year run.

## 3. snowflake-connector on Windows Store Python

`snowflake-connector-python==4.7.3` crashes on import when Python was installed
from the Microsoft Store:

```
OSError: [Errno 22] Invalid argument:
'C:\\Users\\<user>\\AppData\\Local\\Microsoft\\WindowsApps\\
PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\\python.exe'
```

The traceback runs through `build_minicore_usage_for_session` →
`_CoreLoader.get_libc_version()` → `platform.libc_ver()`. The connector collects
telemetry about the running interpreter, and `platform.libc_ver()` opens
`sys.executable` as a file to read its ELF header. Under a Store install
`sys.executable` is a zero-length WindowsApps alias stub, which cannot be opened,
so the `OSError` propagates out of the import.

Two ways round it.

Preferred — install Python from python.org rather than the Microsoft Store, so
`sys.executable` is a real file. This removes the cause rather than the symptom.

Otherwise, neutralise the call before importing the connector. It is only used
for telemetry, so returning an empty version is harmless:

```python
import platform
platform.libc_ver = lambda *a, **k: ("", "")

import snowflake.connector  # must come after the line above
```

The patch has to be applied before the first import of `snowflake.connector`,
because the failure happens at import time, not at connect time.

## 4. Environment variables

Copy `.env.example` to `.env` and fill it in. The NVD API key is optional but
changes ingestion time by roughly an order of magnitude: without it the
ingestion script sleeps at least six seconds between requests to respect the
public rate limit.

The Snowflake loader needs account, user, password, warehouse, database, schema
and role. The test suite needs none of these — it runs without Docker, Kafka,
MongoDB, NVD network access or Snowflake.

## 5. Order of operations from a clean checkout

```
pip install -r requirements.txt
pytest -q                                   # no external services needed
docker compose up -d                        # only for the streaming path
python -m src.ingestion.ingest_nvd_batch --from 2026-08-28 --to 2026-08-30
python -m src.transformation.batch_etl --input "data/raw/*.json" --output-dir data/processed
```

The warehouse objects must exist before the first load. `sql/create_warehouse.sql`
creates the database, schema, `RAW.CVE_RAW`, the stage and both file formats;
`sql/star_schema.sql` builds the star schema and the analytics views on top of
the loaded table. Run them in that order.

The load itself is one command; it runs TRUNCATE, PUT and COPY INTO and prints
the verified row count:

```
python -m src.warehouse.load_to_snowflake --input data/processed_8y/cves_cleaned.parquet
```

Then run `sql/star_schema.sql` and `sql/verify_load.sql` in Snowsight, in that
order. The loader replaces the contents of `RAW.CVE_RAW`; that is intended, because
the table is a load target and the cleaned Parquet is the source of truth.

## 6. Reporting scripts

These produce numbers and figures quoted in the report. Each exists so a quoted
figure has a named source rather than a hand count.

```
python scripts/count_cvss_metric_versions.py \
    --input "data/raw/nvd_cves_2025-09-22_to_*.json" \
    --input "data/raw/nvd_cves_2026-*.json" \
    --from 2025-09-22 --to 2026-09-21
python scripts/window_breakdown.py --input data/processed_8y/cves_cleaned.csv --end 2026-09-21
python scripts/extract_published_window.py \
    --input data/raw/nvd_cves_2026-08-11_to_2026-09-21.json \
    --start 2026-08-28 --end 2026-08-30 \
    --output data/raw_windows/three_day_2026-08-28_to_2026-08-30.json
```

The last one slices a published-date window out of an existing raw chunk instead
of re-fetching it, which is how the three-day baseline input is produced.

## 7. Spark driver memory (and why 8g was wrong)

`SPARK_DRIVER_MEMORY` sets the driver heap for the batch ETL; the default is `4g`.
It replaced a hard-coded `8g` in `get_spark_session`.

Measured on the eight-year run of 282,755 records. The 1g to 5g rows come from
`logs/etl_memory_probe_8y.json` and `logs/etl_memory_probe_8y_boundary.json`. The
8g row is the ETL stage of `logs/e2e_eight-year_20261014T180922Z.json`, run before
`SPARK_DRIVER_MEMORY` existed, when `get_spark_session` still hard-coded 8g.

| Driver memory | Result | Duration | Free RAM before |
|---|---|---|---|
| 1g (Spark default) | OutOfMemoryError | 258.1 s | 2.03 GB |
| 2g | OutOfMemoryError | 56.8 s | 2.14 GB |
| 3g | completed | 105.8 s | 2.90 GB |
| 4g | completed | 109.0 s | 2.71 GB |
| 5g | completed | 99.4 s | 4.14 GB |
| 8g | completed | 122.0 s | — |

The floor is between 2g and 3g, so 4g is one step of headroom above it.

The `spark_config` block in every `logs/e2e_*.json` is a hard-coded literal in
`scripts/e2e_run.py` rather than a reading from the live session, so it is not
evidence of the heap a run used.

Two things to know about this machine (13.8 GB RAM):

- `8g` is larger than the free RAM once Docker Desktop is running, which reserves
  a VM of around 6.6 GB. The heap is then backed by the page file and the run
  slows down. Repeats of the three-day ETL took a mean of 27.0 s at 4g against
  34–39 s at 8g with the containers idle, and the spread fell from 7.9 s to 0.8 s.
- `spark.executor.memory` is no longer set at all. The job runs `local[*]`, where
  the executor shares the driver JVM, so that setting never had any effect. It
  previously read `8g` alongside the driver setting, which gave the misleading
  impression that two separate heaps were being sized.

Note that `.config("spark.driver.memory", ...)` in the builder does take effect
in PySpark — the launcher reads it before starting the JVM. A
`PYSPARK_SUBMIT_ARGS --driver-memory` value overrides it for the real heap while
`spark.conf.get("spark.driver.memory")` still reports the builder's value, so
check `Runtime.getRuntime().maxMemory()` rather than the config when verifying.

## 8. Measurement pitfalls found while timing the pipeline

Four traps, all of which produced wrong numbers before being caught. They are
recorded because each one is invisible in the output it produces.

**`--output` is ignored for ranges over 120 days.** This is a defect in
`src/ingestion/ingest_nvd_batch.py`, not in the measurement harness. `main()`
honours `args.output` only when the range fits in a single chunk:

```python
if args.output and len(chunks) == 1:
    output_path = Path(args.output)
else:
    output_path = raw_dir / f"nvd_cves_{cs}_to_{ce}.json"
```

A one-year range is 4 chunks and eight years is 25, so an explicit `--output` is
silently discarded and the chunks land in `config.raw_dir()`. This overwrote
`data/raw/nvd_cves_2018-09-22_to_2019-01-19.json`, part of the frozen
input snapshot. It is recorded here as a known limitation and is deliberately not
fixed, because the reported timings were measured against this version of the
ingestion script. The
fix is either to honour `--output` as a directory for multi-chunk ranges, or to
fail loudly when it cannot be honoured. Until then, chunk the range in the caller
and fetch one chunk per invocation, which is what `scripts/e2e_run.py` does.

**The replay producer defaults to 100 events at one per second.**
`producer_max_events` is 100 and `producer_delay_seconds` is 1.0 in config, so a
replay invoked without flags publishes 100 events in about 100 seconds and
measures the sleep, not the pipeline. `--max-events` has no unlimited sentinel,
so the exact record count has to be passed along with `--delay-seconds 0`.

**The Kafka consumer fails about half the time.** `kafka-python-ng 2.2.3` on
Windows raises `ValueError: Invalid file descriptor: -1` from Python's selector
when the group coordinator's heartbeat thread closes a socket the main thread is
still polling. Measured at 3 failures in 6 consecutive runs against a broker that
had been up for 27 minutes, and it is worse under load: the 85,147-event replay
needed 5 attempts, the 282,755-event replay needed 2.

It is a race, not a configuration problem, and the evidence for that is worth
keeping because the obvious diagnosis is wrong. Passing `api_version` explicitly
appears to fix it — `(2, 8, 0)` and `(3, 0, 0)` worked while `(2, 6, 0)`,
`(2, 7, 0)` and `(3, 7, 1)` failed. That ordering is not monotonic, so it cannot
be version support; re-testing `(2, 6, 0)` three times then succeeded three
times. The broker is `confluentinc/cp-kafka:7.7.1`, reporting `7.7.1-ccs`
(Apache Kafka 3.7.1), and the producer is unaffected because it does not join a
consumer group. Retry the stage rather than pinning a version that only looked
like a fix.

**Timings are invalid if the machine state changes mid-measurement.** A set of
three-day ETL repetitions gave a mean of 46.2 s with a 7.9 s spread, against
27.0 s and 0.8 s for the same code and input measured properly. Reconstructing
the window from the file timestamps showed the burst spanned about two and a
half minutes, with Docker's containers starting partway through it, so the middle
run bracketed container startup and was the slowest of the three. Let the containers
settle for at least ten minutes, and log free RAM per run —
`scripts/repeat_etl_timing.py` now records both the driver-memory setting and
free RAM before each repetition, so a contaminated set can be spotted after the
fact instead of being averaged into a result.
