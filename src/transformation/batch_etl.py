# PySpark batch ETL: raw NVD JSON -> cleaned Parquet + CSV + quality report.

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pyspark.sql import SparkSession, functions as F
from pyspark.sql.types import StringType, StructField, StructType

from src.transformation.cpe_parser import find_primary_cpe23_uri, parse_cpe23_uri
from src.transformation.quality_checks import (
    SEVERITY_RANK_MAP,
    is_valid_cve_id_expr,
    severity_rank_expr,
)
from src.utils.config import Config
from src.utils.logging_config import get_logger, setup_logging

logger = get_logger(__name__)

# Canonical output column order (also the CSV header). Kept at module level so
# the replay producer's regression test can assert the exact header it maps.
FINAL_COLS = [
    "cve_id", "published", "published_date", "year", "month", "quarter",
    "days_since_published", "last_modified", "vuln_status", "description_en",
    "cvss_version", "cvss_score", "severity", "severity_rank",
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
    "cwe_ids", "vendor", "product", "cpe_uri", "source_identifier",
]

# Vendor/product extraction from the CPE configurations.

_RESOLVED_SCHEMA = StructType(
    [
        StructField("vendor", StringType(), True),
        StructField("product", StringType(), True),
        StructField("cpe_uri", StringType(), True),
    ]
)


# Pull vendor/product from the first CPE 2.3 URI in the configurations.
def _resolve_cpe(configurations_json):
    uri = find_primary_cpe23_uri(configurations_json)
    parsed = parse_cpe23_uri(uri) if uri else None
    return (
        parsed["vendor"] if parsed else "",
        parsed["product"] if parsed else "",
        uri or "",
    )


_resolve_udf = F.udf(_resolve_cpe, _RESOLVED_SCHEMA)


# Set HADOOP_HOME so Spark can write files on Windows (needs winutils.exe).
def _ensure_hadoop_home() -> None:
    home = os.environ.get("HADOOP_HOME")
    if not home:
        base = os.environ.get("TEMP") or os.environ.get("TMP") or str(Path.home())
        home = str(Path(base) / "cve-analysis-hadoop")
        os.environ["HADOOP_HOME"] = home

    bin_dir = Path(home) / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    # hadoop.dll must be on the JVM's library search path (PATH on Windows).
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    if not any(p.lower() == str(bin_dir).lower() for p in path_entries):
        os.environ["PATH"] = str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

    if not (bin_dir / "winutils.exe").exists():
        logger.warning(
            "winutils.exe not found — Spark may fail to write files on Windows. "
            "See docs/runbook.md -> 'Windows Spark setup (winutils)'.",
            extra={"bin_dir": str(bin_dir)},
        )
    else:
        logger.info("set HADOOP_HOME for Windows local-FS writes", extra={"path": home})


# Local single-machine session, the Hadoop fix must run before the JVM starts.
def get_spark_session(config: Config) -> SparkSession:
    _ensure_hadoop_home()
    return (
        SparkSession.builder.appName(config.spark_app_name)
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )


# Collect all CWE ids (e.g. CWE-79,CWE-89), deduped, or empty string.
def _cwe_ids_expr() -> F.Column:
    return F.coalesce(
        F.expr(
            "concat_ws(',', array_distinct(flatten("
            "transform(weaknesses, w -> transform(w.description, d -> d.value)))))"
        ),
        F.lit(""),
    )


# Read the raw JSON and shape it into the cleaned DataFrame.
def transform(spark: SparkSession, input_path: str) -> "F.DataFrame":
    input_path_obj = Path(input_path)
    if not input_path_obj.exists() and not _matches_glob(input_path):
        raise SystemExit(f"Input not found: {input_path}")

    raw = spark.read.option("multiline", "true").json(input_path)
    if "vulnerabilities" not in raw.columns:
        raise SystemExit(
            "Critical schema problem: input JSON has no 'vulnerabilities' field — "
            "expected an NVD CVE API 2.0 response."
        )

    cve = raw.select(F.explode("vulnerabilities").alias("vuln")).select("vuln.cve.*")

    metrics = F.col("metrics")
    # Null-safe: try_element_at returns null on empty arrays (Spark 4 raises INVALID_ARRAY_INDEX on [0]).
    v31 = F.try_element_at(metrics["cvssMetricV31"], F.lit(1))
    v30 = F.try_element_at(metrics["cvssMetricV30"], F.lit(1))
    v2 = F.try_element_at(metrics["cvssMetricV2"], F.lit(1))

    v31_data = v31["cvssData"]
    v30_data = v30["cvssData"]
    v2_data = v2["cvssData"]

    df = cve.select(
        F.col("id").alias("cve_id"),
        F.col("published"),
        F.col("lastModified").alias("last_modified"),
        F.col("vulnStatus").alias("vuln_status"),
        F.expr("try_element_at(filter(descriptions, d -> d.lang == 'en'), 1).value").alias("description_en"),
        F.coalesce(v31_data["version"], v30_data["version"], v2_data["version"]).alias("cvss_version"),
        F.coalesce(v31_data["baseScore"], v30_data["baseScore"], v2_data["baseScore"]).cast("double").alias("cvss_score"),
        F.coalesce(v31_data["baseSeverity"], v30_data["baseSeverity"], v2["baseSeverity"]).alias("severity"),
        F.coalesce(v31_data["attackVector"], v30_data["attackVector"]).alias("attack_vector"),
        F.coalesce(v31_data["attackComplexity"], v30_data["attackComplexity"]).alias("attack_complexity"),
        F.coalesce(v31_data["privilegesRequired"], v30_data["privilegesRequired"]).alias("privileges_required"),
        F.coalesce(v31_data["userInteraction"], v30_data["userInteraction"]).alias("user_interaction"),
        _cwe_ids_expr().alias("cwe_ids"),
        F.col("sourceIdentifier").alias("source_identifier"),
        F.to_json(F.col("configurations")).alias("_configurations_json"),
    )

    resolved = _resolve_udf(df["_configurations_json"])
    df = (
        df.withColumn("vendor", resolved["vendor"])
        .withColumn("product", resolved["product"])
        .withColumn("cpe_uri", resolved["cpe_uri"])
        .drop("_configurations_json")
    )

    # Derived fields.
    published_date = F.to_date(F.col("published"))
    df = (
        df.withColumn("published_date", published_date)
        .withColumn("year", F.year(published_date))
        .withColumn("month", F.month(published_date))
        .withColumn("quarter", F.quarter(published_date))
        .withColumn("days_since_published", F.datediff(F.current_date(), published_date))
        .withColumn("severity_rank", severity_rank_expr(F.col("severity")).cast("int"))
    )

    return df


# Simple check: does the path contain a glob character?
def _matches_glob(path: str) -> bool:
    return any(ch in path for ch in "*?[")


def _dedupe_by_cve_id(df: "F.DataFrame") -> "F.DataFrame":
    from pyspark.sql import Window

    window = Window.partitionBy("cve_id").orderBy(F.col("last_modified").desc_nulls_last())
    return df.withColumn("_rn", F.row_number().over(window)).filter(F.col("_rn") == 1).drop("_rn")


# Spark writes a folder of part files, collapse to one flat CSV for the replay.
def _write_single_csv(df: "F.DataFrame", csv_path: Path) -> None:
    tmp_dir = Path(str(csv_path) + ".tmp")
    (
        df.coalesce(1)
        .write.mode("overwrite")
        .option("header", "true")
        .option("escape", '"')
        .option("lineSep", "\n")
        .csv(str(tmp_dir))
    )
    part_files = list(tmp_dir.glob("part-*.csv"))
    if not part_files:
        raise SystemExit("CSV write produced no part file — cannot produce a flat CSV")

    if csv_path.exists():
        if csv_path.is_dir():
            shutil.rmtree(csv_path)
        else:
            csv_path.unlink()
    shutil.move(str(part_files[0]), str(csv_path))
    shutil.rmtree(tmp_dir)


# Pull out a single aggregated value.
def _collect_scalar(df: "F.DataFrame", col: str):
    rows = df.select(col).collect()
    return rows[0][0] if rows else None


# Run the whole ETL and return the quality report dict.
def run_etl(config: Config, input_path: str, output_dir: Path) -> Dict[str, Any]:
    spark = get_spark_session(config)
    try:
        df = transform(spark, input_path)

        input_records = df.count()
        if input_records == 0:
            logger.warning(
                "input has zero CVE records — writing empty outputs",
                extra={"input": input_path},
            )

        # Analysis-ready filter: keep only records with a well-formed CVE id.
        df_valid = df.filter(is_valid_cve_id_expr(F.col("cve_id")))
        records_dropped_invalid_cve_id = input_records - df_valid.count()

        # Dedupe by cve_id keeping the newest last_modified.
        deduped = _dedupe_by_cve_id(df_valid)

        # Persist for the multiple aggregations that follow.
        deduped.cache()
        output_records = deduped.count()
        valid_count = df_valid.count()

        duplicate_records_removed = valid_count - output_records

        records_missing_cvss = deduped.filter(F.col("cvss_score").isNull()).count()
        records_missing_description = deduped.filter(
            F.col("description_en").isNull() | (F.trim(F.col("description_en")) == "")
        ).count()
        records_missing_vendor = deduped.filter(
            F.col("vendor").isNull() | (F.trim(F.col("vendor")) == "")
        ).count()

        severity_counts = deduped.groupBy("severity").count().collect()
        severity_distribution: Dict[str, int] = {s: 0 for s in SEVERITY_RANK_MAP}
        severity_distribution["null"] = 0
        for row in severity_counts:
            key = row["severity"]
            if key is None:
                severity_distribution["null"] += row["count"]
                continue
            # Normalize exactly like quality_checks.severity_distribution so
            # lowercase/whitespace values don't fall into the "null" bucket.
            normalized = str(key).strip().upper()
            if normalized in severity_distribution:
                severity_distribution[normalized] += row["count"]
            else:
                severity_distribution["null"] += row["count"]

        min_published_date = _collect_scalar(deduped, F.min("published_date").alias("m"))
        max_published_date = _collect_scalar(deduped, F.max("published_date").alias("m"))
        min_published_date = str(min_published_date) if min_published_date is not None else None
        max_published_date = str(max_published_date) if max_published_date is not None else None

        # Write outputs.
        output_dir.mkdir(parents=True, exist_ok=True)
        parquet_path = output_dir / "cves_cleaned.parquet"
        csv_path = output_dir / "cves_cleaned.csv"

        final_cols = FINAL_COLS
        final = deduped.select(*final_cols)

        final.write.mode("overwrite").parquet(str(parquet_path))
        _write_single_csv(final, csv_path)

        report = {
            "input_records": input_records,
            "output_records": output_records,
            "duplicate_records_removed": duplicate_records_removed,
            "records_dropped_invalid_cve_id": records_dropped_invalid_cve_id,
            "records_missing_cvss": records_missing_cvss,
            "records_missing_description": records_missing_description,
            "records_missing_vendor": records_missing_vendor,
            "severity_distribution": severity_distribution,
            "min_published_date": min_published_date,
            "max_published_date": max_published_date,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        report_path = output_dir / "quality_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        logger.info(
            "ETL complete",
            extra={
                "input_records": input_records,
                "output_records": output_records,
                "parquet": str(parquet_path),
                "csv": str(csv_path),
                "report": str(report_path),
            },
        )
        return report
    finally:
        spark.stop()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Run the CVE Analysis batch ETL.")
    parser.add_argument("--input", required=True, help="NVD raw JSON path (file or glob).")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: data/processed).",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    config = Config()
    setup_logging(config.log_level)

    output_dir = Path(args.output_dir) if args.output_dir else config.processed_dir()
    try:
        report = run_etl(config, args.input, output_dir)
    except SystemExit as exc:
        logger.error("ETL aborted", extra={"error": str(exc)})
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        logger.error("ETL failed", extra={"error": str(exc)})
        print(f"ETL failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
