-- Creates everything the batch load needs: warehouse, database, schemas, the raw
-- table, the stage and both file formats. Run this before the first load.
-- RAW.CVE_RAW must mirror FINAL_COLS in src/transformation/batch_etl.py, because
-- COPY INTO matches by column name and silently leaves out anything missing here.

CREATE WAREHOUSE IF NOT EXISTS CVE_ANALYSIS_WH
    WAREHOUSE_SIZE = 'XSMALL'
    AUTO_SUSPEND = 60
    AUTO_RESUME = TRUE;

USE WAREHOUSE CVE_ANALYSIS_WH;

CREATE DATABASE IF NOT EXISTS CVE_ANALYSIS;

USE DATABASE CVE_ANALYSIS;

CREATE SCHEMA IF NOT EXISTS RAW;
CREATE SCHEMA IF NOT EXISTS CLEANED;
CREATE SCHEMA IF NOT EXISTS ANALYTICS;

-- CSV format. Kept for reference only: the cleaned CSV fails Snowflake's parser
-- on embedded commas, quotes and newlines, so the load uses Parquet instead.
CREATE OR REPLACE FILE FORMAT RAW.CVE_CSV_FORMAT
    TYPE = CSV
    FIELD_DELIMITER = ','
    SKIP_HEADER = 1
    FIELD_OPTIONALLY_ENCLOSED_BY = '"'
    NULL_IF = ('', 'NaN', 'NULL', 'null')
    EMPTY_FIELD_AS_NULL = TRUE
    TRIM_SPACE = TRUE
    TIMESTAMP_FORMAT = 'AUTO'
    ERROR_ON_COLUMN_COUNT_MISMATCH = FALSE;

-- The format the loader actually names in COPY INTO.
CREATE OR REPLACE FILE FORMAT RAW.CVE_PARQUET_FORMAT
    TYPE = PARQUET;

CREATE OR REPLACE STAGE RAW.CVE_STAGE
    FILE_FORMAT = RAW.CVE_PARQUET_FORMAT;

CREATE OR REPLACE TABLE RAW.CVE_RAW (
    CVE_ID                  STRING,
    PUBLISHED               TIMESTAMP_NTZ,
    PUBLISHED_DATE          DATE,
    YEAR                    INT,
    MONTH                   INT,
    QUARTER                 INT,
    DAYS_SINCE_PUBLISHED    INT,
    LAST_MODIFIED           TIMESTAMP_NTZ,
    VULN_STATUS             STRING,
    DESCRIPTION_EN          STRING,
    CVSS_VERSION            STRING,
    CVSS_SCORE              FLOAT,
    SEVERITY                STRING,
    SEVERITY_RANK           INT,
    ATTACK_VECTOR           STRING,
    ATTACK_COMPLEXITY       STRING,
    PRIVILEGES_REQUIRED     STRING,
    USER_INTERACTION        STRING,
    CWE_IDS                 STRING,
    VENDOR                  STRING,
    PRODUCT                 STRING,
    CPE_URI                 STRING,
    SOURCE_IDENTIFIER       STRING,
    CVE_SOURCE_TYPE         STRING,
    AFFECTED_STATUS         STRING,
    AFFECTED_VERSION_RANGE  STRING
);

SHOW TABLES IN SCHEMA CVE_ANALYSIS.RAW;
SHOW STAGES IN SCHEMA CVE_ANALYSIS.RAW;
SHOW FILE FORMATS IN SCHEMA CVE_ANALYSIS.RAW;

DESC TABLE CVE_ANALYSIS.RAW.CVE_RAW;
