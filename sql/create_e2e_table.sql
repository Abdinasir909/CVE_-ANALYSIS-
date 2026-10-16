-- Creates the load target for the end-to-end performance runs, so a measurement run
-- never loads into RAW.CVE_RAW, which the loader would truncate first.
-- LIKE copies the structure only, not the rows, so load timings stay comparable.

USE DATABASE CVE_ANALYSIS;
USE SCHEMA RAW;

CREATE TABLE IF NOT EXISTS raw.cve_raw_e2e LIKE raw.cve_raw;

-- Confirm both tables report the same columns.
DESC TABLE CVE_ANALYSIS.RAW.CVE_RAW_E2E;

SELECT COUNT(*) AS rows_currently_in_e2e_table FROM CVE_ANALYSIS.RAW.CVE_RAW_E2E;

-- LIKE copies only the columns RAW.CVE_RAW currently has, and MATCH_BY_COLUMN_NAME
-- would silently skip any the ETL writes but the table lacks, so add them here.
-- ADD COLUMN IF NOT EXISTS, and only on CVE_RAW_E2E.
ALTER TABLE raw.cve_raw_e2e ADD COLUMN IF NOT EXISTS CVE_SOURCE_TYPE STRING;
ALTER TABLE raw.cve_raw_e2e ADD COLUMN IF NOT EXISTS AFFECTED_STATUS STRING;
ALTER TABLE raw.cve_raw_e2e ADD COLUMN IF NOT EXISTS AFFECTED_VERSION_RANGE STRING;

SELECT COUNT(*) AS e2e_column_count
FROM CVE_ANALYSIS.INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA = 'RAW' AND TABLE_NAME = 'CVE_RAW_E2E';
