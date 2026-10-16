-- Rebuilds the ANALYTICS star schema and Power BI views from RAW.CVE_RAW.
-- Re-runnable: every statement is CREATE OR REPLACE ... AS SELECT.
-- Surrogate keys use HASH(value), so a value maps to the same key on every rebuild.

USE DATABASE CVE_ANALYSIS;

CREATE SCHEMA IF NOT EXISTS CVE_ANALYSIS.ANALYTICS;

-- Dimensions
CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.dim_vendor AS
SELECT
    HASH(vendor) AS vendor_key,
    vendor
FROM (
    SELECT DISTINCT vendor
    FROM CVE_ANALYSIS.RAW.CVE_RAW
    WHERE vendor IS NOT NULL AND vendor <> ''
    UNION
    SELECT 'UNKNOWN'
);

CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.dim_product AS
SELECT
    HASH(product) AS product_key,
    product
FROM (
    SELECT DISTINCT product
    FROM CVE_ANALYSIS.RAW.CVE_RAW
    WHERE product IS NOT NULL AND product <> ''
    UNION
    SELECT 'UNKNOWN'
);

CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.dim_severity AS
SELECT
    HASH(severity) AS severity_key,
    severity
FROM (
    SELECT DISTINCT severity
    FROM CVE_ANALYSIS.RAW.CVE_RAW
    WHERE severity IS NOT NULL AND severity <> ''
    UNION
    SELECT 'MISSING'
);

CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.dim_date AS
SELECT
    HASH(published_date) AS date_key,
    published_date,
    year,
    month,
    quarter
FROM (
    SELECT DISTINCT published_date, year, month, quarter
    FROM CVE_ANALYSIS.RAW.CVE_RAW
);

-- Fact
CREATE OR REPLACE TABLE CVE_ANALYSIS.ANALYTICS.fact_cve AS
SELECT
    cve_id,
    HASH(COALESCE(NULLIF(vendor, ''), 'UNKNOWN'))   AS vendor_key,
    HASH(COALESCE(NULLIF(product, ''), 'UNKNOWN'))  AS product_key,
    HASH(COALESCE(NULLIF(severity, ''), 'MISSING')) AS severity_key,
    HASH(published_date)                            AS date_key,
    cvss_score,
    severity_rank,
    days_since_published
FROM CVE_ANALYSIS.RAW.CVE_RAW;

-- Views
CREATE OR REPLACE VIEW CVE_ANALYSIS.ANALYTICS.monthly_cve_overview AS
SELECT
    year,
    month,
    COUNT(*)                          AS total_cves,
    COUNT_IF(severity = 'HIGH')       AS high_cves,
    COUNT_IF(severity = 'CRITICAL')   AS critical_cves,
    COUNT_IF(cvss_score IS NULL)      AS missing_cvss
FROM CVE_ANALYSIS.RAW.CVE_RAW
GROUP BY year, month;

CREATE OR REPLACE VIEW CVE_ANALYSIS.ANALYTICS.severity_distribution AS
SELECT
    COALESCE(NULLIF(severity, ''), 'MISSING')  AS severity,
    COUNT(*)                                   AS cve_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) AS share_pct
FROM CVE_ANALYSIS.RAW.CVE_RAW
GROUP BY 1
ORDER BY cve_count DESC;

CREATE OR REPLACE VIEW CVE_ANALYSIS.ANALYTICS.data_quality AS
SELECT
    COUNT(*)                                 AS total_rows,
    COUNT(DISTINCT cve_id)                   AS distinct_cve_id,
    COUNT(*) - COUNT(DISTINCT cve_id)        AS duplicate_cve_id,
    COUNT_IF(cvss_score IS NULL)             AS missing_cvss,
    COUNT_IF(vendor IS NULL OR vendor = '')  AS missing_vendor,
    COUNT_IF(product IS NULL OR product = '') AS missing_product
FROM CVE_ANALYSIS.RAW.CVE_RAW;

-- RAW resolves one vendor/product per CVE, so a vendor's count does not
-- represent all affected vendors and is not a validated risk measure.
CREATE OR REPLACE VIEW CVE_ANALYSIS.ANALYTICS.vendor_cve_counts AS
SELECT
    vendor,
    COUNT(*)                AS cve_count,
    COUNT(DISTINCT cve_id)  AS distinct_cve_count
FROM CVE_ANALYSIS.RAW.CVE_RAW
WHERE vendor IS NOT NULL AND vendor <> ''
GROUP BY vendor
ORDER BY cve_count DESC;
