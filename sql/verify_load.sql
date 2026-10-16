-- Verifies what RAW.CVE_RAW actually contains after a load.
-- The loader clears the stage but not the table, and COPY INTO appends, so the row
-- count and the distinct cve_id count can disagree if several loads ran in sequence.

USE DATABASE CVE_ANALYSIS;
USE SCHEMA RAW;

-- 1. Rows in the table, and how many distinct CVEs they represent.
SELECT
    COUNT(*)                                          AS row_count,
    COUNT(DISTINCT CVE_ID)                            AS distinct_cve_id,
    COUNT(*) - COUNT(DISTINCT CVE_ID)                 AS duplicate_rows
FROM CVE_ANALYSIS.RAW.CVE_RAW;

-- 2. Which published-date range the table covers.
SELECT
    MIN(PUBLISHED)      AS min_published,
    MAX(PUBLISHED)      AS max_published,
    MIN(PUBLISHED_DATE) AS min_published_date,
    MAX(PUBLISHED_DATE) AS max_published_date
FROM CVE_ANALYSIS.RAW.CVE_RAW;

-- 3. Data-quality counts, to reconcile against quality_report.json.
SELECT
    COUNT_IF(CVSS_SCORE IS NULL)                       AS missing_cvss,
    COUNT_IF(VENDOR IS NULL OR TRIM(VENDOR) = '')      AS missing_vendor,
    COUNT_IF(DESCRIPTION_EN IS NULL
             OR TRIM(DESCRIPTION_EN) = '')             AS missing_description
FROM CVE_ANALYSIS.RAW.CVE_RAW;

-- 4. Severity distribution.
SELECT
    COALESCE(NULLIF(SEVERITY, ''), 'MISSING') AS severity,
    COUNT(*)                                  AS cve_count
FROM CVE_ANALYSIS.RAW.CVE_RAW
GROUP BY 1
ORDER BY cve_count DESC;

-- 5. Distinct CVEs per twelve-month publication window. The boundaries are written
--    out rather than derived, because the windows run September to September.
SELECT
    CASE
        WHEN PUBLISHED_DATE BETWEEN '2018-09-22' AND '2019-09-21' THEN '2018-09-22..2019-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2019-09-22' AND '2020-09-21' THEN '2019-09-22..2020-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2020-09-22' AND '2021-09-21' THEN '2020-09-22..2021-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2021-09-22' AND '2022-09-21' THEN '2021-09-22..2022-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2022-09-22' AND '2023-09-21' THEN '2022-09-22..2023-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2023-09-22' AND '2024-09-21' THEN '2023-09-22..2024-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2024-09-22' AND '2025-09-21' THEN '2024-09-22..2025-09-21'
        WHEN PUBLISHED_DATE BETWEEN '2025-09-22' AND '2026-09-21' THEN '2025-09-22..2026-09-21'
        ELSE 'OUTSIDE'
    END AS publication_window,
    COUNT(DISTINCT CVE_ID)                            AS distinct_cve_id,
    COUNT_IF(CVSS_SCORE IS NULL)                      AS missing_cvss,
    COUNT_IF(VENDOR IS NULL OR TRIM(VENDOR) = '')     AS missing_vendor
FROM CVE_ANALYSIS.RAW.CVE_RAW
GROUP BY 1
ORDER BY 1;

-- 6. CVSS versions loaded. v4.0 appears only where no earlier version exists.
SELECT
    COALESCE(CVSS_VERSION, 'NONE') AS cvss_version,
    COUNT(*)                       AS cve_count
FROM CVE_ANALYSIS.RAW.CVE_RAW
GROUP BY 1
ORDER BY 1;

-- 7. Which columns the table actually has.
DESC TABLE CVE_ANALYSIS.RAW.CVE_RAW;
