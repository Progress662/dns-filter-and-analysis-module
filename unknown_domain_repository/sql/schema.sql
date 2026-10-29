-- =============================================================================
-- Unknown Domain Repository Schema
-- =============================================================================
-- Production-grade PostgreSQL schema for persisting domains not found in
-- known threat intelligence databases (Tranco, URLhaus).
-- 
-- This schema is designed for:
-- - High-throughput batch insertions
-- - Concurrent read/write access
-- - Future extensibility via metadata
-- - Audit and compliance requirements
-- - Performance optimization for millions of domains
-- =============================================================================

-- Ensure we're using UTF-8 encoding for international domains
SET client_encoding = 'UTF8';

-- =============================================================================
-- Extensions
-- =============================================================================

-- Enable UUID generation for potential future use
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable advanced JSON operations for metadata queries
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- =============================================================================
-- Custom Types
-- =============================================================================

-- Domain source enumeration
-- Tracks where the domain was discovered for audit purposes
CREATE TYPE domain_source AS ENUM (
    'dns_query_log',    -- From Bind9 DNS query logs (primary source)
    'manual_import',    -- Manually imported domains
    'system_test'       -- Test data for development/testing
);

-- Domain status enumeration
-- Tracks processing state for enrichment workflows
--
-- Covers the full online threat-intelligence lifecycle:
--   new           -- Newly inserted, awaiting enrichment
--   processing    -- Currently being evaluated by online TI providers
--   malicious     -- Confirmed malicious by online TI correlation
--   clean         -- Evaluated and found to have no malicious indicators
--   review_needed -- No provider had any intelligence on the domain
--   error         -- Enrichment failed and requires investigation/retry
CREATE TYPE domain_status AS ENUM (
    'new',
    'processing',
    'malicious',
    'clean',
    'review_needed',
    'error'
);

-- =============================================================================
-- Migration: Upgrade existing databases to the extended domain_status enum
-- =============================================================================
-- On a fresh install the CREATE TYPE statement above already defines every
-- value, so these are no-ops (IF NOT EXISTS guards against the duplicate).
-- On an existing database where domain_status only has 'new', these safely
-- add the missing values without dropping/recreating the type (which would
-- require rewriting every dependent column, index, and view).
--
-- Note: ALTER TYPE ... ADD VALUE cannot be used in the same transaction as
-- a statement that reads/writes a column using the new value, but each
-- statement below is otherwise safe to run standalone or as part of a
-- migration script.
ALTER TYPE domain_status ADD VALUE IF NOT EXISTS 'processing';
ALTER TYPE domain_status ADD VALUE IF NOT EXISTS 'malicious';
ALTER TYPE domain_status ADD VALUE IF NOT EXISTS 'clean';
ALTER TYPE domain_status ADD VALUE IF NOT EXISTS 'review_needed';
ALTER TYPE domain_status ADD VALUE IF NOT EXISTS 'error';

-- =============================================================================
-- Main Table: unknown_domains
-- =============================================================================

CREATE TABLE unknown_domains (
    -- =================================================================
    -- Primary Key
    -- =================================================================
    
    id BIGSERIAL PRIMARY KEY,
    -- BIGSERIAL provides auto-incrementing 64-bit integers
    -- Supports up to 9.2 quintillion rows
    -- Using BIGINT from start prevents future migration pain
    
    -- =================================================================
    -- Core Domain Data
    -- =================================================================
    
    domain VARCHAR(253) NOT NULL,
    -- VARCHAR(253): Maximum domain length per RFC 1035
    -- NOT NULL: Every record must have a domain
    -- Indexed uniquely for UPSERT operations
    
    -- =================================================================
    -- Temporal Tracking
    -- =================================================================
    
    first_seen TIMESTAMPTZ NOT NULL,
    -- When domain was first encountered in DNS logs
    -- TIMESTAMPTZ: Timezone-aware for global deployments
    -- Essential for threat intelligence timeline analysis
    
    last_seen TIMESTAMPTZ NOT NULL,
    -- When domain was most recently observed
    -- Updated on each subsequent observation
    -- Enables dormancy and activity pattern analysis
    
    -- =================================================================
    -- Metadata and Classification
    -- =================================================================
    
    source domain_source NOT NULL DEFAULT 'dns_query_log',
    -- Origin of domain discovery
    -- Enum type ensures referential integrity
    -- Default matches primary use case
    
    status domain_status NOT NULL DEFAULT 'new',
    -- Processing state for enrichment workflows
    -- Enables queuing and status tracking
    -- Future-proofed for enrichment service integration
    
    metadata JSONB,
    -- Extensible metadata storage for enrichment data
    -- JSONB: Binary JSON for performance and indexing
    -- NULL by default: most domains start without metadata
    -- Future enrichment services can add structured data here
    
    -- =================================================================
    -- Audit and System Columns
    -- =================================================================
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Record creation timestamp
    -- Immutable after insertion
    -- Required for audit trails and compliance
    
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Last modification timestamp
    -- Updated by triggers or application logic
    -- Essential for change tracking
    
    schema_version INTEGER NOT NULL DEFAULT 2
    -- Schema version for migration compatibility
    -- Enables rolling deployments and gradual migrations
    -- Increment when schema changes
);

-- =============================================================================
-- Constraints
-- =============================================================================

-- Unique constraint on domain for UPSERT operations
-- Enables efficient ON CONFLICT handling
ALTER TABLE unknown_domains 
ADD CONSTRAINT uq_unknown_domains_domain UNIQUE (domain);

-- Temporal consistency: last_seen >= first_seen
-- Prevents data corruption from application bugs
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_temporal_order 
CHECK (last_seen >= first_seen);

-- Audit consistency: updated_at >= created_at
-- Maintains audit trail integrity
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_audit_order 
CHECK (updated_at >= created_at);

-- Domain format validation (basic check)
-- Additional validation performed at application level
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_domain_format 
CHECK (
    domain ~ '^[a-z0-9.-]+$' AND           -- Only lowercase alphanumeric, dots, hyphens
    length(domain) >= 3 AND                -- Minimum reasonable length
    length(domain) <= 253 AND              -- RFC 1035 maximum
    domain NOT LIKE '.%' AND               -- Cannot start with dot
    domain NOT LIKE '%.' AND               -- Cannot end with dot
    domain NOT LIKE '%..%'                 -- No consecutive dots
);

-- Metadata size limit to prevent abuse
-- 1MB should be sufficient for enrichment data
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_metadata_size 
CHECK (pg_column_size(metadata) <= 1048576);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================

-- Primary query pattern: lookup by domain name
-- Covered by unique constraint, but explicit for clarity
-- Used by: UPSERT operations, domain existence checks
CREATE UNIQUE INDEX IF NOT EXISTS idx_unknown_domains_domain 
ON unknown_domains (domain);

-- Time-based queries for analytics and cleanup
-- Query pattern: domains seen within date ranges
CREATE INDEX idx_unknown_domains_first_seen 
ON unknown_domains (first_seen);

CREATE INDEX idx_unknown_domains_last_seen 
ON unknown_domains (last_seen);

-- Status-based queries for enrichment workflows
-- Query pattern: find domains by processing status
CREATE INDEX idx_unknown_domains_status 
ON unknown_domains (status);

-- Composite index for status + temporal queries
-- Query pattern: new domains within time range
CREATE INDEX idx_unknown_domains_status_first_seen 
ON unknown_domains (status, first_seen);

-- Source tracking for audit and debugging
-- Query pattern: domains from specific sources
CREATE INDEX idx_unknown_domains_source 
ON unknown_domains (source);

-- Metadata queries using GIN index
-- Query pattern: search within JSON metadata
-- Requires btree_gin extension
CREATE INDEX idx_unknown_domains_metadata_gin 
ON unknown_domains USING GIN (metadata);

-- Composite index for efficient pagination
-- Query pattern: paginated results ordered by ID
CREATE INDEX idx_unknown_domains_id_created_at 
ON unknown_domains (id, created_at);

-- Schema version for migration queries
-- Query pattern: find records needing migration
CREATE INDEX idx_unknown_domains_schema_version 
ON unknown_domains (schema_version);

-- =============================================================================
-- Triggers
-- =============================================================================

-- Automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trg_unknown_domains_updated_at
    BEFORE UPDATE ON unknown_domains
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Views for Common Queries
-- =============================================================================

-- Recently discovered domains (last 24 hours)
CREATE VIEW recent_domains AS
SELECT 
    domain,
    first_seen,
    last_seen,
    source,
    status,
    created_at
FROM unknown_domains
WHERE first_seen >= NOW() - INTERVAL '24 hours'
ORDER BY first_seen DESC;

-- Domains requiring enrichment (status = 'new')
CREATE VIEW domains_for_enrichment AS
SELECT 
    id,
    domain,
    first_seen,
    last_seen,
    source,
    metadata,
    created_at
FROM unknown_domains
WHERE status = 'new'
ORDER BY first_seen ASC;

-- Domain activity summary
CREATE VIEW domain_activity_summary AS
SELECT 
    status,
    source,
    COUNT(*) as count,
    MIN(first_seen) as earliest_first_seen,
    MAX(last_seen) as latest_last_seen,
    AVG(EXTRACT(EPOCH FROM (last_seen - first_seen))) as avg_observation_duration_seconds
FROM unknown_domains
GROUP BY status, source
ORDER BY status, source;

-- =============================================================================
-- Table Statistics and Maintenance
-- =============================================================================

-- Set table statistics target for better query planning
-- Higher value improves planning for large tables
ALTER TABLE unknown_domains ALTER COLUMN domain SET STATISTICS 1000;
ALTER TABLE unknown_domains ALTER COLUMN first_seen SET STATISTICS 1000;
ALTER TABLE unknown_domains ALTER COLUMN last_seen SET STATISTICS 1000;
ALTER TABLE unknown_domains ALTER COLUMN status SET STATISTICS 100;

-- =============================================================================
-- Table Storage Optimization
-- =============================================================================

-- Set fillfactor to 90% to leave space for updates
-- Reduces page splits during UPDATE operations
ALTER TABLE unknown_domains SET (fillfactor = 90);

-- Enable parallel operations for large table operations
ALTER TABLE unknown_domains SET (parallel_workers = 4);

-- =============================================================================
-- Comments for Documentation
-- =============================================================================

COMMENT ON TABLE unknown_domains IS 
'Persistent storage for domains not found in known threat intelligence databases (Tranco, URLhaus). Used as input for enrichment services to gather additional reputation data.';

COMMENT ON COLUMN unknown_domains.id IS 
'Primary key. Auto-incrementing 64-bit integer supporting billions of records.';

COMMENT ON COLUMN unknown_domains.domain IS 
'Normalized domain name. Lowercase, validated format. Unique constraint enables efficient UPSERT operations.';

COMMENT ON COLUMN unknown_domains.first_seen IS 
'Timestamp when domain was first encountered in DNS logs. Timezone-aware for global deployments.';

COMMENT ON COLUMN unknown_domains.last_seen IS 
'Timestamp when domain was most recently observed. Updated on subsequent observations.';

COMMENT ON COLUMN unknown_domains.source IS 
'Origin of domain discovery. Enum type ensures data integrity and enables audit tracking.';

COMMENT ON COLUMN unknown_domains.status IS 
'Processing state for enrichment workflows. Enables queuing and progress tracking.';

COMMENT ON COLUMN unknown_domains.metadata IS 
'Extensible JSONB storage for enrichment data. Future enrichment services add structured data here.';

COMMENT ON COLUMN unknown_domains.created_at IS 
'Immutable record creation timestamp. Required for audit trails and compliance.';

COMMENT ON COLUMN unknown_domains.updated_at IS 
'Last modification timestamp. Automatically updated by trigger on record changes.';

COMMENT ON COLUMN unknown_domains.schema_version IS 
'Schema version for migration compatibility. Enables gradual rollouts and data consistency.';

-- =============================================================================
-- Grants (to be customized per deployment)
-- =============================================================================

-- Example grants - customize based on your security requirements
-- GRANT SELECT, INSERT, UPDATE ON unknown_domains TO dns_pipeline_user;
-- GRANT USAGE ON SEQUENCE unknown_domains_id_seq TO dns_pipeline_user;
-- GRANT SELECT ON recent_domains, domains_for_enrichment TO enrichment_service_user;

-- =============================================================================
-- Schema Version Record
-- =============================================================================

-- Track schema version in the database itself
CREATE TABLE IF NOT EXISTS schema_metadata (
    component VARCHAR(50) NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_metadata (component, version, description)
VALUES (
    'unknown_domain_repository',
    2,
    'Initial production schema with performance indexes and audit capabilities'
) ON CONFLICT (component) DO UPDATE SET
    version = EXCLUDED.version,
    applied_at = NOW(),
    description = EXCLUDED.description;

-- =============================================================================
-- Performance Analysis Queries (for monitoring)
-- =============================================================================

-- Table size monitoring
-- Run: SELECT * FROM table_size_info;
--
-- FIX (WARN → hardened): pg_total_relation_size() and pg_relation_size() accept
-- text or regclass.  Passing a raw string works but silently returns NULL for
-- any schema/table name that is not yet visible in the search_path.  Casting to
-- ::regclass resolves the name immediately and raises an error if the table does
-- not exist, making misconfiguration failures loud rather than silent.
CREATE VIEW table_size_info AS
SELECT
    schemaname,
    tablename,
    pg_size_pretty(
        pg_total_relation_size((schemaname || '.' || tablename)::regclass)
    ) AS total_size,
    pg_size_pretty(
        pg_relation_size((schemaname || '.' || tablename)::regclass)
    ) AS table_size,
    pg_size_pretty(
        pg_total_relation_size((schemaname || '.' || tablename)::regclass)
        - pg_relation_size((schemaname || '.' || tablename)::regclass)
    ) AS index_size
FROM pg_tables
WHERE tablename = 'unknown_domains';

-- Index usage monitoring
-- Run: SELECT * FROM index_usage_info;
--
-- FIX (BUG): pg_stat_user_indexes does NOT expose a column named "tablename".
-- The table-name column in this catalog view is "relname".
-- Using WHERE tablename = '...' raises:
--     ERROR: column "tablename" does not exist
-- Correct column mapping for pg_stat_user_indexes (PostgreSQL 14+):
--   relname       → table name  (was the bug: called "tablename" in WHERE)
--   indexrelname  → index name  (aliased to "indexname" in SELECT, which is fine)
--   idx_scan      → number of index scans
--   idx_tup_read  → index entries returned by scans
--   idx_tup_fetch → live table rows fetched via index
CREATE OR REPLACE VIEW index_usage_info AS
SELECT
    schemaname,
    relname      AS tablename,    -- relname is the real pg_stat_user_indexes column
    indexrelname AS indexname,    -- indexrelname is the real column; aliased for clarity
    idx_scan     AS index_scans,
    idx_tup_read AS tuples_read,
    idx_tup_fetch AS tuples_fetched
FROM pg_stat_user_indexes
WHERE relname = 'unknown_domains'   -- FIX: was "tablename", must be "relname"
ORDER BY idx_scan DESC;

-- =============================================================================
-- End of Schema
-- =============================================================================