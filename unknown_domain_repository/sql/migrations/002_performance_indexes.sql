-- =============================================================================
-- Migration 002: Performance Optimization Indexes
-- Version: 2.0  
-- Description: Adds strategic indexes for production-scale query patterns
-- =============================================================================

BEGIN;

-- =============================================================================
-- Primary Access Pattern Indexes
-- =============================================================================

-- Unique domain lookup index (required by UPSERT operations)
CREATE UNIQUE INDEX IF NOT EXISTS idx_unknown_domains_domain 
ON unknown_domains (domain);

-- Temporal range query support (for time-based analytics)
CREATE INDEX IF NOT EXISTS idx_unknown_domains_first_seen 
ON unknown_domains (first_seen);

CREATE INDEX IF NOT EXISTS idx_unknown_domains_last_seen 
ON unknown_domains (last_seen);

-- =============================================================================
-- Enrichment Workflow Indexes
-- =============================================================================

-- Status-based filtering (for finding domains needing processing)
CREATE INDEX IF NOT EXISTS idx_unknown_domains_status 
ON unknown_domains (status);

-- Composite index for efficient status + temporal queries
-- Example: "Find all 'new' domains in the last 24 hours"
CREATE INDEX IF NOT EXISTS idx_unknown_domains_status_first_seen 
ON unknown_domains (status, first_seen);

-- Source tracking (for audit/debugging queries)
CREATE INDEX IF NOT EXISTS idx_unknown_domains_source 
ON unknown_domains (source);

-- =============================================================================
-- Metadata Search Index (JSONB GIN)
-- =============================================================================

-- Enables fast search within enrichment metadata JSON
-- Required by btree_gin extension (created in migration 001)
CREATE INDEX IF NOT EXISTS idx_unknown_domains_metadata_gin 
ON unknown_domains USING GIN (metadata);

-- =============================================================================
-- Pagination and Ordering Support
-- =============================================================================

-- Supports paginated results ordered by ID and creation time
CREATE INDEX IF NOT EXISTS idx_unknown_domains_id_created_at 
ON unknown_domains (id, created_at);

-- Migration tracking
CREATE INDEX IF NOT EXISTS idx_unknown_domains_schema_version 
ON unknown_domains (schema_version);

-- =============================================================================
-- Table Statistics Configuration
-- =============================================================================

-- Increase statistics target for frequently queried columns
ALTER TABLE unknown_domains ALTER COLUMN domain SET STATISTICS 1000;
ALTER TABLE unknown_domains ALTER COLUMN first_seen SET STATISTICS 1000;
ALTER TABLE unknown_domains ALTER COLUMN last_seen SET STATISTICS 1000;
ALTER TABLE unknown_columns ALTER COLUMN status SET STATISTICS 100;

-- =============================================================================
-- Storage Optimization Settings
-- =============================================================================

-- Set fillfactor to leave room for UPDATEs without page splits
ALTER TABLE unknown_domains SET (fillfactor = 90);

-- Enable parallel query execution for large table scans
ALTER TABLE unknown_domains SET (parallel_workers = 4);

-- =============================================================================
-- Update Schema Metadata
-- =============================================================================

INSERT INTO schema_metadata (component, version, description)
VALUES (
    'unknown_domain_repository',
    2,
    'Performance indexes added for production query patterns'
) ON CONFLICT (component) DO UPDATE SET
    version = EXCLUDED.version,
    applied_at = NOW(),
    description = EXCLUDED.description;

COMMIT;

-- =============================================================================
-- Verification Query
-- =============================================================================
SELECT 
    count(*) as total_indexes,
    array_agg(indexname) as index_names
FROM pg_indexes
WHERE tablename = 'unknown_domains';