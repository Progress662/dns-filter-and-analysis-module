-- =============================================================================
-- Migration 001: Initial Schema Creation
-- Version: 2.0
-- Description: Creates the core unknown_domains table with constraints
-- =============================================================================

BEGIN;

-- =============================================================================
-- Custom Types for Domain Classification
-- =============================================================================

-- Domain source enumeration tracks where domains originate
CREATE TYPE domain_source AS ENUM (
    'dns_query_log',    -- From Bind9 DNS query logs (primary)
    'manual_import',    -- Manually imported via admin scripts
    'system_test'       -- Test/development data only
);

-- Domain status enumeration tracks processing state
-- Currently only supports 'new'; future states reserved for enrichment
CREATE TYPE domain_status AS ENUM (
    'new'              -- Freshly inserted, awaiting enrichment services
    'processing',
    'malicious',
    'clean',
    'review_needed',
    'error'
);

-- =============================================================================
-- Core Table: unknown_domains
-- =============================================================================

-- This table stores domains not found in known threat intelligence databases.
-- It serves as a staging area for future enrichment by external services.

CREATE TABLE IF NOT EXISTS unknown_domains (
    -- Primary key using BIGINT for support up to 9.2 quintillion rows
    id BIGSERIAL PRIMARY KEY,
    
    -- Core domain data (normalized per RFC 1035)
    domain VARCHAR(253) NOT NULL,
    
    -- Temporal tracking for timeline analysis
    first_seen TIMESTAMPTZ NOT NULL,   -- When domain was first encountered
    last_seen TIMESTAMPTZ NOT NULL,    -- When most recently observed
    
    -- Classification metadata
    source domain_source NOT NULL DEFAULT 'dns_query_log',
    status domain_status NOT NULL DEFAULT 'new',
    
    -- Extensible JSON storage for future enrichment data
    metadata JSONB,                    -- NULL until enriched
    
    -- Audit trail columns
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Record creation timestamp
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- Last modification timestamp
    
    -- Migration tracking
    schema_version INTEGER NOT NULL DEFAULT 2     -- Schema version at insertion time
);

-- =============================================================================
-- Data Integrity Constraints
-- =============================================================================

-- Unique constraint on domain name enables UPSERT operations and deduplication
ALTER TABLE unknown_domains 
ADD CONSTRAINT uq_unknown_domains_domain UNIQUE (domain);

-- Ensure timestamps maintain temporal consistency
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_temporal_order 
CHECK (last_seen >= first_seen);

-- Ensure audit trail integrity  
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_audit_order 
CHECK (updated_at >= created_at);

-- Validate domain format (RFC-compliant basics, full validation in application layer)
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_domain_format 
CHECK (
    domain ~ '^[a-z0-9.-]+$' AND           -- Only lowercase alphanumerics, dots, hyphens
    length(domain) >= 3 AND                 -- Minimum reasonable length
    length(domain) <= 253 AND               -- RFC 1035 maximum
    domain NOT LIKE '.%' AND                -- Cannot start with dot
    domain NOT LIKE '%.' AND                -- Cannot end with dot
    domain NOT LIKE '%..%'                  -- No consecutive dots
);

-- Limit metadata size to prevent abuse (1MB should suffice for enrichment data)
ALTER TABLE unknown_domains 
ADD CONSTRAINT ck_unknown_domains_metadata_size 
CHECK (
    pg_column_size(metadata) <= 1048576 OR 
    metadata IS NULL
);

-- =============================================================================
-- Automatic Timestamp Updates
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger ensures updated_at is always current on row modifications
CREATE TRIGGER trg_unknown_domains_updated_at
    BEFORE UPDATE ON unknown_domains
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Schema Metadata Table (Tracks Applied Migrations)
-- =============================================================================

CREATE TABLE IF NOT EXISTS schema_metadata (
    component VARCHAR(50) NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT,
    checksum VARCHAR(64)           -- SHA256 hash of this migration script
);

INSERT INTO schema_metadata (component, version, description)
VALUES (
    'unknown_domain_repository',
    1,
    'Initial schema creation with core table and constraints'
) ON CONFLICT (component) DO UPDATE SET
    version = EXCLUDED.version,
    applied_at = NOW(),
    description = EXCLUDED.description;

COMMIT;

-- =============================================================================
-- Verification Query (should return "Migration 001 applied successfully")
-- =============================================================================
SELECT 'Migration 001 applied successfully' AS result;