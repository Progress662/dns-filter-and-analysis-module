-- DNS Client Profiling Database Schema
-- This schema maintains profiles for DNS clients and their query history

-- Table 1: Client Profiles
-- Stores metadata about each unique client IP
CREATE TABLE IF NOT EXISTS client_profiles (
    client_ip INET PRIMARY KEY,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Table 2: Client History
-- Stores unique domains queried by each client with visit statistics
CREATE TABLE IF NOT EXISTS client_history (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL,
    domain VARCHAR(255) NOT NULL,
    first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
    visit_count INTEGER NOT NULL DEFAULT 1,
    
    -- Foreign key relationship
    CONSTRAINT fk_client
        FOREIGN KEY(client_ip)
        REFERENCES client_profiles(client_ip)
        ON DELETE CASCADE,
    
    -- Enforce uniqueness: one row per (client_ip, domain) pair
    CONSTRAINT unique_client_domain
        UNIQUE(client_ip, domain)
);

-- Performance Indexes
-- Index on client_ip for fast lookups of client history
CREATE INDEX IF NOT EXISTS idx_client_history_client_ip 
    ON client_history(client_ip);

-- Index on last_seen for efficient cleanup operations
CREATE INDEX IF NOT EXISTS idx_client_history_last_seen 
    ON client_history(last_seen);

-- Index on domain for potential future queries
CREATE INDEX IF NOT EXISTS idx_client_history_domain 
    ON client_history(domain);

-- Composite index for the most common query pattern
CREATE INDEX IF NOT EXISTS idx_client_history_client_domain 
    ON client_history(client_ip, domain);

-- Comment documentation
COMMENT ON TABLE client_profiles IS 'Stores metadata for each unique DNS client';
COMMENT ON TABLE client_history IS 'Stores domain query history for each client';
COMMENT ON COLUMN client_history.visit_count IS 'Number of times client queried this domain';