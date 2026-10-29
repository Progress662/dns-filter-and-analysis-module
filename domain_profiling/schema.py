"""
Schema definition and DDL execution statements for the Domain Profiling module.

This module provides the necessary database table creation and indexing scripts
for tracking domain profiles and historical query logs.
"""

import logging
from typing import List

# Configure logger
logger = logging.getLogger("dns_threat_detection.domain_profiling.schema")


CREATE_DOMAIN_PROFILES_TABLE = """
CREATE TABLE IF NOT EXISTS domain_profiles (
    domain VARCHAR(253) PRIMARY KEY,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    total_queries BIGINT NOT NULL DEFAULT 0,
    unique_clients INTEGER NOT NULL DEFAULT 0,
    last_client_ip INET NOT NULL,
    query_a_count BIGINT NOT NULL DEFAULT 0,
    query_aaaa_count BIGINT NOT NULL DEFAULT 0,
    query_mx_count BIGINT NOT NULL DEFAULT 0,
    query_txt_count BIGINT NOT NULL DEFAULT 0,
    query_ns_count BIGINT NOT NULL DEFAULT 0,
    query_other_count BIGINT NOT NULL DEFAULT 0,
    malicious_queries BIGINT NOT NULL DEFAULT 0,
    clean_queries BIGINT NOT NULL DEFAULT 0,
    unknown_queries BIGINT NOT NULL DEFAULT 0,
    last_label VARCHAR(50),
    last_ti_source VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_DOMAIN_QUERY_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS domain_query_history (
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(253) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    query_type VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    response_code VARCHAR(20),
    registered_domain VARCHAR(253),
    tld VARCHAR(63),
    final_label VARCHAR(50),
    ti_source VARCHAR(100)
);
"""

# Indexes as per requirements: domain, timestamp, client_ip, query_type, last_seen
CREATE_INDEX_HISTORY_DOMAIN = """
CREATE INDEX IF NOT EXISTS idx_query_history_domain 
ON domain_query_history (domain);
"""

CREATE_INDEX_HISTORY_TIMESTAMP = """
CREATE INDEX IF NOT EXISTS idx_query_history_timestamp 
ON domain_query_history (timestamp);
"""

CREATE_INDEX_HISTORY_CLIENT_IP = """
CREATE INDEX IF NOT EXISTS idx_query_history_client_ip 
ON domain_query_history (client_ip);
"""

CREATE_INDEX_HISTORY_QUERY_TYPE = """
CREATE INDEX IF NOT EXISTS idx_query_history_query_type 
ON domain_query_history (query_type);
"""

CREATE_INDEX_PROFILES_LAST_SEEN = """
CREATE INDEX IF NOT EXISTS idx_domain_profiles_last_seen 
ON domain_profiles (last_seen);
"""
CREATE_INDEX_PROFILES_TOTAL_QUERIES = """
CREATE INDEX IF NOT EXISTS idx_domain_profiles_total_queries
ON domain_profiles (total_queries DESC);
"""


def get_schema_statements() -> List[str]:
    """
    Returns a list of all schema creation SQL statements in the correct order.
    
    Returns:
        List[str]: Ordered SQL statements for table and index creation.
    """
    return [
        CREATE_DOMAIN_PROFILES_TABLE,
        CREATE_DOMAIN_QUERY_HISTORY_TABLE,
        CREATE_INDEX_HISTORY_DOMAIN,
        CREATE_INDEX_HISTORY_TIMESTAMP,
        CREATE_INDEX_HISTORY_CLIENT_IP,
        CREATE_INDEX_HISTORY_QUERY_TYPE,
        CREATE_INDEX_PROFILES_LAST_SEEN,
        CREATE_INDEX_PROFILES_TOTAL_QUERIES
    ]


def create_domain_profiling_tables(conn) -> None:
    """
    Executes the schema statements against the provided database connection.
    
    Args:
        conn: A PEP 249 compliant database connection (e.g., psycopg2 connection).
    """
    logger.info("Initializing Domain Profiling schema...")
    try:
        with conn.cursor() as cursor:
            for statement in get_schema_statements():
                cursor.execute(statement)
        conn.commit()
        logger.info("Domain Profiling schema initialized successfully.")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to initialize Domain Profiling schema: {e}", exc_info=True)
        raise e
