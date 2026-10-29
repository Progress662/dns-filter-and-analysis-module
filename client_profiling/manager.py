"""
Core client profiling logic

Handles the insertion and updating of client profiles and their query history.
Uses PostgreSQL UPSERT for efficient, atomic operations.
"""

import logging
from datetime import datetime
from .db import get_pool

logger = logging.getLogger(__name__)

# UPSERT for client_profiles
# If client exists, update last_seen. Otherwise, insert new client.
UPSERT_CLIENT = """
INSERT INTO client_profiles (client_ip, first_seen, last_seen)
VALUES (%s, %s, %s)
ON CONFLICT (client_ip)
DO UPDATE SET
    last_seen = EXCLUDED.last_seen;
"""

# UPSERT for client_history
# If (client_ip, domain) exists, increment visit_count and update last_seen.
# Otherwise, insert new record.
UPSERT_HISTORY = """
INSERT INTO client_history (client_ip, domain, first_seen, last_seen, visit_count)
VALUES (%s, %s, %s, %s, 1)
ON CONFLICT (client_ip, domain)
DO UPDATE SET
    last_seen = EXCLUDED.last_seen,
    visit_count = client_history.visit_count + 1;
"""


def process_query(client_ip, domain):
    """
    Process a single DNS query.
    
    This is the main entry point for the module. Call this function
    whenever a DNS query is parsed from the logs.
    
    This function:
    1. Creates/updates the client profile
    2. Creates/updates the domain history for that client
    3. Updates all timestamps
    4. Increments visit count
    
    All operations are performed in a single transaction for atomicity.
    
    Args:
        client_ip (str): The client's IP address (e.g., "192.168.1.39")
        domain (str): The queried domain (e.g., "huggingface.co")
        
    Raises:
        ValueError: If client_ip or domain is invalid
        Exception: If database operation fails
    """
    # Input validation
    if not client_ip or not isinstance(client_ip, str):
        raise ValueError(f"Invalid client_ip: {client_ip}")
    
    if not domain or not isinstance(domain, str):
        raise ValueError(f"Invalid domain: {domain}")
    
    # Normalize domain (lowercase)
    domain = domain.lower().strip()
    client_ip = client_ip.strip()
    
    # Current timestamp
    now = datetime.now()
    
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                # Begin transaction (implicit with context manager)
                
                # 1. UPSERT client profile
                cur.execute(UPSERT_CLIENT, (client_ip, now, now))
                
                # 2. UPSERT domain history
                cur.execute(UPSERT_HISTORY, (client_ip, domain, now, now))
                
                # Commit transaction
                conn.commit()
                
                logger.debug(
                    f"Processed query: client={client_ip}, domain={domain}"
                )
                
    except Exception as e:
        logger.error(
            f"Failed to process query (client={client_ip}, domain={domain}): {e}"
        )
        raise


def get_client_profile(client_ip):
    """
    Retrieve a client's profile.
    
    This is a utility function for debugging or reporting.
    Not required for normal operation.
    
    Args:
        client_ip (str): The client's IP address
        
    Returns:
        dict: Client profile with keys: client_ip, first_seen, last_seen
        None: If client not found
    """
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT client_ip, first_seen, last_seen
                    FROM client_profiles
                    WHERE client_ip = %s
                    """,
                    (client_ip,)
                )
                
                row = cur.fetchone()
                
                if row:
                    return {
                        "client_ip": str(row[0]),
                        "first_seen": row[1],
                        "last_seen": row[2],
                    }
                return None
                
    except Exception as e:
        logger.error(f"Failed to get client profile: {e}")
        raise


def get_client_history(client_ip, limit=100):
    """
    Retrieve a client's query history.
    
    This is a utility function for debugging or reporting.
    Not required for normal operation.
    
    Args:
        client_ip (str): The client's IP address
        limit (int): Maximum number of records to return
        
    Returns:
        list: List of dicts containing domain history
    """
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT domain, first_seen, last_seen, visit_count
                    FROM client_history
                    WHERE client_ip = %s
                    ORDER BY last_seen DESC
                    LIMIT %s
                    """,
                    (client_ip, limit)
                )
                
                rows = cur.fetchall()
                
                return [
                    {
                        "domain": row[0],
                        "first_seen": row[1],
                        "last_seen": row[2],
                        "visit_count": row[3],
                    }
                    for row in rows
                ]
                
    except Exception as e:
        logger.error(f"Failed to get client history: {e}")
        raise