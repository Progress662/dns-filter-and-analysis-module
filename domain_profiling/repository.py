"""
Repository layer for the Domain Profiling module.

This module encapsulates all direct database operations (INSERT, UPSERT, SELECT, DELETE)
for domain profiles and query histories using prepared SQL, batching, and connection pooling.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import psycopg2
import psycopg2.extras

from domain_profiling.connection import get_db_connection, get_db_cursor
from domain_profiling.schema import create_domain_profiling_tables

# Configure logger
logger = logging.getLogger("dns_threat_detection.domain_profiling.repository")


class DomainProfilingRepository:
    """
    Repository handling all persistence and analytical query logic for
    domain profiles and query history.
    """

    def __init__(self) -> None:
        pass

    def initialize_database(self) -> None:
        """
        Initializes the schema (tables, types, and indexes) in the database.
        """
        logger.info("Initializing database schema via repository...")
        with get_db_connection() as conn:
            create_domain_profiling_tables(conn)

    def insert_history_batch(self, records: List[Dict[str, Any]]) -> List[int]:
        """
        Performs high-performance batch insertion of DNS query history records.
        
        Args:
            records (List[Dict[str, Any]]): List of dictionary representations of query history.
            
        Returns:
            List[int]: Generated database IDs of the inserted query history rows.
        """
        if not records:
            return []

        logger.info(f"Inserting batch of {len(records)} query history records...")
        
        # SQL statement using psycopg2.extras.execute_values
        query = """
            INSERT INTO domain_query_history (
                domain, client_ip, query_type, timestamp, response_code,
                registered_domain, tld, final_label, ti_source
            ) VALUES %s
            RETURNING id;
        """

        # Convert dictionary values to tuple of parameters in order
        value_tuples = [
            (
                r.get("domain"),
                r.get("client_ip"),
                (r.get("query_type") or "OTHER").upper(),
                r.get("timestamp", datetime.now(timezone.utc)),
                r.get("response_code"),
                r.get("registered_domain"),
                r.get("tld"),
                r.get("final_label", "Unknown"),
                r.get("ti_source")
            )
            for r in records
        ]

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                psycopg2.extras.execute_values(
                    cursor,
                    query,
                    value_tuples,
                    template=None,
                    page_size=1000
                )
                inserted_ids = [row[0] for row in cursor.fetchall()]
            conn.commit()
            logger.info(f"Successfully inserted {len(inserted_ids)} history records.")
            return inserted_ids

    def upsert_domain_profiles_batch(self, profiles: List[Dict[str, Any]]) -> None:
        """
        Performs high-performance batch UPSERT of domain profile records.
        Increments total queries and specific query type counters, updates timestamps and IP.
        
        Args:
            profiles (List[Dict[str, Any]]): List of dictionary representations of domain updates.
        """
        if not profiles:
            return

        logger.info(f"Upserting batch of {len(profiles)} domain profiles...")

        # SQL query using standard UPSERT structure
        query = """
            INSERT INTO domain_profiles (
                domain, first_seen, last_seen, total_queries, unique_clients, last_client_ip,
                query_a_count, query_aaaa_count, query_mx_count, query_txt_count, query_ns_count, query_other_count,
                malicious_queries, clean_queries, unknown_queries, last_label, last_ti_source, created_at, updated_at
            ) VALUES %s
            ON CONFLICT (domain) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                total_queries = domain_profiles.total_queries + EXCLUDED.total_queries,
                unique_clients = GREATEST(
                    domain_profiles.unique_clients,
                    EXCLUDED.unique_clients
                ),
                last_client_ip = EXCLUDED.last_client_ip,
                query_a_count = domain_profiles.query_a_count + EXCLUDED.query_a_count,
                query_aaaa_count = domain_profiles.query_aaaa_count + EXCLUDED.query_aaaa_count,
                query_mx_count = domain_profiles.query_mx_count + EXCLUDED.query_mx_count,
                query_txt_count = domain_profiles.query_txt_count + EXCLUDED.query_txt_count,
                query_ns_count = domain_profiles.query_ns_count + EXCLUDED.query_ns_count,
                query_other_count = domain_profiles.query_other_count + EXCLUDED.query_other_count,
                malicious_queries = domain_profiles.malicious_queries + EXCLUDED.malicious_queries,
                clean_queries = domain_profiles.clean_queries + EXCLUDED.clean_queries,
                unknown_queries = domain_profiles.unknown_queries + EXCLUDED.unknown_queries,
                last_label = COALESCE(EXCLUDED.last_label, domain_profiles.last_label),
                last_ti_source = COALESCE(EXCLUDED.last_ti_source, domain_profiles.last_ti_source),
                updated_at = EXCLUDED.updated_at;
        """

        value_tuples = [
            (
                p.get("domain"),
                p.get("first_seen", datetime.now(timezone.utc)),
                p.get("last_seen", datetime.now(timezone.utc)),
                p.get("total_queries", 1),
                p.get("unique_clients", 1),
                p.get("last_client_ip"),
                p.get("query_a_count", 0),
                p.get("query_aaaa_count", 0),
                p.get("query_mx_count", 0),
                p.get("query_txt_count", 0),
                p.get("query_ns_count", 0),
                p.get("query_other_count", 0),
                p.get("malicious_queries", 0),
                p.get("clean_queries", 0),
                p.get("unknown_queries", 0),
                p.get("last_label"),
                p.get("last_ti_source"),
                p.get("created_at", datetime.now(timezone.utc)),
                p.get("updated_at", datetime.now(timezone.utc))
            )
            for p in profiles
        ]

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                psycopg2.extras.execute_values(
                    cursor,
                    query,
                    value_tuples,
                    template=None,
                    page_size=1000
                )
            conn.commit()
            logger.info(f"Successfully upserted {len(profiles)} domain profiles.")

    def update_final_labels_batch(self, label_updates: List[Dict[str, Any]]) -> None:
        """
        Updates the final label and threat intelligence sources for query histories,
        and subsequently adjusts label counts and the last label in domain_profiles.
        
        Args:
            label_updates (List[Dict[str, Any]]): List of dicts, each with:
                - 'history_ids': List[int] (The primary keys from domain_query_history)
                - 'domain': str
                - 'final_label': str ('Trusted', 'Clean', 'Unknown', 'Malicious')
                - 'ti_source': Optional[str]
        """
        if not label_updates:
            return

        logger.info(f"Updating final labels for {len(label_updates)} label batches...")
        
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                for item in label_updates:
                    history_ids = item.get("history_ids")
                    domain = item.get("domain")
                    final_label = item.get("final_label", "Unknown")
                    ti_source = item.get("ti_source")

                    if not history_ids or not domain:
                        continue

                    # 1. Update domain_query_history for specific processed IDs
                    update_history_sql = """
                        UPDATE domain_query_history
                        SET final_label = %s,
                            ti_source = %s
                        WHERE id = ANY(%s);
                    """
                    cursor.execute(update_history_sql, (final_label, ti_source, history_ids))

                    # Count how many labels of this type were assigned in this batch
                    increment_count = len(history_ids)

                    # Determine label counter increment column
                    label_col = "unknown_queries"
                    if final_label == "Malicious":
                        label_col = "malicious_queries"
                    elif final_label in ("Clean", "Trusted"):
                        label_col = "clean_queries"

                    # 2. Update domain_profiles counts and last seen label/threat-intel
                    update_profile_sql = f"""
                        UPDATE domain_profiles
                        SET {label_col} = {label_col} + %s,
                            last_label = %s,
                            last_ti_source = %s,
                            updated_at = %s
                        WHERE domain = %s;
                    """
                    cursor.execute(
                        update_profile_sql, 
                        (increment_count, final_label, ti_source, datetime.now(timezone.utc), domain)
                    )
            conn.commit()
            logger.info("Successfully updated final labels across query history and profiles.")

    def cleanup_old_history(self, retention_days: int = 30) -> int:
        """
        Deletes domain query histories older than the retention threshold.
        Does not touch domain profiles.
        
        Args:
            retention_days (int): Cutoff duration in days. Defaults to 30.
            
        Returns:
            int: Number of deleted history rows.
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        logger.info(f"Cleaning up historical queries older than {retention_days} days (cutoff: {cutoff_date})...")

        query = "DELETE FROM domain_query_history WHERE timestamp < %s;"
        
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, (cutoff_date,))
                deleted_rows = cursor.rowcount
            conn.commit()
            logger.info(f"Cleanup finished. Removed {deleted_rows} historical query rows.")
            return deleted_rows

    def get_domain_profile(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a detailed profile for a specific domain.
        
        Args:
            domain (str): The domain to query.
            
        Returns:
            Optional[Dict[str, Any]]: The domain profile fields, or None if not found.
        """
        query = "SELECT * FROM domain_profiles WHERE domain = %s;"
        
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query, (domain,))
                row = cursor.fetchone()
                return dict(row) if row else None

    def get_top_domains(self, limit: int = 10, today_only: bool = False) -> List[Dict[str, Any]]:
        """
        Retrieves the most queried domains.
        
        Args:
            limit (int): Max number of results.
            today_only (bool): If True, filters queries to the last 24 hours.
            
        Returns:
            List[Dict[str, Any]]: List of top-queried domains.
        """
        if today_only:
            # Query history table for counts in the last 24 hours
            since_time = datetime.now(timezone.utc) - timedelta(hours=24)
            query = """
                SELECT domain, COUNT(*) as query_count
                FROM domain_query_history
                WHERE timestamp >= %s
                GROUP BY domain
                ORDER BY query_count DESC
                LIMIT %s;
            """
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(query, (since_time, limit))
                    return [dict(r) for r in cursor.fetchall()]
        else:
            # Query domain_profiles directly for lifetime count
            query = """
                SELECT domain, total_queries as query_count, last_label
                FROM domain_profiles
                ORDER BY total_queries DESC
                LIMIT %s;
            """
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute(query, (limit,))
                    return [dict(r) for r in cursor.fetchall()]

    def get_domains_by_last_seen(self, limit: int = 100, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Retrieves domains seen in a specific historical window.
        
        Args:
            limit (int): Max results.
            hours (int): Hour interval window.
            
        Returns:
            List[Dict[str, Any]]: Matching domain profiles.
        """
        since_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        query = """
            SELECT * FROM domain_profiles
            WHERE last_seen >= %s
            ORDER BY last_seen DESC
            LIMIT %s;
        """
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query, (since_time, limit))
                return [dict(r) for r in cursor.fetchall()]

    def get_most_queried_by_label(self, label: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieves most queried domains filtered by a specific label (Malicious, Unknown, etc.).
        
        Args:
            label (str): The label filter (e.g. 'Malicious', 'Unknown', 'Clean').
            limit (int): Max results.
            
        Returns:
            List[Dict[str, Any]]: Matching top profiles.
        """
        # Determine counter to order by
        order_col = "total_queries"
        if label == "Malicious":
            order_col = "malicious_queries"
        elif label == "Unknown":
            order_col = "unknown_queries"
        elif label in ("Clean", "Trusted"):
            order_col = "clean_queries"

        query = f"""
            SELECT domain, {order_col} as label_query_count, total_queries, last_label
            FROM domain_profiles
            WHERE last_label = %s OR {order_col} > 0
            ORDER BY {order_col} DESC
            LIMIT %s;
        """
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query, (label, limit))
                return [dict(r) for r in cursor.fetchall()]

    def get_top_unique_client_domains(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieves domains queried by the largest number of unique clients.
        
        Args:
            limit (int): Max results.
            
        Returns:
            List[Dict[str, Any]]: List of domains ordered by unique clients count.
        """
        query = """
            SELECT domain, unique_clients, total_queries, last_label
            FROM domain_profiles
            ORDER BY unique_clients DESC, total_queries DESC
            LIMIT %s;
        """
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query, (limit,))
                return [dict(r) for r in cursor.fetchall()]

    def get_domains_by_client_ip(self, client_ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves queries and domains logged for a specific client IP address.
        
        Args:
            client_ip (str): Client IP address.
            limit (int): Max results.
            
        Returns:
            List[Dict[str, Any]]: Queries of the client.
        """
        query = """
            SELECT DISTINCT domain, COUNT(*) as query_count, MAX(timestamp) as last_query_time
            FROM domain_query_history
            WHERE client_ip = %s
            GROUP BY domain
            ORDER BY query_count DESC, last_query_time DESC
            LIMIT %s;
        """
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query, (client_ip, limit))
                return [dict(r) for r in cursor.fetchall()]

    def get_query_type_distribution(self) -> Dict[str, int]:
        """
        Computes the lifetime query type distribution aggregated across all profiles.
        
        Returns:
            Dict[str, int]: Mapping of query type names to lifetime counts.
        """
        query = """
            SELECT 
                SUM(query_a_count) as A,
                SUM(query_aaaa_count) as AAAA,
                SUM(query_mx_count) as MX,
                SUM(query_txt_count) as TXT,
                SUM(query_ns_count) as NS,
                SUM(query_other_count) as OTHER
            FROM domain_profiles;
        """
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(query)
                row = cursor.fetchone()
                if row:
                    return {k: int(v or 0) for k, v in row.items()}
                return {"A": 0, "AAAA": 0, "MX": 0, "TXT": 0, "NS": 0, "OTHER": 0}

    def get_database_statistics(self) -> Dict[str, Any]:
        """
        Retrieves high-level summary statistics of the profiling tables.
        
        Returns:
            Dict[str, Any]: Basic metrics including row counts and totals.
        """
        stats = {}
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Count total domain profiles
                cursor.execute("SELECT COUNT(*) FROM domain_profiles;")
                stats["total_profiled_domains"] = cursor.fetchone()[0]

                # Count history records
                cursor.execute("SELECT COUNT(*) FROM domain_query_history;")
                stats["total_historical_queries"] = cursor.fetchone()[0]

                # Aggregate query category counts
                cursor.execute("""
                    SELECT 
                        SUM(malicious_queries) as malicious,
                        SUM(clean_queries) as clean,
                        SUM(unknown_queries) as unknown
                    FROM domain_profiles;
                """)
                row = cursor.fetchone()
                if row:
                    stats["total_malicious_queries_logged"] = int(row[0] or 0)
                    stats["total_clean_queries_logged"] = int(row[1] or 0)
                    stats["total_unknown_queries_logged"] = int(row[2] or 0)
                else:
                    stats["total_malicious_queries_logged"] = 0
                    stats["total_clean_queries_logged"] = 0
                    stats["total_unknown_queries_logged"] = 0

        return stats
