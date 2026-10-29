"""
Service layer for the Domain Profiling module.

This module exposes high-level domain profiling and analysis APIs that integrate with
the main DNS Threat Detection Pipeline. It wraps the repository and manages business logic,
including processing incoming query dataframes and bulk transactions.
"""

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
import pandas as pd

from domain_profiling.repository import DomainProfilingRepository

# Configure logger
logger = logging.getLogger("dns_threat_detection.domain_profiling.service")


class DomainProfilingService:
    """
    Service class managing the domain profiling pipeline, lifecycle, and analytical reports.
    """

    def __init__(self, repository: Optional[DomainProfilingRepository] = None) -> None:
        """
        Initializes the service with a DomainProfilingRepository instance.
        """
        self.repository = repository or DomainProfilingRepository()

    def initialize_database(self) -> None:
        """
        Creates the domain profiling tables and indexes.
        """
        logger.info("Initializing database for Domain Profiling...")
        self.repository.initialize_database()

    def process_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Processes a normalized DataFrame of DNS queries, inserts query history,
        and batch upserts the domain profiles. This runs BEFORE labelling.
        
        Args:
            df (pd.DataFrame): Normalized DataFrame containing columns:
                - 'domain'
                - 'client_ip'
                - 'query_type'
                - 'timestamp'
                - 'response_code' (optional)
                - 'registered_domain' (optional)
                - 'tld' (optional)
                
        Returns:
            pd.DataFrame: The input DataFrame enriched with a 'history_id' column
                          representing the database primary key of each history event.
        """
        if df.empty:
            logger.warning("Empty DataFrame passed to process_dataframe. Skipping.")
            df['history_id'] = []
            return df

        # Create a copy to avoid side-effects on caller's DataFrame
        processed_df = df.copy()

        # Check for required columns
        required_cols = {'domain', 'client_ip', 'query_type', 'timestamp'}
        missing_cols = required_cols - set(processed_df.columns)
        if missing_cols:
            raise ValueError(f"Input DataFrame is missing required columns: {missing_cols}")

        # Ensure timestamp is formatted as UTC datetime
        if not pd.api.types.is_datetime64_any_dtype(processed_df['timestamp']):
            processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'], errors='coerce', utc=True)
            # Fill NaT with current time
            processed_df['timestamp'] = processed_df['timestamp'].fillna(datetime.now(timezone.utc))

        # Fill other optional columns if missing
        optional_cols = ['response_code', 'registered_domain', 'tld', 'final_label', 'ti_source']
        for col in optional_cols:
            if col not in processed_df.columns:
                processed_df[col] = None

        # Default label to 'Unknown' before DNSLabeller processes it
        processed_df['final_label'] = processed_df['final_label'].fillna('Unknown')

        # Convert DataFrame rows to query history records for database insert
        history_records = []
        for _, row in processed_df.iterrows():
            history_records.append({
                "domain": str(row['domain']).strip().lower(),
                "client_ip": str(row['client_ip']).strip(),
                "query_type": str(row['query_type']).strip().upper(),
                "timestamp": row['timestamp'].to_pydatetime() if hasattr(row['timestamp'], 'to_pydatetime') else row['timestamp'],
                "response_code": str(row['response_code']) if row['response_code'] is not None else None,
                "registered_domain": str(row['registered_domain']) if row['registered_domain'] is not None else None,
                "tld": str(row['tld']) if row['tld'] is not None else None,
                "final_label": str(row['final_label']),
                "ti_source": str(row['ti_source']) if row['ti_source'] is not None else None,
            })

        # 1. Insert history records in batch (this gets database primary key IDs)
        inserted_ids = self.repository.insert_history_batch(history_records)
        processed_df['history_id'] = inserted_ids

        # 2. Aggregate metrics per domain for batch UPSERT into domain_profiles
        grouped = processed_df.groupby('domain')
        profiles_to_upsert = []

        now_utc = datetime.now(timezone.utc)

        for domain, group in grouped:
            # Locate row with the latest timestamp to extract last client IP
            latest_idx = group['timestamp'].idxmax()
            latest_row = group.loc[latest_idx]

            q_types = group['query_type'].str.upper()

            # Group level aggregates
            profiles_to_upsert.append({
                "domain": str(domain).strip().lower(),
                "first_seen": group['timestamp'].min().to_pydatetime() if hasattr(group['timestamp'].min(), 'to_pydatetime') else group['timestamp'].min(),
                "last_seen": group['timestamp'].max().to_pydatetime() if hasattr(group['timestamp'].max(), 'to_pydatetime') else group['timestamp'].max(),
                "total_queries": len(group),
                "unique_clients": int(group['client_ip'].nunique()),
                "last_client_ip": str(latest_row['client_ip']).strip(),
                "query_a_count": int((q_types == 'A').sum()),
                "query_aaaa_count": int((q_types == 'AAAA').sum()),
                "query_mx_count": int((q_types == 'MX').sum()),
                "query_txt_count": int((q_types == 'TXT').sum()),
                "query_ns_count": int((q_types == 'NS').sum()),
                "query_other_count": int((~q_types.isin(['A', 'AAAA', 'MX', 'TXT', 'NS'])).sum()),
                "malicious_queries": 0, # Initial stage is Unknown, DNSLabeller runs later
                "clean_queries": 0,
                "unknown_queries": len(group),
                "last_label": "Unknown",
                "last_ti_source": None,
                "created_at": now_utc,
                "updated_at": now_utc
            })

        # 3. Perform batch UPSERT
        self.repository.upsert_domain_profiles_batch(profiles_to_upsert)

        logger.info(f"DataFrame processing complete. Profiling completed for {len(profiles_to_upsert)} domains.")
        return processed_df

    def upsert_domain(self, domain_data: Dict[str, Any]) -> None:
        """
        Manually upserts a single domain's profiling information.
        
        Args:
            domain_data (Dict[str, Any]): Dictionary of domain profile fields.
        """
        self.repository.upsert_domain_profiles_batch([domain_data])

    def insert_history(self, history_data: Dict[str, Any]) -> int:
        """
        Manually inserts a single historical query log.
        
        Args:
            history_data (Dict[str, Any]): Dictionary of history log fields.
            
        Returns:
            int: The primary key of the inserted history row.
        """
        ids = self.repository.insert_history_batch([history_data])
        return ids[0] if ids else -1

    def update_final_labels(self, label_data: Union[pd.DataFrame, List[Dict[str, Any]]]) -> None:
        """
        Updates final labels and threat intelligence sources for processed histories,
        re-evaluating profiles based on labeling results.
        
        This should be executed AFTER the labeling stage in the pipeline.
        
        Args:
            label_data (Union[pd.DataFrame, List[Dict[str, Any]]]): Accepts either:
                - A pandas DataFrame containing 'history_id', 'domain', 'final_label', and optional 'ti_source'.
                - A list of dictionary objects structured as:
                  [{'history_ids': [1, 2, ...], 'domain': 'example.com', 'final_label': 'Malicious', 'ti_source': 'URLHaus'}]
        """
        if isinstance(label_data, pd.DataFrame):
            if label_data.empty:
                logger.warning("Empty DataFrame passed to update_final_labels. Skipping.")
                return
            
            # Ensure required columns are present
            required = {'history_id', 'domain', 'final_label'}
            if not required.issubset(label_data.columns):
                raise ValueError(f"Labeling DataFrame must contain columns: {required}")

            # Fill missing source column if absent
            if 'ti_source' not in label_data.columns:
                label_data['ti_source'] = None

            # Group the updates by domain and label to update in optimized batch blocks
            grouped = label_data.groupby(['domain', 'final_label', 'ti_source'], dropna=False)
            updates = []
            for (domain, label, source), group in grouped:
                updates.append({
                    "history_ids": group['history_id'].astype(int).tolist(),
                    "domain": str(domain),
                    "final_label": str(label),
                    "ti_source": str(source) if pd.notna(source) else None
                })
            
            self.repository.update_final_labels_batch(updates)
        else:
            self.repository.update_final_labels_batch(label_data)

    def cleanup_old_history(self, retention_days: int = 30) -> int:
        """
        Deletes domain query logs older than specified days.
        Does not touch domain profiles.
        
        Args:
            retention_days (int): Period in days. Defaults to 30.
            
        Returns:
            int: Number of deleted rows.
        """
        return self.repository.cleanup_old_history(retention_days)

    def get_domain_profile(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves the profile of a single domain.
        
        Args:
            domain (str): The target domain.
            
        Returns:
            Optional[Dict[str, Any]]: Profile metrics if found.
        """
        return self.repository.get_domain_profile(domain.strip().lower())

    def get_top_domains(self, limit: int = 10, today_only: bool = False) -> List[Dict[str, Any]]:
        """
        Retrieves top queried domains.
        
        Args:
            limit (int): Limit results.
            today_only (bool): If True, aggregates queries over the last 24 hours.
            
        Returns:
            List[Dict[str, Any]]: Most active domains.
        """
        return self.repository.get_top_domains(limit, today_only)

    def get_domain_statistics(self) -> Dict[str, Any]:
        """
        Retrieves global metrics of domain profiling.
        
        Returns:
            Dict[str, Any]: Row counts and aggregates.
        """
        return self.repository.get_database_statistics()

    def get_domains_in_last_hour(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves domains queried in the last hour.
        """
        return self.repository.get_domains_by_last_seen(limit=limit, hours=1)

    def get_domains_in_last_day(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves domains queried in the last 24 hours.
        """
        return self.repository.get_domains_by_last_seen(limit=limit, hours=24)

    def get_domains_in_last_week(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves domains queried in the last 7 days.
        """
        return self.repository.get_domains_by_last_seen(limit=limit, hours=168)
