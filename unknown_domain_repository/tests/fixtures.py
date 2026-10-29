"""
Test data factories and helper functions for generating test datasets.
Provides reusable fixtures for generating domains, database rows, and statistics.
"""

import random
import string
import hashlib
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

import pandas as pd

# Import after path setup (assuming conftest.py runs first)
from unknown_domain_repository.models import (
    UnknownDomain,
    DomainBatch,
    DomainStatus,
    DomainSource
)


class TestDataGenerator:
    """
    Factory class for generating deterministic test data.
    All generation methods use seed-based randomness for reproducibility.
    """
    
    @staticmethod
    def generate_domain(
        length: int = None,
        tld: str = ".com",
        prefix: str = "test",
        seed: int = None
    ) -> str:
        """
        Generate a random but valid domain name.
        
        Args:
            length: Total domain length (None for random between 8-25 chars).
            tld: Top-level domain to use.
            prefix: Prefix string for domain name.
            seed: Random seed for reproducibility.
            
        Returns:
            Valid domain name string.
        """
        rng = random.Random(seed) if seed is not None else random.Random()
        
        if length is None:
            subdomain_length = rng.randint(8, 25)
        else:
            # Account for tld and dot in total length
            subdomain_length = max(3, len(tld) + 1, length - len(tld) - 1)
            
        # Generate random alphanumeric characters
        chars = string.ascii_lowercase + string.digits
        subdomain = ''.join(rng.choice(chars) for _ in range(subdomain_length))
        
        # Ensure doesn't start with digit or hyphen
        if subdomain[0].isdigit() or subdomain[0] == '-':
            subdomain = 'a' + subdomain[1:]
        
        domain = f"{prefix}-{subdomain}{tld}"
        return domain.lower()
    
    @staticmethod
    def generate_unique_domains(
        count: int,
        base_tlds: Tuple[str, ...] = ('.com', '.org', '.net', '.io', '.co'),
        seed: int = 42
    ) -> List[str]:
        """
        Generate multiple unique domain names deterministically.
        
        Args:
            count: Number of unique domains to generate.
            base_tlds: Allowed TLDs to use.
            seed: Seed for reproducible generation.
            
        Returns:
            List of unique domain name strings.
        """
        rng = random.Random(seed)
        domains_seen = set()
        domains = []
        attempts = 0
        max_attempts = count * 100  # Prevent infinite loop
        
        while len(domains) < count and attempts < max_attempts:
            domain = TestDataGenerator.generate_domain(
                tld=rng.choice(base_tlds),
                prefix=rng.choice(['alpha', 'beta', 'gamma', 'delta']),
                seed=rng.randint(1, 10000)
            )
            
            if domain not in domains_seen:
                domains_seen.add(domain)
                domains.append(domain)
            
            attempts += 1
        
        return domains
    
    @staticmethod
    def create_unknown_domain(
        domain_name: str = None,
        days_ago: int = 0,
        hours_ago: int = 0,
        source: DomainSource = DomainSource.DNS_QUERY_LOG,
        status: DomainStatus = DomainStatus.NEW,
        metadata: Optional[Dict[str, Any]] = None,
        has_id: bool = False
    ) -> UnknownDomain:
        """
        Create an UnknownDomain entity with configurable parameters.
        
        Args:
            domain_name: Domain name (auto-generated if None).
            days_ago: How many days ago domain was first seen.
            hours_ago: Additional hours offset for last_seen.
            source: Source of the domain.
            status: Processing status.
            metadata: Metadata dictionary.
            has_id: Whether to assign a simulated DB ID.
            
        Returns:
            Configured UnknownDomain instance.
        """
        if domain_name is None:
            domain_name = TestDataGenerator.generate_domain(seed=hash(str(days_ago)))
        
        now = datetime.now(timezone.utc)
        first_seen = now - timedelta(days=days_ago, hours=hours_ago)
        last_seen = first_seen + timedelta(hours=max(hours_ago, 1))  # After first_seen
        
        kwargs = {
            'domain': domain_name,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'source': source,
            'status': status,
            'metadata': metadata
        }
        
        if has_id:
            kwargs['id'] = hash(domain_name) % 1000000  # Pseudo-ID
            kwargs['created_at'] = first_seen
            kwargs['updated_at'] = last_seen
        
        return UnknownDomain(**kwargs)
    
    @staticmethod
    def create_batch_of_domains(
        count: int = 20,
        start_days_ago: int = 7,
        end_days_ago: int = 0,
        mix_sources: bool = True,
        mix_statuses: bool = False,
        seed: int = 42
    ) -> List[UnknownDomain]:
        """
        Create batch of domains with varied timestamps and sources.
        
        Args:
            count: Number of domains in batch.
            start_days_ago: Oldest timestamp offset.
            end_days_ago: Most recent timestamp offset.
            mix_sources: Use different source types.
            mix_statuses: Use different statuses (mostly NEW).
            seed: Generation seed.
            
        Returns:
            List of UnknownDomain instances.
        """
        rng = random.Random(seed)
        domains = []
        sources = [DomainSource.DNS_QUERY_LOG] if not mix_sources else list(DomainSource)
        statuses = [DomainStatus.NEW]
        if mix_statuses:
            statuses.extend(list(DomainStatus)[1:])  # Add future statuses if exist
        
        for i in range(count):
            domain_name = TestDataGenerator.generate_domain(
                prefix=f'batch-{i}',
                seed=rng.randint(1000, 9999)
            )
            
            # Distribute dates evenly across range
            day_offset = rng.uniform(start_days_ago, end_days_ago)
            hour_offset = rng.uniform(0, 23)
            
            source = rng.choice(sources)
            status = rng.choices(statuses, weights=[90, 5, 3, 2][:len(statuses)])[0]
            if not mix_statuses:
                status = DomainStatus.NEW
                
            metadata = {
                'batch_number': i // 10,
                'generated': True,
                'seed_used': rng.randint(1000, 9999)
            } if rng.random() > 0.8 else None
            
            domain = TestDataGenerator.create_unknown_domain(
                domain_name=domain_name,
                days_ago=int(day_offset),
                hours_ago=int(hour_offset),
                source=source,
                status=status,
                metadata=metadata
            )
            
            domains.append(domain)
        
        return domains
    
    @staticmethod
    def create_labeled_dataframe(
        row_count: int = 100,
        known_fraction: float = 0.6,       # 60% known (Tranco/URLhaus)
        benign_unknown_ratio: float = 0.7, # 70% of unknown are benign
        malicious_threshold: float = 35,
        suspicious_threshold: float = 100,
        seed: int = 42
    ) -> pd.DataFrame:
        """
        Create DataFrame simulating labeled_dns_dataset.csv output.
        
        This matches the exact column structure produced by DNSLabeller so we can
        properly test the filtering logic in domain_persistence integration.
        
        Args:
            row_count: Number of rows to generate.
            known_fraction: Fraction of rows with known TI results.
            benign_unknown_ratio: Among unknowns, fraction labeled benign.
            malicious_threshold: Threat score threshold for Malicious label.
            suspicious_threshold: Threshold for Suspicious label.
            seed: Random seed for reproducibility.
            
        Returns:
            DataFrame matching labelled_dns_dataset.csv format.
        """
        rng = random.Random(seed)
        
        records = []
        
        for i in range(row_count):
            domain = TestDataGenerator.generate_domain(
                prefix=f'label-{i}',
                seed=rng.randint(2000, 8000)
            )
            
            is_known = rng.random() < known_fraction
            
            if is_known and rng.random() > 0.5:
                # Trusted Tranco example
                ti_reason = "Trusted Tranco Domain"
                threat_score = -100
                label = "Benign"
                confidence = 98
            elif is_known:
                # Known Malicious URLhaus example  
                ti_reason = "Known Malicious Domain (URLhaus)"
                threat_score = 100
                label = "Malicious"
                confidence = 99
            else:
                # UNKNOWN DOMAIN - this is what we persist!
                is_benign_unknown = rng.random() < benign_unknown_ratio
                
                if is_benign_unknown:
                    ti_reason = "Benign score from heuristics"
                    threat_score = rng.randint(0, 34)  # Below suspicious
                    label = "Benign"
                    confidence = rng.choice([82, 85, 88])
                elif rng.random() > 0.4:
                    ti_reason = "High entropy; Long domain; Digit ratio high"
                    threat_score = rng.randint(35, 99)  # Suspicious/Malicious
                    label = "Suspicious"
                    confidence = rng.choice([75, 80, 85, 90])
                else:
                    ti_reason = "DGA characteristics; Cryptomining indicators"
                    threat_score = 100
                    label = "Malicious"
                    confidence = rng.choice([96, 97, 98, 99])
            
            record = {
                'domain': domain,
                'registered_domain': '.'.join(domain.split('.')[-2:]),
                'tld': domain.split('.')[-1],
                'response_code': rng.choice(['NOERROR', 'NOERROR', 'NOERROR', 'NXDOMAIN']),
                'threat_score': threat_score,
                'label': label,
                'confidence': confidence,
                'label_reason': ti_reason
            }
            
            records.append(record)
        
        df = pd.DataFrame(records)
        return df
    
    @staticmethod
    def create_database_row(
        domain_id: int,
        domain_name: str,
        days_ago: int = 1,
        status: str = "new",
        metadata_json: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create dictionary representing a database row as returned by psycopg.
        
        Args:
            domain_id: Integer ID.
            domain_name: Domain string.
            days_ago: Offset for timestamps.
            status: Status string value.
            metadata_json: JSON string for metadata column.
            
        Returns:
            Dictionary mimicking psycopg dict_row output.
        """
        now = datetime.now(timezone.utc)
        created = now - timedelta(days=days_ago)
        
        return {
            'id': domain_id,
            'domain': domain_name,
            'first_seen': created,
            'last_seen': created + timedelta(hours=2),
            'source': 'dns_query_log',
            'status': status,
            'metadata': metadata_json or '{}',
            'created_at': created,
            'updated_at': now,
            'schema_version': 2
        }


class ExpectedStatsCalculator:
    """Helper class for calculating expected processing statistics."""
    
    @staticmethod
    def calculate_expected_stats_from_dataframe(
        df: pd.DataFrame,
        filter_mask: pd.Series = None
    ) -> Dict[str, Any]:
        """
        Calculate expected PersistenceStats from DataFrame shape.
        
        Args:
            df: Full labeled dataframe.
            filter_mask: Boolean mask indicating which rows would be persisted.
            
        Returns:
            Dictionary with expected stat values.
        """
        if filter_mask is not None:
            filtered_df = df[filter_mask]
        else:
            filtered_df = df
        
        total_processed = len(filtered_df)
        
        # In real scenarios, some would be INSERTs (new), some UPDATEs (seen before)
        # For simplicity, assume all are new inserts unless we track duplicates
        domains_stored = total_processed  # Assume all new
        domains_updated = 0                 # Assume no duplicates in test
        domains_skipped = 0                 # Assume no failures in ideal scenario
        
        errors = []
        
        return {
            'total_processed': total_processed,
            'domains_stored': domains_stored,
            'domains_updated': domains_updated,
            'domains_skipped': domains_skipped,
            'processing_time_ms': 0.0,      # Not timing here
            'throughput_per_second': 0.0,
            'errors': errors,
            'success_rate': 100.0           # All succeeded
        }