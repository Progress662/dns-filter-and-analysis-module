from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List

import pandas as pd

from extractors.lexical import LexicalExtractor
from extractors.dns_features import DnsExtractor
from extractors.behavioural_features import BehavioralExtractor

logger = logging.getLogger(__name__)

FEATURE_COLUMNS: List[str] = [
    "domain_length",
    "digit_count",
    "entropy",
    "hyphen_count",
    "subdomain_count",
    "vowel_ratio",
    "consonant_ratio",
    "longest_digit_seq",
    "longest_consonant_seq",
    "unique_char_count",

    "ttl",
    "query_type",
    "response_code",
    "unique_ip_count",
    "ip_change_frequency",

    "domain_age",
    "days_until_expiry",
    "registration_period",
    "nameserver_count",

    "asn",
    "country_count",

    "query_count",
    "unique_client_count",
    "queries_per_client",
    "unique_resolved_ip_count",
    "unique_query_type_count",
    "unique_response_code_count",
    "response_code_diversity",
    "nxdomain_ratio",
    "servfail_ratio",
    "failed_lookup_ratio",
    "avg_query_interval",
    "query_interval_std",
    "burst_score",
    "beacon_score",
    "repeated_query_ratio",
    "unique_domain_count",
    "domain_reuse_ratio",
    "unique_ttl_count",
    "average_ttl",
    "ttl_variance",
    "unique_asn_count",
    "asn_change_frequency",
    "unique_registrar_count",
    "average_domain_age",
    "average_days_until_expiry",
    "avg_response_time",
    "dnssec_ratio",
    "mx_ratio",
    "aaaa_ratio",
    "first_seen_age",
    "last_seen_age",
    "observation_window",
    "query_type_entropy",
    "response_code_entropy",
]


class FeatureExtractor:

    WINDOW_SIZE = 100

    def __init__(
        self,
        enable_whois: bool = True,
        enable_ip_lookup: bool = True,
    ) -> None:

        self.enable_whois = enable_whois
        self.enable_ip_lookup = enable_ip_lookup

    def extract(self, records: List) -> pd.DataFrame:

        logger.info("Extracting features for %d DNS records...", len(records))

        rows: List[Dict] = []

        client_history = defaultdict(list)
        lexical_cache: Dict[str, Dict] = {}
        dns_cache: Dict[str, Dict] = {}

        for record in records:

            client = getattr(record, "client_ip", "unknown")
            history = client_history[client]

            domain = getattr(record, "domain", "")

            if domain not in lexical_cache:
                lexical_cache[domain] = LexicalExtractor.extract(domain)

            if domain not in dns_cache:
                dns_cache[domain] = DnsExtractor.extract([record])

            row = self._extract_one(
                record,
                history + [record],
                lexical_cache[domain],
                dns_cache[domain],
            )

            rows.append(row)

            history.append(record)

            if len(history) > self.WINDOW_SIZE:
                history.pop(0)

        df = pd.DataFrame(rows)

        ordered = [
            "domain",
            *FEATURE_COLUMNS,
            "threat_score",
            "confidence",
            "label",
        ]

        ordered = [c for c in ordered if c in df.columns]

        df = df[ordered]

        logger.info("Feature matrix shape: %s", df.shape)

        return df

    def _extract_one(
        self,
        record,
        history: List,
        lexical_features: Dict[str, object],
        dns_features: Dict[str, object],
    ) -> Dict[str, object]:

        features: Dict[str, object] = {
            "domain": getattr(record, "domain", ""),
            "threat_score": getattr(record, "threat_score", None),
            "confidence": getattr(record, "confidence", None),
            "label": getattr(record, "label", None),
        }

        features.update(lexical_features)

        features.update(dns_features)

        creation_date = getattr(record, "creation_date", None)
        expiration_date = getattr(record, "expiration_date", None)

        registration_period = -1.0

        if creation_date is not None and expiration_date is not None:
            registration_period = (expiration_date - creation_date).days

        domain_age = getattr(record, "domain_age", None)
        days_until_expiry = getattr(record, "days_until_expiry", None)

        features.update(
            {
                "domain_age": domain_age if domain_age is not None else -1,
                "days_until_expiry": days_until_expiry if days_until_expiry is not None else -1,
                "registration_period": registration_period,
                "nameserver_count": getattr(record, "nameserver_count", 0),
            }
        )

        features.update(
            {
                "asn": getattr(record, "asn", 0),
                "country_count": getattr(record, "country_count", 0),
            }
        )

        features.update(
            BehavioralExtractor.extract(history)
        )

        return features