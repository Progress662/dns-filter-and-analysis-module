from __future__ import annotations

import logging
import math
from collections import Counter
from statistics import mean, pstdev, pvariance
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class BehavioralExtractor:
    _FEATURE_KEYS: Tuple[str, ...] = (
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
    )

    _CLIENT_ATTRS: Tuple[str, ...] = ("client_ip", "src_ip", "source_ip", "client")
    _RESOLVED_ATTRS: Tuple[str, ...] = ("resolved_ip", "answer_ip", "ip", "resolved_ips")
    _QTYPE_ATTRS: Tuple[str, ...] = ("query_type", "qtype", "type")
    _RCODE_ATTRS: Tuple[str, ...] = ("response_code", "rcode", "status")
    _DOMAIN_ATTRS: Tuple[str, ...] = ("qname", "domain", "name", "query_name")
    _TIMESTAMP_ATTRS: Tuple[str, ...] = ("timestamp", "ts", "time", "query_time")
    _TTL_ATTRS: Tuple[str, ...] = ("ttl",)
    _ASN_ATTRS: Tuple[str, ...] = ("asn",)
    _REGISTRAR_ATTRS: Tuple[str, ...] = ("registrar",)
    _AGE_ATTRS: Tuple[str, ...] = ("domain_age",)
    _EXPIRY_ATTRS: Tuple[str, ...] = ("days_until_expiry",)
    _RESPONSE_TIME_ATTRS: Tuple[str, ...] = ("response_time",)
    _DNSSEC_ATTRS: Tuple[str, ...] = ("dnssec_available", "dnssec")
    _MX_ATTRS: Tuple[str, ...] = ("mx_exists", "mx")
    _AAAA_ATTRS: Tuple[str, ...] = ("aaaa_exists", "has_ipv6")
    _IPV6_ATTRS: Tuple[str, ...] = ("ipv6", "ipv6_address")

    @staticmethod
    def extract(records: List[Any]) -> Dict[str, float]:
        try:
            return BehavioralExtractor._extract_safe(records)
        except Exception as e:
            logger.exception("Behavioral feature extraction failed: %s", e)
            return BehavioralExtractor._empty_features()

    @staticmethod
    def _extract_safe(records: List[Any]) -> Dict[str, float]:
        features = BehavioralExtractor._empty_features()

        if not records:
            return features

        total = 0
        clients: set = set()
        resolved_ips: set = set()
        qtypes_counter: Counter = Counter()
        rcodes_counter: Counter = Counter()
        domains_counter: Counter = Counter()
        ttls: List[float] = []
        asns: set = set()
        registrars: set = set()
        ages: List[float] = []
        expiries: List[float] = []
        response_times: List[float] = []
        timestamps: List[float] = []

        nxdomain = 0
        servfail = 0
        dnssec_count = 0
        mx_count = 0
        aaaa_count = 0

        get_first = BehavioralExtractor._get_first_attr
        to_float = BehavioralExtractor._to_float
        is_truthy = BehavioralExtractor._is_truthy_flag

        for record in records:
            if record is None:
                continue

            total += 1

            client = get_first(record, BehavioralExtractor._CLIENT_ATTRS)
            if client:
                clients.add(client)

            resolved = get_first(record, BehavioralExtractor._RESOLVED_ATTRS)
            if isinstance(resolved, (list, tuple, set)):
                for ip in resolved:
                    if ip:
                        resolved_ips.add(str(ip))
            elif resolved:
                resolved_ips.add(str(resolved))

            qtype = get_first(record, BehavioralExtractor._QTYPE_ATTRS)
            if qtype is not None:
                qtypes_counter[str(qtype).upper()] += 1

            rcode = get_first(record, BehavioralExtractor._RCODE_ATTRS)
            if rcode is not None:
                rcode_str = str(rcode).upper()
                rcodes_counter[rcode_str] += 1
                if rcode_str in ("NXDOMAIN", "3"):
                    nxdomain += 1
                elif rcode_str in ("SERVFAIL", "2"):
                    servfail += 1

            domain = get_first(record, BehavioralExtractor._DOMAIN_ATTRS)
            if domain:
                domains_counter[str(domain).lower()] += 1

            ttl_val = to_float(get_first(record, BehavioralExtractor._TTL_ATTRS))
            if ttl_val is not None:
                ttls.append(ttl_val)

            asn_val = get_first(record, BehavioralExtractor._ASN_ATTRS)
            if asn_val:
                asns.add(str(asn_val))

            registrar_val = get_first(record, BehavioralExtractor._REGISTRAR_ATTRS)
            if registrar_val:
                registrars.add(str(registrar_val).lower())

            age_val = to_float(get_first(record, BehavioralExtractor._AGE_ATTRS))
            if age_val is not None:
                ages.append(age_val)

            expiry_val = to_float(get_first(record, BehavioralExtractor._EXPIRY_ATTRS))
            if expiry_val is not None:
                expiries.append(expiry_val)

            rt_val = to_float(get_first(record, BehavioralExtractor._RESPONSE_TIME_ATTRS))
            if rt_val is not None:
                response_times.append(rt_val)

            if is_truthy(get_first(record, BehavioralExtractor._DNSSEC_ATTRS)):
                dnssec_count += 1

            if is_truthy(get_first(record, BehavioralExtractor._MX_ATTRS)):
                mx_count += 1

            aaaa_flag = get_first(record, BehavioralExtractor._AAAA_ATTRS)
            ipv6_val = get_first(record, BehavioralExtractor._IPV6_ATTRS)
            if is_truthy(aaaa_flag) or (ipv6_val is not None and str(ipv6_val).strip() != ""):
                aaaa_count += 1

            ts_val = BehavioralExtractor._to_timestamp(
                get_first(record, BehavioralExtractor._TIMESTAMP_ATTRS)
            )
            if ts_val is not None:
                timestamps.append(ts_val)

        if total == 0:
            return features

        features["query_count"] = float(total)
        features["unique_client_count"] = float(len(clients))

        if clients:
            features["queries_per_client"] = total / len(clients)
        else:
            features["queries_per_client"] = 0.0

        features["unique_resolved_ip_count"] = float(len(resolved_ips))
        features["unique_query_type_count"] = float(len(qtypes_counter))
        features["unique_response_code_count"] = float(len(rcodes_counter))

        if total > 0:
            features["response_code_diversity"] = len(rcodes_counter) / total
        else:
            features["response_code_diversity"] = 0.0

        features["nxdomain_ratio"] = nxdomain / total
        features["servfail_ratio"] = servfail / total
        features["failed_lookup_ratio"] = (nxdomain + servfail) / total

        intervals = BehavioralExtractor._compute_intervals(timestamps)
        if intervals:
            avg_interval = mean(intervals)
            std_interval = pstdev(intervals) if len(intervals) > 1 else 0.0
            features["avg_query_interval"] = float(avg_interval)
            features["query_interval_std"] = float(std_interval)

            if avg_interval > 0.0:
                cv = std_interval / avg_interval
                features["beacon_score"] = 1.0 / (1.0 + cv)
            else:
                features["beacon_score"] = 1.0

        window = 0.0
        if timestamps:
            window = max(timestamps) - min(timestamps)
        features["observation_window"] = float(window)

        if window > 0.0:
            features["burst_score"] = total / (window / 60.0)
        else:
            features["burst_score"] = float(total)

        if domains_counter:
            most_common_count = domains_counter.most_common(1)[0][1]
            unique_domains = len(domains_counter)
            features["repeated_query_ratio"] = most_common_count / total
            features["unique_domain_count"] = float(unique_domains)
            features["domain_reuse_ratio"] = total / unique_domains

        features["unique_ttl_count"] = float(len(set(ttls)))

        if ttls:
            features["average_ttl"] = float(mean(ttls))

        if len(ttls) > 1:
            features["ttl_variance"] = float(pvariance(ttls))
        else:
            features["ttl_variance"] = 0.0

        features["unique_asn_count"] = float(len(asns))

        if total > 0:
            features["asn_change_frequency"] = len(asns) / total
        else:
            features["asn_change_frequency"] = 0.0

        features["unique_registrar_count"] = float(len(registrars))

        if ages:
            features["average_domain_age"] = float(mean(ages))
        if expiries:
            features["average_days_until_expiry"] = float(mean(expiries))
        if response_times:
            features["avg_response_time"] = float(mean(response_times))

        features["dnssec_ratio"] = dnssec_count / total
        features["mx_ratio"] = mx_count / total
        features["aaaa_ratio"] = aaaa_count / total

        now_ts = BehavioralExtractor._current_time()
        if timestamps and now_ts is not None:
            features["first_seen_age"] = max(0.0, float(now_ts - min(timestamps)))
            features["last_seen_age"] = max(0.0, float(now_ts - max(timestamps)))

        features["query_type_entropy"] = BehavioralExtractor._entropy(qtypes_counter, total)
        features["response_code_entropy"] = BehavioralExtractor._entropy(rcodes_counter, total)

        return features

    @staticmethod
    def _empty_features() -> Dict[str, float]:
        return {key: 0.0 for key in BehavioralExtractor._FEATURE_KEYS}

    @staticmethod
    def _get_first_attr(record: Any, attrs: Iterable[str]) -> Any:
        for attr in attrs:
            value = getattr(record, attr, None)
            if value is not None:
                return value

        if isinstance(record, dict):
            for attr in attrs:
                if attr in record and record[attr] is not None:
                    return record[attr]

        return None

    @staticmethod
    def _to_float(value: Any) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                return None
            return float(value)
        try:
            result = float(value)
            if math.isnan(result) or math.isinf(result):
                return None
            return result
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _to_timestamp(value: Any) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            f = float(value)
            if math.isnan(f) or math.isinf(f):
                return None
            return f
        if hasattr(value, "timestamp"):
            try:
                return float(value.timestamp())
            except Exception:
                return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_truthy_flag(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes", "y", "t")
        return bool(value)

    @staticmethod
    def _compute_intervals(timestamps: List[float]) -> List[float]:
        n = len(timestamps)
        if n < 2:
            return []
        sorted_ts = sorted(timestamps)
        return [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, n)]

    @staticmethod
    def _entropy(counter: Counter, total: int) -> float:
        if total <= 0 or not counter:
            return 0.0

        entropy = 0.0
        for count in counter.values():
            if count <= 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)

        return float(entropy)

    @staticmethod
    def _current_time() -> Optional[float]:
        try:
            import time
            return float(time.time())
        except Exception:
            return None