from __future__ import annotations

from typing import Dict, List


QUERY_TYPE_MAP: Dict[str, int] = {
    "A": 1, "AAAA": 28, "MX": 15, "NS": 2,
    "CNAME": 5, "TXT": 16, "SOA": 6, "PTR": 12,
    "SRV": 33, "DNSKEY": 48, "DS": 43, "ANY": 255,
}

RESPONSE_CODE_MAP: Dict[str, int] = {
    "NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2,
    "REFUSED": 5, "NOTIMP": 4, "YXDOMAIN": 6,
}


class DnsExtractor:
    """Compute 5 DNS-protocol features from a list of DNSRecord objects
    that share the same domain."""

    @staticmethod
    def extract(records: List) -> Dict[str, float]:

        _empty = {
            "ttl": 0.0,
            "query_type": 0.0,
            "response_code": 0.0,
            "unique_ip_count": 0.0,
            "ip_change_frequency": 0.0,
        }
        if not records:
            return _empty

        features: Dict[str, float] = {}

        ttl_values = [r.ttl for r in records if r.ttl is not None]
        features["ttl"] = sum(ttl_values) / len(ttl_values) if ttl_values else 0.0

        type_list = [r.query_type.upper() for r in records]
        most_common = max(set(type_list), key=type_list.count)
        features["query_type"] = float(QUERY_TYPE_MAP.get(most_common, 0))

        code_list = [r.response_code.upper() for r in records]
        most_common_code = max(set(code_list), key=code_list.count)
        features["response_code"] = float(RESPONSE_CODE_MAP.get(most_common_code, -1))

        resolved = [r.resolved_ip for r in records if r.resolved_ip]
        features["unique_ip_count"] = float(len(set(resolved)))

        features["ip_change_frequency"] = _ip_change_frequency(records)

        return features


def _ip_change_frequency(records: List) -> float:
    """Sort by timestamp, count IP transitions, return ratio."""
    if len(records) < 2:
        return 0.0

    sorted_recs = sorted(records, key=lambda r: r.timestamp)
    changes = 0
    prev_ip = sorted_recs[0].resolved_ip
    for rec in sorted_recs[1:]:
        if rec.resolved_ip != prev_ip:
            changes += 1
            prev_ip = rec.resolved_ip
    return changes / (len(sorted_recs) - 1)