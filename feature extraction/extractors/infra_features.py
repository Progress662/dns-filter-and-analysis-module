

from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

try:
    from ipwhois import IPWhois
    _IPWHOIS_AVAILABLE = True
except ImportError:
    _IPWHOIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class InfrastructureExtractor:
    """Compute 2 infrastructure features from resolved IPs."""

    _cache: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def extract(records: List) -> Dict[str, float]:
        defaults = {"asn": 0.0, "country_count": 0.0}

        if not _IPWHOIS_AVAILABLE:
            logger.warning("ipwhois not installed — skipping infrastructure features.")
            return defaults

        unique_ips = {r.resolved_ip for r in records if r.resolved_ip}
        if not unique_ips:
            return defaults

        asns: Set[int] = set()
        countries: Set[str] = set()

        for ip in unique_ips:
            info = InfrastructureExtractor._lookup(ip)
            if info:
                if info.get("asn"):
                    asns.add(info["asn"])
                if info.get("country"):
                    countries.add(info["country"])

        defaults["asn"] = float(next(iter(asns), 0))
        defaults["country_count"] = float(len(countries))

        return defaults

    @classmethod
    def _lookup(cls, ip: str) -> Dict[str, Any]:
        if ip in cls._cache:
            return cls._cache[ip]

        result: Dict[str, Any] = {}
        try:
            rdap = IPWhois(ip).lookup_rdap()
            result["asn"] = int(rdap.get("asn", 0) or 0)
            result["country"] = rdap.get("asn_country_code", "XX")
        except Exception as exc:
            logger.warning("RDAP lookup failed for %s: %s", ip, exc)

        cls._cache[ip] = result
        return result