#provides features of ownership and registry
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

try:
    import whois                          
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class WhoisExtractor:


    _cache: Dict[str, Optional[Any]] = {}

    @staticmethod
    def extract(domain: str) -> Dict[str, float]:
        defaults = {
            "domain_age": -1.0,
            "days_until_expiry": -1.0,
            "registration_period": -1.0,
            "nameserver_count": 0.0,
        }

        if not _WHOIS_AVAILABLE:
            logger.warning("python-whois not installed — skipping WHOIS features.")
            return defaults

        try:
            w = WhoisExtractor._lookup(domain)
            if w is None:
                return defaults

            now = datetime.now()

            creation = _first(w.creation_date)
            if creation:
                creation = _to_datetime(creation)
                defaults["domain_age"] = float((now - creation).days)

            expiry = _first(w.expiration_date)
            if expiry:
                expiry = _to_datetime(expiry)
                defaults["days_until_expiry"] = float((expiry - now).days)
                if creation:
                    defaults["registration_period"] = float(
                        (expiry - creation).days
                    )

            ns = w.name_servers
            if ns:
                if isinstance(ns, (list, tuple, set)):
                    defaults["nameserver_count"] = float(
                        len({n.strip().lower() for n in ns})
                    )
                else:
                    defaults["nameserver_count"] = 1.0

        except Exception as exc:
            logger.warning("WHOIS lookup failed for %s: %s", domain, exc)

        return defaults

    @classmethod
    def _lookup(cls, domain: str) -> Optional[Any]:
        if domain in cls._cache:
            return cls._cache[domain]
        try:
            w = whois.whois(domain)
            cls._cache[domain] = w
            return w
        except Exception:
            cls._cache[domain] = None
            return None


def _first(value: Any) -> Any:
    """If *value* is a list, return the first element; else return it as-is."""
    if isinstance(value, (list, tuple)) and value:
        return value[0]
    return value


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if hasattr(value, "year"):          # date object
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
    raise ValueError(f"Cannot convert {value!r} to datetime")
