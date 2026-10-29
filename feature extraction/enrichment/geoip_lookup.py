import logging
import os
import time
from typing import Any, Optional

try:
    import geoip2.database
except ImportError:
    geoip2 = None

logger = logging.getLogger(__name__)


class GeoIPLookup:

    def __init__(self, db_path: str = 'GeoLite2-City.mmdb'):
        self.db_path = db_path
        self.reader = None
        
        if geoip2 is None:
            logger.error("geoip2 library missing. GeoIP disabled.")
        else:
            self._load_reader(db_path)

    def _load_reader(self, path: str):
        """Initialize the database reader."""
        if os.path.exists(path):
            try:
                self.reader = geoip2.database.Reader(path)
                logger.info(f"GeoIP loaded DB: {path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP DB at {path}: {e}")
        else:
            logger.warning(f"GeoIP DB file not found at {path}. GeoIP features disabled.")

    def enrich(self, record: Any) -> Any:
        if not self.reader:
            return record

        # Prefer IPv4
        ip_addr = getattr(record, 'resolved_ip', None)
        
        # If resolved_ip is a list, take first
        if isinstance(ip_addr, list):
            ip_addr = ip_addr[0] if len(ip_addr) > 0 else None

        if not ip_addr:
            # Try IPv6 if v4 missing
            ip_addr = getattr(record, 'ipv6', None)
            if isinstance(ip_addr, list):
                 ip_addr = ip_addr[0] if len(ip_addr) > 0 else None

        if not ip_addr:
            return record

        start_time = time.time()
        logger.debug(f"GeoIP Lookup starting for IP: {ip_addr}")

        try:
            response = self.reader.city(ip_addr)
            
            setattr(record, 'country', response.country.name)
            setattr(record, 'country_code', response.country.iso_code)
            setattr(record, 'continent', response.continent.name)
            setattr(record, 'city', response.city.name)
            setattr(record, 'latitude', response.location.latitude)
            setattr(record, 'longitude', response.location.longitude)
            
            elapsed = time.time() - start_time
            logger.debug(f"GeoIP success for {ip_addr}. Location: {response.city.name}, {response.country.name}")
            
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip_addr}: {e}")
            self._set_defaults(record)

        return record

    def _set_defaults(self, record: Any):
        defaults = {
            'country': None,
            'continent': None,
            'city': None,
            'latitude': None,
            'longitude': None
        }
        for k, v in defaults.items():
            if not hasattr(record, k):
                setattr(record, k, v)