import logging
import os
import time
from typing import Any, Optional

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    import geoip2.database
except ImportError:
    geoip2 = None

logger = logging.getLogger(__name__)

class ASNLookup:
    def __init__(self, asn_db_path: str = "databases/GeoLite2-ASN.mmdb", enable_rdap: bool = False):

        self.enable_rdap = enable_rdap and (IPWhois is not None)
        self.asn_reader = None

        if geoip2 is not None and os.path.exists(asn_db_path):
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                logger.info(f"Local ASN DB initialized: {asn_db_path}")
            except Exception as e:
                logger.error(f"Failed to load ASN DB: {e}")
    
    def enrich(self, record: Any) -> Any:
        ip_addr = getattr(record, 'resolved_ip', None)
        if isinstance(ip_addr, list):
            ip_addr = ip_addr[0]
        
        if not ip_addr:
            return record

        start_time = time.time()
        
        # First try the local ASN database
        if self.asn_reader:
         result = self._lookup_local(ip_addr)
         if result:
             self._apply_asn(record, result)
             return record
        
        # Optional fallback to RDAP
        if self.enable_rdap:
         result = self._lookup_rdap(ip_addr)
         if result:
             self._apply_asn(record, result)
             return record
                
        logger.debug(f"No ASN data found for {ip_addr}")
        self._set_defaults(record)
        return record

    def _lookup_rdap(self, ip: str) -> Optional[dict]:
        """Perform RDAP lookup."""
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            # Parse nested ipwhois response
            asn_data = res.get('asn')
            asn_desc = res.get('asn_description')
            # Clean description (usually comes as "AS1234 Description Text")
            asn_org = asn_desc.replace(f"{asn_data} ", "") if asn_desc else None
            
            return {
                'asn': asn_data,
                'asn_org': asn_org,
                'asn_cidr': res.get('network', {}).get('cidr')
            }
        except Exception as e:
            logger.warning(f"RDAP lookup failed for {ip}: {e}")
            return None

    def _lookup_local(self, ip: str) -> Optional[dict]:
        """Perform Local GeoLite2 ASN lookup."""
        try:
            response = self.asn_reader.asn(ip)
            autonomous_system_number = response.autonomous_system_number
            org_name = response.autonomous_system_organization
            
            return {
                'asn': f"AS{autonomous_system_number}",
                'asn_org': org_name,
                'asn_cidr': None
            }
        except Exception as e:
            logger.warning(f"Local ASN lookup failed for {ip}: {e}")
            return None

    def _apply_asn(self, record: Any, data: dict):
        setattr(record, 'asn', data.get('asn'))
        setattr(record, 'asn_org', data.get('asn_org'))
        # Optional: store CIDR if useful for infrastructure analysis
        # setattr(record, 'asn_cidr', data.get('asn_cidr')) 

    def _set_defaults(self, record: Any):
        setattr(record, "asn", None)
        setattr(record, "asn_org", None)