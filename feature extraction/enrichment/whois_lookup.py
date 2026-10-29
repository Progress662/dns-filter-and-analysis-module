import logging
import re
import tldextract
from datetime import datetime, date
from typing import Any, Optional, Dict
import time

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None

logger = logging.getLogger(__name__)


class WhoisLookup:

    def __init__(self, cache_ttl: int = 3600):
        if whois_lib is None:
            logger.error("python-whois library not installed. WhoisLookup disabled.")
        
        self.cache: Dict[str, tuple] = {} # key: (result_dict, timestamp)
        self.cache_ttl = cache_ttl
        logger.info("WhoisLookup initialized.")

    def enrich(self, record: Any) -> Any:
        if whois_lib is None:
            return record

        domain = getattr(record, 'domain', None) or getattr(record, 'qname', None)
        if not domain:
            return record

        ext = tldextract.extract(domain)

        effective_domain = f"{ext.domain}.{ext.suffix}"

        start_time = time.time()
        logger.info(f"Starting WHOIS enrichment for: {effective_domain}")

        try:
            w_data = self._get_whois(effective_domain)
            
            if w_data:
                # Date Parsing
                creation_date = self._parse_date(w_data.creation_date)
                expiration_date = self._parse_date(w_data.expiration_date)
                
                today = datetime.now()

                # Calculations
                domain_age_days = (today - creation_date).days if creation_date else None
                days_until_expiry = (expiration_date - today).days if expiration_date else None
                
                # Registrar Info
                registrar = getattr(w_data, 'registrar', None)
                
                # Name Servers
                ns_list = getattr(w_data, 'name_servers', [])
                ns_count = len(ns_list) if isinstance(ns_list, list) else 0
                
                # Registrant Country (Text parsing)
                country = self._parse_country(getattr(w_data, 'text', ''))

                # Attach Data
                setattr(record, 'creation_date', creation_date)
                setattr(record, 'expiration_date', expiration_date)
                setattr(record, 'domain_age', domain_age_days)
                setattr(record, 'days_until_expiry', days_until_expiry)
                setattr(record, 'registrar', registrar)
                setattr(record, 'nameserver_count', ns_count)
                setattr(record, 'registrant_country', country)
                
                elapsed = time.time() - start_time
                logger.info(f"WHOIS success for {effective_domain}. Elapsed: {elapsed:.4f}s")
            else:
                self._set_defaults(record)

        except Exception as e:
            logger.warning(f"WHOIS processing error for {effective_domain}: {e}")
            self._set_defaults(record)

        return record

    def _get_whois(self, domain: str):
        now = time.time()
        
        if domain in self.cache:
            data, ts = self.cache[domain]
            if (now - ts) < self.cache_ttl:
                return data

        try:
            # python-whois call
            result = whois_lib.whois(domain)
            self.cache[domain] = (result, now)
            return result
        except Exception as e:
            logger.warning(f"WHOIS query failed for {domain}: {e}")
            self.cache[domain] = (None, now)
            return None

    def _parse_date(self, date_input) -> Optional[datetime]:
        if not date_input:
            return None
            
        # Handle lists (sometimes returned)
        if isinstance(date_input, list):
            date_input = date_input[0]

        if isinstance(date_input, (datetime, date)):
            return datetime(date_input.year, date_input.month, date_input.day)
        
        if isinstance(date_input, str):
             date_str = date_input.strip()
             formats = [
                    "%Y-%m-%d",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%d-%b-%Y",
                    "%Y.%m.%d",
             ]
             for fmt in formats:
                 try:
                    return datetime.strptime(date_str.split()[0], fmt)
                 except ValueError:
                    continue

        return None

    def _parse_country(self, text: str) -> Optional[str]:
        if not text:
            return None
        match = re.search(r'(Country:\s*)([\w\s]+)', text, re.IGNORECASE)
        if match:
            return match.group(2).strip()
        return None

    def _set_defaults(self, record: Any):
        defaults = {
            'creation_date': None,
            'expiration_date': None,
            'domain_age': None,
            'days_until_expiry': None,
            'registrar': None,
            'nameserver_count': 0,
            'registrant_country': None
        }
        for k, v in defaults.items():
                setattr(record, k, v)