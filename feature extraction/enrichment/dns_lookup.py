import logging
import time
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


class DNSLookup:

    def __init__(self, timeout: float = 2.0) -> None:
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.cache: Dict[str, Dict[str, Any]] = {}
        logger.info("DNSLookup initialized with timeout: %ss", timeout)

    def enrich(self, record: Any) -> Any:
        domain = getattr(record, 'domain', None) or getattr(record, 'qname', None)
        if not domain:
            logger.debug("No domain/qname found in record. Skipping DNS enrichment.")
            return record

        domain = domain.rstrip('.').lower()

        # Check cache before performing network lookups
        if domain in self.cache:
            logger.debug(f"Cache hit for {domain}")
            cached_data = self.cache[domain]
            for key, value in cached_data.items():
                setattr(record, key, value)
            return record

        start_time = time.perf_counter()
        logger.info(f"Starting DNS enrichment for domain: {domain}")

        try:
            # Execute individual lookups
            a_data = self._resolve_a(domain)
            aaaa_data = self._resolve_aaaa(domain)
            cname_data = self._resolve_cname(domain)
            mx_exists = self._check_mx_exists(domain)

            elapsed = time.perf_counter() - start_time

            # Compile results for caching and record enrichment
            result = {
                'resolved_ip': a_data.get('ip'),
                'resolved_ips': a_data.get('ips', []),
                'ipv6': aaaa_data.get('ip'),
                'ipv6_addresses': aaaa_data.get('ips', []),
                'ttl': a_data.get('ttl'),
                'cname': cname_data.get('cname'),
                'mx_exists': mx_exists,
                'aaaa_exists': bool(aaaa_data.get('ips')),
                'response_time': round(elapsed, 4),
                'dnssec_available': False
            }

            # Store in cache for future records
            self.cache[domain] = result

            # Apply attributes to the record
            for key, value in result.items():
                setattr(record, key, value)

            logger.info(f"Successfully enriched {domain}. Elapsed: {elapsed:.4f}s")

        except Exception as e:
            logger.warning(f"DNS lookup failed for {domain}: {e}")
            self._set_defaults(record)

        return record

    def _resolve_a(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {'ip': None, 'ips': [], 'ttl': None}
        try:
            answers = self.resolver.resolve(domain, 'A', lifetime=self.timeout)
            ips = [str(rdata.address) for rdata in answers]
            if ips:
                result['ips'] = ips
                result['ip'] = ips[0]
                result['ttl'] = answers.ttl
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"A record lookup failed for {domain}: {e}")
        return result

    def _resolve_aaaa(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {'ip': None, 'ips': []}
        try:
            answers = self.resolver.resolve(domain, 'AAAA', lifetime=self.timeout)
            ips = [str(rdata.address) for rdata in answers]
            if ips:
                result['ips'] = ips
                result['ip'] = ips[0]
        except (dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"AAAA record lookup failed for {domain}: {e}")
        return result

    def _resolve_cname(self, domain: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {'cname': None}
        try:
            answers = self.resolver.resolve(domain, 'CNAME', lifetime=self.timeout)
            if answers:
                result['cname'] = str(answers[0].target).rstrip('.')
        except (dns.resolver.NoAnswer, dns.exception.DNSException) as e:
            logger.debug(f"CNAME record lookup failed for {domain}: {e}")
        return result

    def _check_mx_exists(self, domain: str) -> bool:
        try:
            self.resolver.resolve(domain, 'MX', lifetime=self.timeout)
            return True
        except (dns.resolver.NoAnswer, dns.exception.DNSException):
            return False

    def _set_defaults(self, record: Any) -> None:
        defaults = {
            'resolved_ip': None,
            'resolved_ips': [],
            'ipv6': None,
            'ipv6_addresses': [],
            'ttl': None,
            'cname': None,
            'mx_exists': False,
            'aaaa_exists': False,
            'response_time': None,
            'dnssec_available': False
        }
        for key, value in defaults.items():
             setattr(record, key, value)
        logger.debug(f"Applied default DNS enrichment values to record.")