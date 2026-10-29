import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional
from parser.models import DNSRecord

BASE_DIR = Path(__file__).parent

from .dns_lookup import DNSLookup
from .whois_lookup import WhoisLookup
from .geoip_lookup import GeoIPLookup
from .asn_lookup import ASNLookup

logger = logging.getLogger(__name__)


class EnrichmentManager:
    def __init__(
        self,
        enable_dns: bool = True,
        enable_whois: bool = True,
        enable_geoip: bool = False,
        enable_asn: bool = True,
        geoip_db_path: str = str(BASE_DIR / "databases" / "GeoLite2-City.mmdb"),
        asn_db_path: str = str(BASE_DIR / "databases" / "GeoLite2-ASN.mmdb"),
        whois_workers: int = 10,  # Configurable concurrency limit for WHOIS
    ):

        self.enrichers = []
        self._whois_lookup: Optional[WhoisLookup] = None
        self._whois_workers = whois_workers

        if enable_dns:
            self.enrichers.append(('DNSLookup', DNSLookup()))
            logger.info("Pipeline: DNS Enabled")

        if enable_whois:
            self._whois_lookup = WhoisLookup()
            logger.info("Pipeline: WHOIS Enabled (concurrent workers=%d)", whois_workers)

        if enable_geoip:
            self.enrichers.append(('GeoIPLookup', GeoIPLookup(db_path=geoip_db_path)))
            logger.info("Pipeline: GeoIP Enabled")

        if enable_asn:
            self.enrichers.append(('ASNLookup', ASNLookup(asn_db_path=asn_db_path)))
            logger.info("Pipeline: ASN Enabled")

        if not self.enrichers and self._whois_lookup is None:
            logger.warning("No enrichers enabled! Pipeline will pass records through unmodified.")

    def _enrich_whois_concurrent(self, records: List[DNSRecord]) -> None:
        """
        Run WHOIS lookups for all records concurrently using a ThreadPoolExecutor.

        Results are written directly onto each record object (same as the
        sequential WhoisLookup.enrich() behaviour). Record order in the list
        is preserved because we submit by index and join all futures before
        returning.
        """
        if not records:
            return

        whois_start = time.perf_counter()
        logger.info("Starting concurrent WHOIS enrichment for %d records (workers=%d)",
                    len(records), self._whois_workers)

        def _whois_one(record: DNSRecord) -> DNSRecord:
            try:
                self._whois_lookup.enrich(record)
            except Exception:
                # WhoisLookup.enrich() already logs and sets defaults internally;
                # this outer guard ensures a thread exception never silently kills
                # the executor.
                logger.exception("Unexpected error in WHOIS thread for record: %s",
                                 getattr(record, 'domain', '<unknown>'))
            return record

        with ThreadPoolExecutor(max_workers=self._whois_workers,
                                thread_name_prefix="whois") as executor:
            # Submit all records; preserve order via list of futures
            futures = [executor.submit(_whois_one, record) for record in records]

            completed = 0
            for future in as_completed(futures):
                try:
                    future.result()  # Propagate any uncaught exception to the log
                except Exception:
                    logger.exception("WHOIS future raised an unhandled exception")
                completed += 1
                if completed % 100 == 0:
                    logger.info("WHOIS: completed %d/%d lookups...", completed, len(records))

        # Executor is shut down cleanly here (context manager __exit__ calls shutdown(wait=True))
        whois_elapsed = time.perf_counter() - whois_start
        logger.info("Concurrent WHOIS enrichment complete. Time: %.2fs", whois_elapsed)

    def enrich(self, records: List[DNSRecord]) -> List[DNSRecord]:
        total_start = time.perf_counter()
        count = len(records)

        logger.info("--- Starting Enrichment Pipeline for %d records ---", count)

        # -----------------------------------------------------------------
        # Phase 1: WHOIS — run all lookups concurrently before anything else.
        # All other enrichers depend on order-sensitive sequential iteration;
        # WHOIS results are independent per-domain so they are safe to batch.
        # -----------------------------------------------------------------
        if self._whois_lookup is not None:
            self._enrich_whois_concurrent(records)

        # -----------------------------------------------------------------
        # Phase 2: Remaining enrichers — sequential, order-preserved, same
        # behaviour as the original pipeline.
        # -----------------------------------------------------------------
        enriched_records = []

        for i, record in enumerate(records):
            for name, enricher_instance in self.enrichers:
                try:
                    enricher_instance.enrich(record)
                except Exception as e:
                    # Catch-all to ensure one bad record or enricher doesn't kill the run
                    logger.exception("Unrecoverable error in %s for record %d", name, i)

            enriched_records.append(record)

            # Log progress periodically
            if (i + 1) % 100 == 0:
                logger.info("Processed %d/%d records...", i + 1, count)

        total_elapsed = time.perf_counter() - total_start
        logger.info("--- Enrichment Complete. Total Time: %.2fs ---", total_elapsed)

        return enriched_records

