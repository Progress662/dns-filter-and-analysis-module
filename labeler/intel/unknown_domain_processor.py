"""UnknownDomainProcessor - enrich unknown domains via online TI.

Consumes rows from the ``unknown_domains`` persistence layer and
resolves each one using the online threat correlation framework
(:class:`~labeler.intel.threat_intelligence.ThreatIntelligence`, i.e.
VirusTotal + AlienVault OTX), then writes the final status back.

This module owns no provider logic of its own — it only interprets the
``ThreatDecision`` returned by ``OnlineThreatIntelligence.evaluate()``.
"""
from __future__ import annotations

import logging
from typing import Optional

from ..config import LabelingConfig
from .threat_intelligence import ThreatIntelligence as OnlineThreatIntelligence
from .reputation import store_malicious_domain, get_domain
from unknown_domain_repository.unknown_domain_repository.constants import DomainStatus

logger = logging.getLogger(__name__)


class UnknownDomainProcessor:
    """Resolves domains left in ``review``/``unknown`` state by the
    offline pipeline, using the online TI correlation engine.

    Parameters
    ----------
    persistence : object
        Storage layer exposing ``get_pending_domains() -> list[str]``
        and ``update_status(domain, status, detail=None)``. Backed by
        the ``unknown_domains`` PostgreSQL table.
    config : LabelingConfig or None
        Reuses the same configuration object as the rest of the
        pipeline. A default ``LabelingConfig()`` is created if omitted.
    """

    def __init__(
        self,
        persistence,
        config: Optional[LabelingConfig] = None,
    ) -> None:
        self.persistence = persistence
        if config is None:
            raise ValueError(
                "UnknownDomainProcessor requires a LabelingConfig instance."
            )
        self.config = config

        # Instantiated exactly as in labeler/threat_intelligence.py so
        # that reputation caching (Layer-2/PostgreSQL) and automatic
        # storage of malicious domains behave identically.
        self.ti = OnlineThreatIntelligence(
            config=self.config.get_online_ti_config(),
            db_store=store_malicious_domain,
            db_getter=get_domain,
        )

    def process(self) -> None:
        domains = self.persistence.get_pending_domains()
        logger.info("Loaded %d pending domains", len(domains))

        try:
            for domain in domains:
                domain_name = domain.domain
                logger.info("Processing %s", domain_name)
                try:
                    self.persistence.update_status(domain_name, DomainStatus.PROCESSING)

                    # FIX (Bug 2): pass client_ip and query_type directly to
                    # evaluate() so that CorrelationEngine._persist() receives
                    # them and includes them in the very first INSERT into
                    # reputation_domains — rather than inserting NULL and
                    # relying on a second store_malicious_domain() call to
                    # correct the row.  The second call below is now removed
                    # because _persist() already writes the complete record.
                    decision = self.ti.evaluate(
                        domain_name,
                        client_ip=domain.client_ip,
                        query_type=domain.query_type,
                    )

                    if decision.malicious:
                        # The CorrelationEngine already called
                        # store_malicious_domain() with client_ip/query_type
                        # inside evaluate() → _persist().  No second call
                        # needed here; just set the status.
                        status = DomainStatus.MALICIOUS
                    elif decision.has_intelligence:
                        # At least one provider was reachable and had
                        # a record for this domain, and none flagged
                        # it malicious -> a real, evidenced "clean".
                        status = DomainStatus.CLEAN
                    else:
                        # Every provider was either unreachable or had
                        # no record at all for the domain (VT "Not
                        # Found", OTX "No Pulses"/unknown domain) ->
                        # no evidence either way.
                        status = DomainStatus.REVIEW_NEEDED

                    logger.info("Decision: %s", status)
                    self.persistence.update_status(domain_name, status)
                    logger.info("Status -> %s", status)

                except Exception as exc:
                    logger.exception("Error on %s", domain_name)
                    self.persistence.update_status(domain_name, DomainStatus.ERROR, str(exc))
        finally:
            self.ti.close()