"""
Online Threat Intelligence Facade
=================================
Connects the existing providers, correlation engine, and cache layers
into a single class consumed by the pipeline.

``ThreatIntelligence`` is the class imported by ``labeler/intel/__init__.py``
(``from .threat_intelligence import ThreatIntelligence``).

It delegates all evaluation logic to the existing ``CorrelationEngine``
and exposes a ``close()`` lifecycle method.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from .correlation.engine import CorrelationEngine
from .correlation.models import ThreatDecision

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """Facade for the online threat correlation framework.

    The pipeline creates **one** instance at startup and calls
    ``evaluate(domain)`` for every unknown domain.

    Parameters
    ----------
    config : dict
        Configuration dictionary.  See ``CorrelationEngine`` and
        ``WeightedScorer`` for details.
    db_store : callable or None
        ``store_malicious_domain(domain, metadata)`` — will be called
        automatically when a domain is deemed malicious.
    db_getter : callable or None
        ``get_domain(domain) -> dict or None`` — enables Layer-2
        (PostgreSQL) caching.
    """

    def __init__(
        self,
        config: dict[str, Any],
        db_store: Optional[Callable[[str, Optional[dict]], bool]] = None,
        db_getter: Optional[Callable[[str], Optional[dict[str, Any]]]] = None,
    ) -> None:
        self._engine: CorrelationEngine = CorrelationEngine(
            config=config,
            db_store=db_store,
            db_getter=db_getter,
        )
        logger.info("ThreatIntelligence initialised.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def evaluate(
        self,
        domain: str,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> ThreatDecision:
        """Evaluate *domain* using all enabled threat providers.

        Parameters
        ----------
        domain : str
            The domain to evaluate.
        client_ip : str or None
            Originating client IP address for the DNS query that surfaced
            this domain.  Forwarded to ``store_malicious_domain()`` so
            that ``reputation_domains.client_ip`` is populated for
            online-TI-confirmed malicious domains.
        query_type : str or None
            DNS query type (e.g. ``A``, ``AAAA``, ``MX``).  Forwarded
            alongside ``client_ip``.

        Returns
        -------
        ThreatDecision
            Final decision with weighted score and provider breakdown.
        """
        return self._engine.evaluate(
            domain,
            client_ip=client_ip,
            query_type=query_type,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def close(self) -> None:
        """Release all provider resources (HTTP sessions, etc.)."""
        self._engine.close_providers()
        logger.info("ThreatIntelligence closed.")

    def __enter__(self) -> "ThreatIntelligence":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()