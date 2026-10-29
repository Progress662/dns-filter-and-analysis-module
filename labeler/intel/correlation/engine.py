"""
Threat Correlation Engine
=========================
The central orchestrator for the threat intelligence framework.
 
Responsibilities
----------------
1. Two-layer cache lookup (in-memory → PostgreSQL).
2. Concurrent querying of all enabled providers via ``ThreadPoolExecutor``.
3. Weighted scoring and confidence calculation via ``WeightedScorer``.
4. Domain persistence via ``store_malicious_domain()``.
 
Design
------
The engine has **zero** knowledge of provider-specific APIs.  It only
communicates through the ``BaseThreatProvider`` interface and the
``ThreatProviderResult`` / ``ThreatDecision`` models.
 
This allows adding new providers, changing weights, or swapping scoring
strategies without modifying the engine itself.
"""
 
from __future__ import annotations
 
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional
 
from ..cache import ThreatIntelCache
from ..providers import get_enabled_providers
from ..providers.base import BaseThreatProvider
from .models import ThreatDecision, ThreatProviderResult
from .scoring import WeightedScorer
 
logger = logging.getLogger(__name__)
 
 
class CorrelationEngine:
    """Orchestrates provider lookups, weighted scoring, caching, and
    persistence.
 
    Parameters
    ----------
    config : dict
        Configuration dictionary.  Relevant keys:
 
        * ``ENABLE_VT``, ``ENABLE_OTX`` — provider enable flags
        * ``CACHE_TTL_MALICIOUS`` — cache TTL for malicious (default ``24``)
        * ``CACHE_TTL_CLEAN`` — cache TTL for clean (default ``6``)
        * ``API_TIMEOUT`` — HTTP timeout (default ``15``)
        * Provider weights: ``WEIGHT_VT``, ``WEIGHT_OTX``
        * ``MALICIOUS_THRESHOLD`` — minimum score for malicious (default ``0.60``)
 
    db_store : callable or None
        ``store_malicious_domain(domain, metadata)`` for persisting
        malicious verdicts into ``reputation_domains``.
    db_getter : callable or None
        ``get_domain(domain) -> dict or None`` for Layer 2 cache lookups.
    """
 
    def __init__(
        self,
        config: dict[str, Any],
        db_store: Optional[Callable[[str, Optional[dict]], bool]] = None,
        db_getter: Optional[Callable[[str], Optional[dict[str, Any]]]] = None,
    ) -> None:
        self.config: dict[str, Any] = config
 
        # --- Cache (two-layer, dual TTL) ---
        ttl_malicious: int = int(config.get("CACHE_TTL_MALICIOUS", 24))
        ttl_clean: int = int(config.get("CACHE_TTL_CLEAN", 6))
        self._cache: ThreatIntelCache = ThreatIntelCache(
            ttl_malicious_hours=ttl_malicious,
            ttl_clean_hours=ttl_clean,
            db_getter=db_getter,
        )
 
        # --- Providers (lazy-initialised) ---
        self._providers: Optional[list[BaseThreatProvider]] = None
 
        # --- Weighted scorer ---
        weights = self._build_weights(config)
        threshold = float(config.get("MALICIOUS_THRESHOLD", 0.60))
        self._scorer: WeightedScorer = WeightedScorer(
            weights=weights,
            threshold=threshold,
        )
 
        # --- Database callbacks ---
        self._db_store: Optional[Callable] = db_store
 
        logger.info(
            "CorrelationEngine initialised "
            "(threshold=%.2f, cache_ttl_malicious=%dh, "
            "cache_ttl_clean=%dh, weights=%s)",
            threshold, ttl_malicious, ttl_clean, weights,
        )
 
    # ------------------------------------------------------------------
    # Provider lifecycle
    # ------------------------------------------------------------------
    def _get_providers(self) -> list[BaseThreatProvider]:
        """Lazy-load enabled providers."""
        if self._providers is None:
            self._providers = get_enabled_providers(self.config)
        return self._providers
 
    def close_providers(self) -> None:
        """Release all provider resources (HTTP sessions)."""
        if self._providers:
            for provider in self._providers:
                try:
                    provider.close()
                except Exception as exc:
                    logger.warning(
                        "Error closing provider %s: %s",
                        provider.provider_name,
                        exc,
                    )
 
    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------
    def evaluate(
        self,
        domain: str,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> ThreatDecision:
        """Evaluate *domain* across all enabled threat providers.
 
        Flow
        ----
        1. Check two-layer cache — return cached decision if fresh.
        2. Query all enabled providers concurrently via ``ThreadPoolExecutor``.
        3. Perform weighted scoring + confidence calculation.
        4. Cache the result in Layer 1 (with appropriate TTL).
        5. If malicious, persist via ``db_store`` (``store_malicious_domain``).
 
        Parameters
        ----------
        domain : str
            The domain to evaluate.
        client_ip : str or None
            Originating client IP.  Stored in ``reputation_domains.client_ip``
            when the domain is found malicious.
        query_type : str or None
            DNS query type (e.g. ``A``, ``AAAA``).  Stored in
            ``reputation_domains.query_type`` when malicious.
 
        Returns
        -------
        ThreatDecision
        """
        # --- 1. Cache check ---
        cached = self._cache.get(domain)
        if cached is not None:
            logger.info(
                "[Correlation] Cache hit — reusing decision for %s", domain
            )
            return cached
 
        providers = self._get_providers()
        if not providers:
            logger.warning("[Correlation] No enabled providers — returning clean.")
            return ThreatDecision(
                domain=domain,
                malicious=False,
                score=0.0,
                confidence=0.0,
                provider_results=[],
            )
 
        # --- 2. Query all providers concurrently ---
        logger.info(
            "[Correlation] Querying %d providers — %s",
            len(providers),
            domain,
        )
 
        all_results: list[ThreatProviderResult] = []
 
        try:
            with ThreadPoolExecutor(max_workers=len(providers)) as executor:
                future_map = {
                    executor.submit(provider.lookup, domain): provider
                    for provider in providers
                }
                for future in as_completed(future_map):
                    provider = future_map[future]
                    try:
                        result = future.result()
                        all_results.append(result)
                    except Exception as exc:
                        logger.error(
                            "[Correlation] %s raised unexpected exception: %s",
                            provider.provider_name,
                            exc,
                        )
                        all_results.append(
                            ThreatProviderResult(
                                provider=provider.provider_name,
                                unavailable=True,
                                error=f"Unexpected exception: {exc}",
                            )
                        )
        except Exception as exc:
            # Fallback: query remaining providers sequentially
            logger.error(
                "[Correlation] ThreadPoolExecutor error — "
                "falling back to sequential queries: %s",
                exc,
            )
            for provider in providers:
                try:
                    result = provider.lookup(domain)
                    all_results.append(result)
                except Exception as inner_exc:
                    all_results.append(
                        ThreatProviderResult(
                            provider=provider.provider_name,
                            unavailable=True,
                            error=f"Exception: {inner_exc}",
                        )
                    )
 
        # --- 3. Weighted scoring + confidence ---
        score, confidence, is_malicious = self._scorer.calculate(all_results)
 
        decision = ThreatDecision(
            domain=domain,
            malicious=is_malicious,
            score=score,
            confidence=confidence,
            threshold=self._scorer.threshold,
            provider_results=all_results,
        )
 
        # --- 4. Cache (Layer 1) — dual TTL applied automatically ---
        self._cache.set(domain, decision)
 
        # --- 5. Persist if malicious ---
        if is_malicious:
            self._persist(domain, decision, client_ip=client_ip, query_type=query_type)
 
        return decision
 
    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _persist(
        self,
        domain: str,
        decision: ThreatDecision,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> None:
        """Store malicious domain in ``reputation_domains``.

        Parameters
        ----------
        domain : str
            The domain to persist.
        decision : ThreatDecision
            Scoring decision from the correlation engine.
        client_ip : str or None
            Originating client IP — written to ``reputation_domains.client_ip``.
        query_type : str or None
            DNS query type — written to ``reputation_domains.query_type``.
        """
        if self._db_store is None:
            return
 
        try:
            # Build metadata from the decision and inject client context
            # so that reputation_domains.client_ip / query_type are
            # populated on the very first INSERT rather than left NULL.
            metadata = dict(decision.metadata)
            if client_ip is not None:
                metadata["client_ip"] = client_ip
            if query_type is not None:
                metadata["query_type"] = query_type

            self._db_store(domain=domain, metadata=metadata)
            logger.info(
                "[Correlation] Stored in reputation_domains — %s "
                "(score=%.2f, confidence=%.2f, providers=%d, "
                "client_ip=%s, query_type=%s)",
                domain,
                decision.score,
                decision.confidence,
                len(decision.provider_results),
                client_ip,
                query_type,
            )
        except Exception as exc:
            logger.error(
                "[Correlation] Failed to store %s: %s", domain, exc,
            )
 
    # ------------------------------------------------------------------
    # Weight builder
    # ------------------------------------------------------------------
    @staticmethod
    def _build_weights(config: dict) -> dict[str, float]:
        """Build provider weight mapping from configuration.
 
        Reads ``WEIGHT_VT``, ``WEIGHT_OTX`` from config, falling back
        to defaults.
        """
        return {
            "VirusTotal": float(config.get("WEIGHT_VT", 0.60)),
            "AlienVault OTX": float(config.get("WEIGHT_OTX", 0.40)),
        }
 
    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def __enter__(self) -> "CorrelationEngine":
        """Allow use as a context manager (``with CorrelationEngine(...) as engine:``)."""
        return self
 
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: object,
    ) -> None:
        """Release provider resources on context-manager exit."""
        self.close_providers()
 
    def __del__(self) -> None:
        try:
            self.close_providers()
        except Exception:
            pass