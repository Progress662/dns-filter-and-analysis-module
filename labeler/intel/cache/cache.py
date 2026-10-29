
"""
Two-Layer Threat Intelligence Cache
====================================
Implements a two-layer caching strategy to minimise external API calls.
 
Layer 1 — In-Memory Cache
    Fast dict-based cache with separate TTLs for malicious and clean
    decisions.  Thread-safe via a ``threading.Lock``.  Both malicious
    and clean decisions are cached here.
 
Layer 2 — PostgreSQL Persistent Cache (malicious only)
    ``reputation_domains`` stores only previously confirmed malicious
    domains.  If a domain is present with a recent ``last_seen``
    timestamp (within the malicious TTL), the cached decision is reused
    instead of re-querying APIs.  Clean decisions are **not** stored in
    PostgreSQL and are only cached in Layer 1 (in-memory).
 
TTL Strategy
------------
- Malicious decisions: 24 hours (CACHE_TTL_MALICIOUS) — both layers.
- Clean decisions:      6 hours (CACHE_TTL_CLEAN)     — Layer 1 only.
 
This prevents repeatedly querying APIs for common clean domains while
keeping the cache responsive to newly-flagged malicious domains.
 
Cache hit order
---------------
1. Check Layer 1 (in-memory).
2. If miss, check Layer 2 (PostgreSQL via ``get_domain()``).
3. If both miss → the engine queries providers and stores the result.
"""
 
from __future__ import annotations
 
import logging
import time
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Callable, Optional
 
from ..correlation.models import ThreatDecision, ThreatProviderResult
 
logger = logging.getLogger(__name__)
 
 
class ThreatIntelCache:
    """Two-layer TTL-based cache for threat intelligence decisions.
 
    Parameters
    ----------
    ttl_malicious_hours : int
        TTL for malicious decisions in hours (default 24).
    ttl_clean_hours : int
        TTL for clean decisions in hours (default 6).
    db_getter : callable or None
        Optional ``get_domain(domain) -> dict or None`` function from
        the database repository.  Used for Layer 2 (PostgreSQL) cache
        lookups.
    """
 
    def __init__(
        self,
        ttl_malicious_hours: int = 24,
        ttl_clean_hours: int = 6,
        db_getter: Optional[Callable[[str], Optional[dict[str, Any]]]] = None,
    ) -> None:
        self._ttl_malicious_seconds: float = ttl_malicious_hours * 3600.0
        self._ttl_clean_seconds: float = ttl_clean_hours * 3600.0
        self._db_getter: Optional[Callable[[str], Optional[dict[str, Any]]]] = db_getter
 
        # --- Layer 1: In-memory ---
        self._memory: dict[str, tuple[float, ThreatDecision]] = {}
        self._lock: Lock = Lock()
 
        logger.info(
            "ThreatIntelCache initialised "
            "(ttl_malicious=%dh, ttl_clean=%dh, layer2=%s)",
            ttl_malicious_hours,
            ttl_clean_hours,
            "enabled" if db_getter else "disabled",
        )
 
    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get(self, domain: str) -> Optional[ThreatDecision]:
        """Retrieve a cached decision for *domain*.
 
        Checks Layer 1 (in-memory) first, then Layer 2 (PostgreSQL).
        Returns ``None`` if both layers miss or have expired data.
 
        Parameters
        ----------
        domain : str
            The domain to look up.
 
        Returns
        -------
        ThreatDecision or None
        """
        # --- Layer 1: In-memory ---
        decision = self._get_from_memory(domain)
        if decision is not None:
            logger.debug("[Cache] Layer-1 hit — %s", domain)
            return decision
 
        # --- Layer 2: PostgreSQL ---
        decision = self._get_from_database(domain)
        if decision is not None:
            logger.debug("[Cache] Layer-2 hit — %s", domain)
            # Promote to Layer 1 for faster future access
            self._set_in_memory(domain, decision)
            return decision
 
        logger.debug("[Cache] Miss — %s", domain)
        return None
 
    def set(self, domain: str, decision: ThreatDecision) -> None:
        """Store *decision* in Layer 1 (in-memory).
 
        The TTL is selected automatically based on the decision:
        malicious → uses ``ttl_malicious_hours``, clean → uses
        ``ttl_clean_hours``.
 
        Note: Layer 2 (PostgreSQL) is written by ``store_malicious_domain()``
        in the pipeline, not by the cache itself.
 
        Parameters
        ----------
        domain : str
        decision : ThreatDecision
        """
        self._set_in_memory(domain, decision)
        ttl_label = "malicious" if decision.malicious else "clean"
        logger.debug(
            "[Cache] Cached in Layer 1 — %s (%s)", domain, ttl_label,
        )
 
    def invalidate(self, domain: str) -> None:
        """Remove *domain* from both cache layers.
 
        Parameters
        ----------
        domain : str
        """
        with self._lock:
            self._memory.pop(domain, None)
        logger.debug("[Cache] Invalidated — %s", domain)
 
    def clear(self) -> None:
        """Clear the in-memory cache only (Layer 1)."""
        with self._lock:
            self._memory.clear()
        logger.debug("[Cache] Layer 1 cleared.")
 
    @property
    def size(self) -> int:
        """Return the number of entries in the in-memory cache."""
        with self._lock:
            return len(self._memory)
 
    # ------------------------------------------------------------------
    # Internal: Layer 1
    # ------------------------------------------------------------------
    def _get_ttl_for_decision(self, decision: ThreatDecision) -> float:
        """Return the appropriate TTL in seconds for a given decision."""
        if decision.malicious:
            return self._ttl_malicious_seconds
        return self._ttl_clean_seconds
 
    def _get_from_memory(self, domain: str) -> Optional[ThreatDecision]:
        """Check the in-memory cache.  Returns ``None`` if missing or
        expired."""
        with self._lock:
            entry = self._memory.get(domain)
            if entry is None:
                return None
            timestamp, decision = entry
            ttl = self._get_ttl_for_decision(decision)
            if time.monotonic() - timestamp > ttl:
                del self._memory[domain]
                return None
            return decision
 
    def _set_in_memory(self, domain: str, decision: ThreatDecision) -> None:
        """Store *decision* in the in-memory cache."""
        with self._lock:
            self._memory[domain] = (time.monotonic(), decision)
 
    # ------------------------------------------------------------------
    # Internal: Layer 2
    # ------------------------------------------------------------------
    def _get_from_database(self, domain: str) -> Optional[ThreatDecision]:
        """Check PostgreSQL via ``get_domain()``.
 
        If the domain exists and ``last_seen`` is within the appropriate
        TTL window (malicious entries use the malicious TTL),
        reconstruct a ``ThreatDecision`` and return it.
        """
        if self._db_getter is None:
            return None
 
        try:
            record = self._db_getter(domain)
        except Exception as exc:
            logger.warning(
                "[Cache] Layer-2 lookup failed for %s: %s", domain, exc
            )
            return None
 
        if record is None:
            return None
 
        # Check if last_seen is within TTL
        last_seen = record.get("last_seen")
        if last_seen is None:
            return None
 
        # last_seen may be a datetime or a string
        if isinstance(last_seen, str):
            try:
                last_seen_dt = datetime.fromisoformat(last_seen)
            except ValueError:
                return None
        else:
            last_seen_dt = last_seen
 
        # Ensure timezone-aware for comparison
        now = datetime.now(timezone.utc)
        if last_seen_dt.tzinfo is None:
            # Assume UTC if naive
            last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
 
        age_seconds = (now - last_seen_dt).total_seconds()
 
        # The domain is confirmed malicious (it's in reputation_domains).
        # Use the malicious TTL.
        if age_seconds > self._ttl_malicious_seconds:
            logger.debug(
                "[Cache] Layer-2 expired for %s (age=%.1fh > ttl=%dh)",
                domain, age_seconds / 3600,
                self._ttl_malicious_seconds / 3600,
            )
            return None
 
        # Reconstruct a ThreatDecision from the stored record
        source = record.get("source", "reputation_domains")
        confidence = record.get("confidence") or 0.0
 
        decision = ThreatDecision(
            domain=domain,
            malicious=True,
            score=1.0,              # Domain is confirmed malicious; score and
                                    # confidence are distinct concepts — the
                                    # weighted correlation score must not be
                                    # reconstructed from the stored confidence.
            confidence=float(confidence),
            threshold=0.0,  # Already confirmed, no threshold needed
            provider_results=[
                ThreatProviderResult(
                    provider=source,
                    malicious=True,
                    confidence=float(confidence),
                    raw_data={"cached_from": "reputation_domains"},
                )
            ],
            checked_at=last_seen_dt,
            source="Cache (reputation_domains)",
        )
 
        logger.info(
            "[Cache] Layer-2 hit — %s (last_seen=%s, confidence=%.2f)",
            domain, last_seen_dt.isoformat(), confidence,
        )
        return decision
 
