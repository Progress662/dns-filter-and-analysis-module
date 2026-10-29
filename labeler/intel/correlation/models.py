"""
Domain Models for the Threat Correlation Framework
===================================================
Standardised data-transfer objects (DTOs) used across all providers,
the scoring engine, and the correlation engine.

Every provider returns ``ThreatProviderResult`` with the same shape.
The correlation engine returns ``ThreatDecision``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class ThreatProviderResult:
    """Standardised result returned by every threat intelligence provider.

    Every provider **must** return this exact shape.

    Parameters
    ----------
    provider : str
        Human-readable name (e.g. ``"VirusTotal"``).
    malicious : bool
        Whether the provider considers this domain malicious.
    confidence : float
        Provider-level confidence in [0.0, 1.0].
    malicious_count : int
        Number of malicious reports / detections.
    harmless_count : int
        Number of harmless / clean reports.
    suspicious_count : int
        Number of suspicious reports.
    unavailable : bool
        ``True`` if the provider could not be reached, timed out, or
        returned an error.  When ``True`` the result contributes zero
        weight to the final score.
    error : str or None
        Human-readable error when ``unavailable=True``.
    found : bool
        ``True`` if the provider actually holds intelligence on this
        domain (e.g. VirusTotal returned an analysis record, OTX
        returned pulses).  ``False`` when the provider was reachable
        and responded successfully, but has **no record at all** for
        the domain (VT HTTP 404 / OTX "no pulses"/"unknown domain").
        This is distinct from ``unavailable`` (provider could not be
        queried) and from ``malicious=False`` (provider queried the
        domain and found it clean) — it means "no data either way".
    raw_data : dict
        Full raw API response for auditability and debugging.
    """

    provider: str
    malicious: bool = False
    confidence: float = 0.0
    malicious_count: int = 0
    harmless_count: int = 0
    suspicious_count: int = 0
    unavailable: bool = False
    error: Optional[str] = None
    found: bool = True
    raw_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatDecision:
    """Final decision produced by the :class:`CorrelationEngine`.

    Parameters
    ----------
    domain : str
        The domain that was evaluated.
    malicious : bool
        Final verdict — ``True`` when the weighted score >= threshold.
    score : float
        Weighted score in [0.0, 1.0].  Sum of weights of all providers
        that voted malicious.
    confidence : float
        Average confidence across all *available* providers that voted
        malicious.  Independent of score.
    threshold : float
        The score threshold used for this decision (configurable).
    provider_results : list[ThreatProviderResult]
        Full list of individual provider results for auditability.
    checked_at : datetime
        UTC timestamp of when the evaluation was performed.
    source : str
        Always ``"Threat Correlation Engine"``.
    metadata : dict
        Enriched metadata suitable for ``store_malicious_domain()``.
        Includes provider breakdown, score, confidence, and timestamp.
    """

    domain: str
    malicious: bool = False
    score: float = 0.0
    confidence: float = 0.0
    threshold: float = 0.5
    provider_results: list[ThreatProviderResult] = field(default_factory=list)
    checked_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    source: str = "Threat Correlation Engine"

    @property
    def has_intelligence(self) -> bool:
        """``True`` if at least one provider was reachable *and* had a
        record for this domain (``unavailable=False`` and
        ``found=True``).

        ``False`` means every provider either could not be reached or
        explicitly had no data (e.g. VT 404 *and* OTX "no pulses") —
        i.e. this decision carries no real evidence either way, even
        though ``malicious`` defaults to ``False`` in that case.
        """
        return any(
            not r.unavailable and r.found for r in self.provider_results
        )

    @property
    def metadata(self) -> dict[str, Any]:
        """Build the metadata dict for ``store_malicious_domain()``.

        Contains enough information to reconstruct the exact reason for
        the decision.

        Note
        ----
        The existing ``reputation`` table does **not** have a JSON/JSONB
        column.  The ``store_malicious_domain()`` function accepts an
        optional ``metadata`` dict but only extracts ``source``,
        ``confidence``, and ``query_count`` from it.  The full provider
        evidence below is therefore **documented in the stored metadata**
        for forward compatibility — when a JSONB column is added, this
        data becomes queryable.
        """
        provider_details: dict[str, Any] = {}
        for r in self.provider_results:
            if not r.unavailable:
                provider_details[r.provider.lower().replace(" ", "_")] = {
                    "malicious": r.malicious,
                    "malicious_count": r.malicious_count,
                    "harmless_count": r.harmless_count,
                    "suspicious_count": r.suspicious_count,
                    "confidence": r.confidence,
                }

        return {
            "decision": "malicious" if self.malicious else "clean",
            "score": self.score,
            "confidence": self.confidence,
            "threshold": self.threshold,
            "providers": provider_details,
            "checked_at": self.checked_at.isoformat(),
            "source": self.source,
        }