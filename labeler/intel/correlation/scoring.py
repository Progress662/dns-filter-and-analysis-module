"""
Weighted Scoring Engine
=======================
Implements a configurable weighted scoring system for threat provider
correlation.  This replaces simple majority voting with a professional
score-based approach.
 
Each provider is assigned a weight (importance).  The final score is the
sum of weights of all providers that voted malicious.  A domain is
considered malicious if ``score >= threshold``.
 
Confidence is computed separately from score:
    ``confidence = average(provider.confidence for providers voting malicious)``
 
This allows tuning weights and thresholds independently of the
confidence signal.
 
Default weights (configurable via .env):
----------------------------------------
    VirusTotal         0.60
    AlienVault OTX     0.40
 
Threshold: 0.60
 
This design allows adding new providers without rewriting the engine —
simply assign a weight and add the provider to the registry.
"""
 
from __future__ import annotations
 
import logging
from typing import Optional
 
from .models import ThreatProviderResult
 
logger = logging.getLogger(__name__)
 
# ---------------------------------------------------------------------------
# Default weights — used when environment variables are not set
# ---------------------------------------------------------------------------
_DEFAULT_WEIGHTS: dict[str, float] = {
    "VirusTotal": 0.60,
    "AlienVault OTX": 0.40,
}
 
_DEFAULT_THRESHOLD: float = 0.60
 
 
class WeightedScorer:
    """Calculates weighted threat scores from provider results.
 
    Parameters
    ----------
    weights : dict[str, float] or None
        Provider-name → weight mappings.  Missing providers get a
        weight of 0.0.
    threshold : float
        Score threshold above which a domain is considered malicious
        (default 0.60).
    """
 
    def __init__(
        self,
        weights: Optional[dict[str, float]] = None,
        threshold: float = _DEFAULT_THRESHOLD,
    ) -> None:
        self._weights: dict[str, float] = {}
        if weights:
            self._weights.update(weights)
        self._threshold: float = threshold
 
        logger.info(
            "WeightedScorer initialised (threshold=%.2f, weights=%s)",
            self._threshold,
            self._weights,
        )
 
    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def calculate(
        self,
        results: list[ThreatProviderResult],
    ) -> tuple[float, float, bool]:
        """Calculate the weighted score, average confidence, and verdict.
 
        * Unavailable providers contribute **zero** weight.
        * Only providers with a defined weight participate in the score.
        * Providers not in the weight table receive 0.0 weight.
        * Confidence is the **average** of individual provider confidence
          values from providers that voted malicious.
        * If no provider voted malicious, confidence is 0.0.
 
        Parameters
        ----------
        results : list[ThreatProviderResult]
            All provider results (including unavailable ones).
 
        Returns
        -------
        tuple[float, float, bool]
            ``(score, confidence, is_malicious)`` where:
            - ``score`` is the sum of malicious-provider weights.
            - ``confidence`` is the average confidence of malicious providers.
            - ``is_malicious`` is ``True`` when ``score >= threshold``.
        """
        total_score: float = 0.0
        malicious_confidences: list[float] = []
 
        # Build structured log lines
        log_lines: list[str] = []
        log_lines.append("Correlation:")
 
        for result in results:
            if result.unavailable:
                log_lines.append(
                    f"  {result.provider:<25s} unavailable"
                )
                continue
 
            weight = self._weights.get(result.provider, 0.0)
            if result.malicious:
                total_score += weight
                malicious_confidences.append(result.confidence)
                log_lines.append(
                    f"  {result.provider:<25s} malicious  weight={weight:.2f}  "
                    f"confidence={result.confidence:.2f}"
                )
            else:
                log_lines.append(
                    f"  {result.provider:<25s} clean      weight=0.00"
                )
 
        # Confidence = average of malicious provider confidences
        confidence: float = 0.0
        if malicious_confidences:
            confidence = sum(malicious_confidences) / len(malicious_confidences)
 
        is_malicious = total_score >= self._threshold
        log_lines.append(f"  {'Total Score':<25s} {total_score:.2f}")
        log_lines.append(f"  {'Confidence':<25s} {confidence:.2f}")
        log_lines.append(f"  {'Decision':<25s} {'Malicious' if is_malicious else 'Clean'}")
 
        logger.info("\n".join(log_lines))
 
        return round(total_score, 4), round(confidence, 4), is_malicious
 
    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def threshold(self) -> float:
        return self._threshold
 
    @property
    def weights(self) -> dict[str, float]:
        return dict(self._weights)
 
