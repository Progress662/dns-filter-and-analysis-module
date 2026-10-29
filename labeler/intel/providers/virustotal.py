"""
VirusTotal Threat Provider
==========================
Queries the VirusTotal v3 API for domain reputation.

Uses the official ``/api/v3/domains/{domain}`` endpoint.

Configuration (.env)
--------------------
VT_API_KEY       — VirusTotal API key (required if VT_API_KEYS is not set)
VT_API_KEYS      — Comma-separated list of VirusTotal API keys (optional,
                   takes precedence over VT_API_KEY when present and
                   non-empty). When set, requests are rotated across the
                   configured keys via ``APIKeyManager`` and a key that
                   hits a 429 rate limit is skipped in favor of another
                   available key.
API_TIMEOUT      — HTTP request timeout in seconds (default 15)
ENABLE_VT        — ``True`` to enable (default ``True``)

Official docs: https://docs.virustotal.com/reference/domain-info

Root-cause notes (bugs fixed in this version)
---------------------------------------------
BUG-1 (PRIMARY — explains ``malicious=0 harmless=0 suspicious=0`` on every domain):
    When VirusTotal returns HTTP 200 and ``last_analysis_stats`` is present
    but every counter is zero (domain exists in VT's index but has never been
    submitted to any scanning engine, OR the API key does not have analysis
    privileges), ``total == 0`` caused ``confidence = 0 / 0 → 0.0`` and the
    code returned ``ThreatProviderResult(malicious=False, found=True)`` — a
    **false clean**.  The fix: ``total == 0`` is now detected explicitly and
    returns ``unavailable=True`` with a diagnostic message containing the full
    response body so the caller knows why.

BUG-2 (SECONDARY — same false-clean path):
    When ``last_analysis_stats`` is entirely **absent** from ``data.attributes``
    (e.g. the response carries a different attribute set for newly-indexed
    domains), ``.get("last_analysis_stats", {})`` silently returned ``{}`` and
    the code fell into the same ``total == 0`` path.  The fix: absence of
    ``last_analysis_stats`` is now detected before the counter extraction and
    also returns ``unavailable=True``.

BUG-3 (TERTIARY — base-class 429 retry conflicts with outer key rotation):
    ``BaseThreatProvider._request_with_retry`` includes 429 in its default
    retryable-status set, meaning it retried up to 3 times with the **same**
    rate-limited key before returning the 429 response to the outer key-
    rotation loop in ``lookup()``.  This wasted retry slots and introduced
    unnecessary 7-second delays (1 s + 2 s + 4 s backoff) before the next
    available key was tried.  The fix: ``_request_with_retry`` is now called
    with ``retryable_statuses={500, 502, 503, 504}`` — 429 is excluded so
    the outer loop can act on it immediately.  ``base.py`` was extended to
    accept ``retryable_statuses`` as an optional keyword argument; all other
    providers that do not pass it continue to use the original default
    ``{429, 500, 502, 503, 504}``.

DEBUG LOGGING ADDED:
    Every request now logs the full URL, masked API key (last 6 chars),
    response status code, response headers, and complete response body at
    DEBUG level before any parsing occurs.  Enable with ``LOG_LEVEL=DEBUG``.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from ..correlation.models import ThreatProviderResult
from .key_manager import APIKeyManager
from .base import BaseThreatProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_BASE_URL: str = "https://www.virustotal.com/api/v3/domains/{domain}"

# How long (in seconds) to permanently remove a key from rotation when a
# 401/403 indicates the key itself is invalid (only applies when using
# APIKeyManager with multiple keys).
_PERMANENT_COOLDOWN: int = 86400  # 24 hours — effectively permanent for a run

# Retryable statuses passed to _request_with_retry.
# 429 is intentionally EXCLUDED here: the outer key-rotation loop in
# ``lookup()`` handles 429 by marking the current key as rate-limited and
# immediately trying the next available key.  Including 429 in the base-class
# retryable set would cause it to retry the same rate-limited key 3 more
# times before surfacing the 429 to this outer loop.
_VT_RETRYABLE_STATUSES: frozenset[int] = frozenset({500, 502, 503, 504})


class VirusTotalProvider(BaseThreatProvider):
    """Query VirusTotal v3 for domain reputation."""

    provider_name: str = "VirusTotal"

    def __init__(
        self,
        config: dict,
        session: Optional[requests.Session] = None,
    ) -> None:
        super().__init__(config, session)
        self._api_key: str = config.get("VT_API_KEY", "")
        self._timeout: int = int(config.get("API_TIMEOUT", 15))

        # --- Multi-key support (VT_API_KEYS) ---------------------------
        raw_keys = config.get("VT_API_KEYS", "")
        if isinstance(raw_keys, str):
            keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
        elif isinstance(raw_keys, (list, tuple)):
            keys = [str(k).strip() for k in raw_keys if str(k).strip()]
        else:
            keys = []

        self._key_manager: Optional[APIKeyManager] = None
        if keys:
            self._key_manager = APIKeyManager(keys)
            logger.info("[VT] Using APIKeyManager with %d key(s).", len(keys))
        elif self._api_key:
            logger.info("[VT] Using single VT_API_KEY.")

    # ------------------------------------------------------------------
    # Enabled check
    # ------------------------------------------------------------------
    def is_enabled(self) -> bool:
        value = self.config.get("ENABLE_VT", True)
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _mask_key(key: str) -> str:
        """Return the API key with all but the last 6 characters replaced
        by asterisks, suitable for debug logging."""
        if len(key) <= 6:
            return "*" * len(key)
        return "*" * (len(key) - 6) + key[-6:]

    def _log_raw_response(
        self,
        url: str,
        api_key: str,
        resp: requests.Response,
    ) -> None:
        """Log the complete HTTP exchange at DEBUG level before any parsing.

        Prints:
          - Final URL (with domain substituted)
          - Request headers (API key masked to last 6 chars)
          - Response status code
          - Response headers
          - Complete response body (raw text, untruncated)
        """
        masked_key = self._mask_key(api_key)

        # Merge session-level and per-request headers for the log
        sent_headers: dict = dict(self.session.headers)
        sent_headers["x-apikey"] = masked_key

        logger.debug(
            "[VT] ---- RAW HTTP EXCHANGE ----\n"
            "  URL             : %s\n"
            "  Request headers : %s\n"
            "  Response status : %d\n"
            "  Response headers: %s\n"
            "  Response body   :\n%s\n"
            "[VT] ---- END RAW EXCHANGE ----",
            url,
            sent_headers,
            resp.status_code,
            dict(resp.headers),
            resp.text,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def lookup(self, domain: str) -> ThreatProviderResult:
        """Query VirusTotal for *domain*.

        Returns
        -------
        ThreatProviderResult
        """
        logger.info("[VT] Lookup started — %s", domain)

        if not self._key_manager and not self._api_key:
            logger.warning("[VT] No API key configured — marking unavailable.")
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error="VT_API_KEY not set.",
            )

        url = _BASE_URL.format(domain=domain)

        # ------------------------------------------------------------------
        # Retry loop with round-robin key rotation
        #
        # When APIKeyManager is active, we can retry on HTTP 429 or
        # 401/403 up to once per available key — each attempt selects
        # the next key from the round-robin pool.
        #
        #   - 429 (rate limit):   key is put on a short cooldown,
        #                          retry with next available key.
        #   - 401/403 (invalid):   key is permanently removed from
        #                          rotation for the current run,
        #                          retry with next available key.
        #   - All keys exhausted:  return a descriptive error.
        #
        # When a single VT_API_KEY is used (no key manager), the loop
        # executes exactly once — no retry.
        #
        # NOTE: _request_with_retry is called with retryable_statuses
        # that EXCLUDE 429.  This is intentional: the outer key-rotation
        # loop below handles 429 by marking the key and switching
        # immediately.  If 429 were included in the base-class retryable
        # set, the base class would retry the same rate-limited key up to
        # 3 more times (wasting 7 seconds) before this loop could act.
        # ------------------------------------------------------------------
        available_key_count: int = (
            len(self._key_manager.available_keys())
            if self._key_manager
            else 1
        )
        max_attempts: int = max(available_key_count, 1)

        for attempt in range(max_attempts):
            # --- Select the next available key (round-robin) ---
            if self._key_manager:
                api_key = self._key_manager.get_next_key()
                if not api_key:
                    logger.warning(
                        "[VT] All keys are unavailable — marking unavailable.",
                    )
                    return ThreatProviderResult(
                        provider=self.provider_name,
                        unavailable=True,
                        error="All VirusTotal API keys are unavailable.",
                    )
            else:
                api_key = self._api_key

            headers = {"x-apikey": api_key}

            logger.debug(
                "[VT] Attempt %d/%d — key=...%s url=%s",
                attempt + 1,
                max_attempts,
                api_key[-6:] if len(api_key) >= 6 else api_key,
                url,
            )

            try:
                resp = self._request_with_retry(
                    "GET",
                    url,
                    headers=headers,
                    # BUG-3 FIX: exclude 429 from base-class retries so the
                    # outer key-rotation loop can act on it immediately.
                    retryable_statuses=_VT_RETRYABLE_STATUSES,
                )
            except requests.exceptions.Timeout:
                logger.warning("[VT] Timeout — %s", domain)
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error="Request timed out.",
                )
            except requests.exceptions.ConnectionError as exc:
                logger.warning("[VT] Connection error — %s: %s", domain, exc)
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=f"Connection error: {exc}",
                )
            except requests.exceptions.RequestException as exc:
                logger.warning("[VT] Request failed — %s: %s", domain, exc)
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=str(exc),
                )

            # --- Log the raw response before any interpretation ---
            self._log_raw_response(url, api_key, resp)

            # --- HTTP 429: rate limit — rotate to next key if available ---
            if resp.status_code == 429:
                logger.warning("[VT] Rate limited (HTTP 429) — %s", domain)
                if self._key_manager:
                    self._key_manager.mark_rate_limited(api_key)
                    logger.info("[VT] Switching to next available API key.")
                    continue
                # Single key — no retry possible
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error="Rate limited (HTTP 429).",
                )

            # --- HTTP 401/403: invalid key ---
            # When using APIKeyManager, remove this key from rotation
            # and immediately retry with the next available key.  Only
            # return Authentication failed if ALL keys have been tried
            # and exhausted.
            if resp.status_code in (401, 403):
                logger.error(
                    "[VT] Authentication failed (HTTP %d) — %s",
                    resp.status_code,
                    domain,
                )
                if self._key_manager:
                    # Permanently remove this key from rotation
                    self._key_manager.mark_rate_limited(
                        api_key, cooldown_seconds=_PERMANENT_COOLDOWN,
                    )
                    logger.info(
                        "[VT] Key invalidated — switching to next "
                        "available API key.",
                    )
                    continue
                # Single key — immediate failure
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=f"Authentication failed (HTTP {resp.status_code}).",
                )

            # Non-429/401/403 response — process below (break out of retry loop)
            break
        else:
            # Loop exhausted all attempts without a successful response
            logger.warning(
                "[VT] All %d attempt(s) exhausted — marking unavailable.",
                max_attempts,
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"All {max_attempts} attempt(s) exhausted.",
            )

        # --- HTTP status codes ---
        if resp.status_code >= 500:
            logger.warning(
                "[VT] Server error (HTTP %d) — %s", resp.status_code, domain
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"Server error (HTTP {resp.status_code}).",
            )
        if resp.status_code == 404:
            logger.info("[VT] Domain not found — %s", domain)
            return ThreatProviderResult(
                provider=self.provider_name,
                malicious=False,
                confidence=0.0,
                found=False,
                raw_data={},
            )
        if resp.status_code != 200:
            logger.warning("[VT] Unexpected status %d — %s", resp.status_code, domain)
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"HTTP {resp.status_code}.",
            )

        # --- Parse JSON ---
        try:
            data = resp.json()
        except ValueError as exc:
            logger.error("[VT] JSON parse error — %s: %s", domain, exc)
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"JSON parse error: {exc}",
            )

        # --- Extract attributes block ---
        # The VT v3 response for a known domain is:
        #   { "data": { "type": "domain", "id": "<domain>",
        #               "attributes": { "last_analysis_stats": { ... }, ... } } }
        try:
            data_block = data.get("data", None)
            if data_block is None:
                # "data" key missing entirely — unexpected structure
                logger.error(
                    "[VT] Response missing 'data' key — %s. "
                    "Full response: %s",
                    domain,
                    data,
                )
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=(
                        "Unexpected VirusTotal response: 'data' key absent. "
                        f"Top-level keys present: {list(data.keys())}. "
                        "See DEBUG logs for full response body."
                    ),
                )

            attributes = data_block.get("attributes", None)
            if attributes is None:
                logger.error(
                    "[VT] Response missing 'data.attributes' — %s. "
                    "data keys: %s",
                    domain,
                    list(data_block.keys()) if isinstance(data_block, dict) else type(data_block),
                )
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=(
                        "Unexpected VirusTotal response: 'data.attributes' absent. "
                        f"'data' keys present: "
                        f"{list(data_block.keys()) if isinstance(data_block, dict) else type(data_block).__name__}. "
                        "See DEBUG logs for full response body."
                    ),
                )

        except (AttributeError, TypeError) as exc:
            logger.error("[VT] Unexpected response structure — %s: %s", domain, exc)
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"Unexpected response structure: {exc}",
            )

        # --- BUG-1 + BUG-2 FIX: detect absent or all-zero last_analysis_stats ---
        #
        # BUG-1: last_analysis_stats IS present but every counter is 0
        #        (domain indexed in VT but never submitted to any scanning engine).
        #        Previously: total==0 → confidence=0.0, malicious=False, found=True
        #        → FALSE CLEAN.
        #        Fix: total==0 → unavailable=True with informative error.
        #
        # BUG-2: last_analysis_stats is ABSENT from attributes entirely
        #        (e.g. very new domain with a different attribute schema).
        #        Previously: .get("last_analysis_stats", {}) → {} → total==0
        #        → same false-clean path.
        #        Fix: absence of the key is detected explicitly before extraction.
        #
        # In both cases we return unavailable=True rather than a false result.
        # The caller (CorrelationEngine / UnknownDomainProcessor) will correctly
        # treat unavailable=True as "no evidence either way" and set the domain
        # status to REVIEW_NEEDED rather than CLEAN.
        if "last_analysis_stats" not in attributes:
            logger.error(
                "[VT] 'last_analysis_stats' absent from attributes — %s. "
                "Attributes keys present: %s",
                domain,
                list(attributes.keys()) if isinstance(attributes, dict) else type(attributes),
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=(
                    "VirusTotal response did not include 'last_analysis_stats'. "
                    f"Attributes keys present: "
                    f"{list(attributes.keys()) if isinstance(attributes, dict) else type(attributes).__name__}. "
                    "The domain may be too new to have been analysed, or the "
                    "API key may not have scan-result privileges. "
                    "See DEBUG logs for full response body."
                ),
                raw_data=data,
            )

        last_analysis_stats = attributes["last_analysis_stats"]

        if not isinstance(last_analysis_stats, dict):
            logger.error(
                "[VT] 'last_analysis_stats' has unexpected type %s — %s",
                type(last_analysis_stats).__name__,
                domain,
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=(
                    f"'last_analysis_stats' has unexpected type "
                    f"{type(last_analysis_stats).__name__} (expected dict). "
                    "See DEBUG logs for full response body."
                ),
                raw_data=data,
            )

        malicious: int = last_analysis_stats.get("malicious", 0)
        harmless: int = last_analysis_stats.get("harmless", 0)
        suspicious: int = last_analysis_stats.get("suspicious", 0)
        undetected: int = last_analysis_stats.get("undetected", 0)
        total: int = malicious + harmless + suspicious + undetected

        if total == 0:
            # BUG-1 FIX: all counters are zero — this is NOT a clean result.
            # It means VirusTotal has an index entry for the domain but no
            # scanning engine has ever analysed it (or the API key does not
            # have access to analysis results).  Do NOT return malicious=False
            # here: return unavailable=True so the domain is re-queued for
            # review rather than being silently marked clean.
            logger.warning(
                "[VT] last_analysis_stats all-zero for %s — "
                "stats=%s. Domain may not have been analysed yet.",
                domain,
                last_analysis_stats,
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=(
                    "VirusTotal returned HTTP 200 with last_analysis_stats "
                    f"all-zero: {last_analysis_stats}. "
                    "The domain is indexed in VirusTotal but has not been "
                    "submitted to any scanning engine yet, or the API key "
                    "does not have access to analysis results. "
                    "See DEBUG logs for full response body."
                ),
                raw_data=data,
            )

        is_malicious = malicious > 0
        confidence = malicious / total

        logger.info(
            "[VT] Lookup completed — %s: malicious=%d harmless=%d suspicious=%d undetected=%d total=%d",
            domain, malicious, harmless, suspicious, undetected, total,
        )

        if is_malicious:
            logger.info("[VT] Malicious — %s (confidence=%.4f)", domain, confidence)
        else:
            logger.info("[VT] Clean — %s (confidence=%.4f)", domain, confidence)

        return ThreatProviderResult(
            provider=self.provider_name,
            malicious=is_malicious,
            confidence=round(confidence, 4),
            malicious_count=malicious,
            harmless_count=harmless,
            suspicious_count=suspicious,
            raw_data=data,
        )