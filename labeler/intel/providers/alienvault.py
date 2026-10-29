"""AlienVault OTX Threat Provider"""
from __future__ import annotations

import logging
from typing import Optional

import requests

from ..correlation.models import ThreatProviderResult
from .key_manager import APIKeyManager
from .base import BaseThreatProvider

logger = logging.getLogger(__name__)

GENERAL_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
ANALYSIS_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/analysis"


class AlienVaultOTXProvider(BaseThreatProvider):
    provider_name = "AlienVault OTX"

    def __init__(self, config: dict, session: Optional[requests.Session] = None) -> None:
        super().__init__(config, session)
        self._api_key = config.get("OTX_API_KEY", "")
        self._timeout = int(config.get("API_TIMEOUT", 15))

        raw_keys = config.get("OTX_API_KEYS", "")
        if isinstance(raw_keys, str):
            keys = [k.strip() for k in raw_keys.split(",") if k.strip()]
        elif isinstance(raw_keys, (list, tuple)):
            keys = [str(k).strip() for k in raw_keys if str(k).strip()]
        else:
            keys = []

        self._key_manager: Optional[APIKeyManager] = None
        if keys:
            self._key_manager = APIKeyManager(keys)
            logger.info("[OTX] Using APIKeyManager with %d key(s).", len(keys))
        elif self._api_key:
            logger.info("[OTX] Using single OTX_API_KEY.")

    def is_enabled(self) -> bool:
        value = self.config.get("ENABLE_OTX", True)
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes")

    def _next_headers(self) -> Optional[dict]:
        if self._key_manager:
            api_key = self._key_manager.get_next_key()
            if not api_key:
                return None
        else:
            api_key = self._api_key
        return {"X-OTX-API-KEY": api_key, "Accept": "application/json"}

    def lookup(self, domain: str) -> ThreatProviderResult:
        logger.info("[OTX] Lookup started — %s", domain)

        if not self._key_manager and not self._api_key:
            logger.warning("[OTX] No API key configured — marking unavailable.")
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error="OTX_API_KEY not set.",
            )

        general_url = GENERAL_URL.format(domain=domain)

        # Bounded retry loop for the General endpoint.
        # If APIKeyManager is active, attempt at most once per currently available key
        # (round-robin rotation). For a single OTX_API_KEY, perform exactly one attempt.
        # This prevents an infinite loop while still exhausting all usable keys.
        max_attempts = (
            max(len(self._key_manager.available_keys()), 1)
            if self._key_manager
            else 1
        )

        resp: Optional[requests.Response] = None

        for attempt in range(max_attempts):
            headers = self._next_headers()
            if headers is None:
                logger.warning("[OTX] All keys are rate limited — marking unavailable.")
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error="All AlienVault OTX API keys are rate limited.",
                )

            current_key = headers["X-OTX-API-KEY"]

            try:
                resp = self._request_with_retry("GET", general_url, headers=headers)
            except requests.exceptions.Timeout:
                logger.warning("[OTX] Timeout — %s", domain)
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error="Request timed out.",
                )
            except requests.exceptions.ConnectionError as exc:
                logger.warning("[OTX] Connection error — %s: %s", domain, exc)
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=f"Connection error: {exc}",
                )
            except requests.exceptions.RequestException as exc:
                logger.warning("[OTX] Request failed — %s: %s", domain, exc)
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=str(exc),
                )

            # HTTP 429: key is rate-limited. Mark it and rotate to the next key.
            if resp.status_code == 429:
                logger.warning("[OTX] Rate limited (HTTP 429) — %s", domain)
                if self._key_manager:
                    self._key_manager.mark_rate_limited(current_key)
                    logger.info("[OTX] Switching to next available API key.")
                    continue
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error="Rate limited (HTTP 429).",
                )

            # HTTP 401/403: authentication failed for this key.
            # If APIKeyManager is active, invalidate the key with a long cooldown and
            # rotate to the next key. Only give up once all keys have been tried.
            # For a single-key setup, return an error immediately.
            if resp.status_code in (401, 403):
                logger.warning(
                    "[OTX] Authentication failed (HTTP %d). Invalidating API key.",
                    resp.status_code,
                )
                if self._key_manager:
                    self._key_manager.mark_rate_limited(
                        current_key, cooldown_seconds=86400
                    )
                    logger.info(
                        "[OTX] Key invalidated — switching to next available API key."
                    )
                    continue
                return ThreatProviderResult(
                    provider=self.provider_name,
                    unavailable=True,
                    error=f"Authentication failed (HTTP {resp.status_code}).",
                )

            # Successful (or unrecoverable) status — exit the retry loop.
            break

        else:
            # for-loop exhausted without a successful response: all configured keys
            # were unavailable (rate-limited or authentication failures).
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error="No usable AlienVault OTX API keys remain.",
            )

        # resp is guaranteed to be assigned here (loop exited via break).
        assert resp is not None  # satisfy type checkers

        if resp.status_code >= 500:
            logger.warning(
                "[OTX] Server error (HTTP %d) — %s", resp.status_code, domain
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"Server error (HTTP {resp.status_code}).",
            )

        if resp.status_code == 404:
            logger.info("[OTX] Domain not found in OTX — %s", domain)
            return ThreatProviderResult(
                provider=self.provider_name,
                malicious=False,
                confidence=0.0,
                found=False,
                raw_data={},
            )

        if resp.status_code != 200:
            logger.warning(
                "[OTX] Unexpected status %d — %s", resp.status_code, domain
            )
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"HTTP {resp.status_code}.",
            )

        try:
            general_data = resp.json()
        except ValueError as exc:
            logger.error("[OTX] JSON parse error (general) — %s", exc)
            return ThreatProviderResult(
                provider=self.provider_name,
                unavailable=True,
                error=f"JSON parse error: {exc}",
            )

        # --- Analysis endpoint (best-effort) ---
        # Failures here do not fail the overall lookup; we simply continue with
        # general data only. Uses the same bounded retry / key-rotation logic as
        # the General endpoint.
        analysis_url = ANALYSIS_URL.format(domain=domain)
        analysis_data: dict = {}

        max_analysis = (
            max(len(self._key_manager.available_keys()), 1)
            if self._key_manager
            else 1
        )

        for _analysis_attempt in range(max_analysis):
            analysis_headers = self._next_headers()
            if analysis_headers is None:
                logger.warning(
                    "[OTX] All keys are rate limited for analysis lookup — "
                    "continuing with general data only."
                )
                break

            analysis_key = analysis_headers["X-OTX-API-KEY"]

            # Initialize to None so that later status checks are always guarded.
            analysis_resp: Optional[requests.Response] = None

            try:
                analysis_resp = self._request_with_retry(
                    "GET", analysis_url, headers=analysis_headers
                )
            except requests.exceptions.RequestException as exc:
                logger.warning(
                    "[OTX] Analysis endpoint failed — %s: %s", domain, exc
                )
                # Best-effort: a network failure is not fatal; exit the loop.
                break

            # HTTP 429 on analysis: mark key and rotate.
            if analysis_resp.status_code == 429:
                logger.warning(
                    "[OTX] Rate limited (HTTP 429) on analysis endpoint — %s", domain
                )
                if self._key_manager:
                    self._key_manager.mark_rate_limited(analysis_key)
                    logger.info("[OTX] Switching to next available API key.")
                    continue
                break

            # HTTP 401/403 on analysis: invalidate key (if manager) and rotate.
            if analysis_resp.status_code in (401, 403):
                logger.warning(
                    "[OTX] Authentication failed (HTTP %d). Invalidating API key.",
                    analysis_resp.status_code,
                )
                if self._key_manager:
                    self._key_manager.mark_rate_limited(
                        analysis_key, cooldown_seconds=86400
                    )
                    logger.info(
                        "[OTX] Key invalidated — switching to next available API key."
                    )
                    continue
                break

            # HTTP 5xx on analysis: log and continue with general data only.
            if analysis_resp.status_code >= 500:
                logger.warning(
                    "[OTX] Analysis endpoint server error (HTTP %d) — %s; "
                    "continuing with general data only.",
                    analysis_resp.status_code,
                    domain,
                )
                break

            if analysis_resp.status_code == 200:
                try:
                    analysis_data = analysis_resp.json()
                except ValueError:
                    analysis_data = {}

            # Any other status (including 200 handled above): exit the loop.
            break

        # --- Parsing (functionally identical to original) ---
        raw_data = {"general": general_data, "analysis": analysis_data}

        pulse_count = 0
        try:
            pulses = general_data.get("pulse_info", {}).get("pulses", [])
            pulse_count = len(pulses)
        except (AttributeError, TypeError):
            pass

        try:
            analysis_pulses = (
                analysis_data.get("data", {})
                .get("attributes", {})
                .get("pulse_info", {})
                .get("pulses", [])
            )
            pulse_count = max(pulse_count, len(analysis_pulses))
        except (AttributeError, TypeError):
            pass

        is_malicious = pulse_count > 0
        confidence = min(pulse_count / 3.0, 1.0) if pulse_count > 0 else 0.0

        logger.info(
            "[OTX] Lookup completed — %s: pulses=%d malicious=%s",
            domain,
            pulse_count,
            is_malicious,
        )
        if is_malicious:
            logger.info(
                "[OTX] Malicious — %s (pulses=%d confidence=%.2f)",
                domain,
                pulse_count,
                confidence,
            )
        else:
            logger.info("[OTX] Clean — %s", domain)

        return ThreatProviderResult(
            provider=self.provider_name,
            malicious=is_malicious,
            confidence=round(confidence, 4),
            malicious_count=pulse_count,
            found=pulse_count > 0,
            raw_data=raw_data,
        )