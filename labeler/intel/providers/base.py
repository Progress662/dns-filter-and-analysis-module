"""
Abstract Base Provider
======================
Every threat intelligence provider inherits from ``BaseThreatProvider``
and implements ``lookup(domain) -> ThreatProviderResult``.
 
The base class manages:
 
- Lazy HTTP session with configurable timeout.
- **Rate limiting with exponential backoff** for HTTP 429 and 5xx errors.
- Standardised error handling template.
- Provider enable/disable flag.
 
Rate limiting
-------------
Providers can use ``self._request_with_retry(method, url, **kwargs)``
instead of ``self.session.request(...)``.  This method:
 
1. Sends the request.
2. If a ``429`` or ``5xx`` status is received, waits and retries.
3. Backoff: 1s → 2s → 4s (max 3 retries, max delay 60s).
4. If all retries are exhausted, returns the last response.

The set of retryable status codes can be overridden per-call via the
``retryable_statuses`` keyword argument.  This allows providers that
manage their own 429 / key-rotation logic (e.g. ``VirusTotalProvider``)
to exclude 429 from the base-class retry loop so they can act on it
immediately without burning extra retry slots against the same
rate-limited key.

  Example::

      resp = self._request_with_retry(
          "GET", url, headers=headers,
          retryable_statuses={500, 502, 503, 504},  # exclude 429
      )
 
Adding a new provider
---------------------
1. Create ``providers/myprovider.py``.
2. Subclass ``BaseThreatProvider``, set ``provider_name``, implement ``lookup(domain)``.
3. Add the class to ``providers/__init__.py`` ``_PROVIDER_CLASSES``.
 
No other code in the framework needs to change.
"""
 
from __future__ import annotations
 
import logging
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional, FrozenSet
 
import requests
 
from ..correlation.models import ThreatProviderResult
 
if TYPE_CHECKING:
    pass  # requests is now imported unconditionally above
 
logger = logging.getLogger(__name__)
 
# ---------------------------------------------------------------------------
# Retry / rate-limit constants
# ---------------------------------------------------------------------------
_MAX_RETRIES: int = 3
_BASE_BACKOFF_SECONDS: float = 1.0
_BACKOFF_FACTOR: float = 2.0
_MAX_BACKOFF_SECONDS: float = 60.0

# Default set of HTTP status codes that trigger an automatic retry.
# Providers that manage their own retry/rotation logic for specific codes
# (e.g. 429) should pass a custom ``retryable_statuses`` to
# ``_request_with_retry`` to avoid double-handling.
_DEFAULT_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
 
 
class BaseThreatProvider(ABC):
    """Abstract base for all threat intelligence providers.
 
    Parameters
    ----------
    config : dict
        Configuration dictionary (typically from environment variables).
    session : requests.Session or None
        An optional shared HTTP session.  If not provided, a session
        is created lazily on first use.
    """
 
    #: Human-readable provider name (e.g. ``"VirusTotal"``).
    provider_name: str = "base"
 
    def __init__(
        self,
        config: dict,
        session: Optional["requests.Session"] = None,
    ) -> None:
        self.config: dict = config
        self._session: Optional["requests.Session"] = session
        self.timeout: int = int(self.config.get("API_TIMEOUT", 15))
 
    # ------------------------------------------------------------------
    # HTTP session (lazy, per-provider)
    # ------------------------------------------------------------------
    @property
    def session(self) -> "requests.Session":
        """Lazy-initialised HTTP session with a configurable timeout.
 
        Each provider gets its own session to allow independent
        configuration (timeout, headers, auth).
        """
        if self._session is None:
            self._session = requests.Session()
            timeout = int(self.config.get("API_TIMEOUT", 15))
            self._session.headers.update(
                {"User-Agent": "DNS-ThreatCorrelation/1.0"}
            )
            # Store timeout on the session for easy reference
            self.timeout = int(self.config.get("API_TIMEOUT", 15))
        return self._session
 
    # ------------------------------------------------------------------
    # Rate-limited request with exponential backoff
    # ------------------------------------------------------------------
    def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> "requests.Response":
        """Send an HTTP request with automatic retry on rate-limit and
        server errors.

        Retryable status codes (default):
            - 429 (Too Many Requests)
            - 500, 502, 503, 504 (Server errors)

        Override the retryable set via the ``retryable_statuses`` keyword
        argument.  Providers that manage their own 429 / key-rotation
        logic should exclude 429 from this set so the base class does not
        waste retry slots on a key that is already rate-limited::

            resp = self._request_with_retry(
                "GET", url, headers=headers,
                retryable_statuses={500, 502, 503, 504},
            )
 
        Backoff strategy:
            1s → 2s → 4s (exponential, capped at 60s).
 
        If all retries are exhausted, the last response is returned as-is
        so the caller can inspect ``resp.status_code``.
 
        Parameters
        ----------
        method : str
            HTTP method (``"GET"``, ``"POST"``, etc.).
        url : str
            Request URL.
        retryable_statuses : set[int], optional
            HTTP status codes that should trigger a retry with backoff.
            Defaults to ``{429, 500, 502, 503, 504}``.  Pass a custom
            set to override — e.g. exclude 429 when the provider handles
            key rotation itself.
        **kwargs
            Additional arguments passed to ``session.request()``.
 
        Returns
        -------
        requests.Response
            The final response (possibly from a retry).
        """
        # Pop provider-specific kwarg before forwarding to requests
        retryable_statuses: frozenset[int] = frozenset(
            kwargs.pop("retryable_statuses", _DEFAULT_RETRYABLE_STATUSES)
        )
        timeout = kwargs.pop("timeout", self.timeout)
        last_response: Optional["requests.Response"] = None
 
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = self.session.request(
                    method, url, timeout=timeout, **kwargs
                )
            except requests.RequestException:
                # Network-level failure — retry if attempts remain
                if attempt < _MAX_RETRIES:
                    wait = min(
                        _BASE_BACKOFF_SECONDS * (_BACKOFF_FACTOR ** attempt),
                        _MAX_BACKOFF_SECONDS,
                    )
                    logger.warning(
                        "[%s] Request failed (attempt %d/%d) — "
                        "retrying in %.1fs",
                        self.provider_name,
                        attempt + 1,
                        _MAX_RETRIES + 1,
                        wait,
                    )
                    time.sleep(wait)
                    continue
                raise
 
            if resp.status_code not in retryable_statuses:
                # Non-retryable — return immediately
                return resp
 
            last_response = resp
 
            if attempt < _MAX_RETRIES:
                wait = min(
                    _BASE_BACKOFF_SECONDS * (_BACKOFF_FACTOR ** attempt),
                    _MAX_BACKOFF_SECONDS,
                )
 
                # Parse Retry-After header if present
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = max(wait, float(retry_after))
                    except ValueError:
                        pass
 
                logger.warning(
                    "[%s] HTTP %d (attempt %d/%d) — "
                    "backing off %.1fs",
                    self.provider_name,
                    resp.status_code,
                    attempt + 1,
                    _MAX_RETRIES + 1,
                    wait,
                )
                time.sleep(wait)
 
        # All retries exhausted — return the last response
        if last_response is not None:
            logger.warning(
                "[%s] All %d retries exhausted — "
                "returning HTTP %d",
                self.provider_name,
                _MAX_RETRIES + 1,
                last_response.status_code,
            )
 
        return last_response  # type: ignore[return-value]
 
    # ------------------------------------------------------------------
    # Abstract interface — every provider must implement
    # ------------------------------------------------------------------
    @abstractmethod
    def lookup(self, domain: str) -> ThreatProviderResult:
        """Query the provider for *domain* and return a standardised result.
 
        Parameters
        ----------
        domain : str
            The fully-qualified domain name to look up.
 
        Returns
        -------
        ThreatProviderResult
            Always returns a result object — never raises on transient
            failures.  Errors are captured in the ``unavailable`` and
            ``error`` fields.
        """
        ...
 
    # ------------------------------------------------------------------
    # Lifecycle hooks (optional overrides)
    # ------------------------------------------------------------------
    def is_enabled(self) -> bool:
        """Return ``True`` if this provider should be activated.
 
        Override in subclasses to check an ``ENABLE_<NAME>``
        environment variable.
        """
        return True
 
    def close(self) -> None:
        """Release provider resources (HTTP session)."""
        if self._session is not None:
            self._session.close()
 
    def __repr__(self) -> str:
        return f"<{type(self).__name__}:{self.provider_name}>"