"""
Custom Exceptions for the Threat Correlation Framework
======================================================
All exceptions inherit from ``ThreatIntelError`` so callers can catch
a single base type.  Every provider failure is caught and reported as
``unavailable=True`` — exceptions never propagate to the pipeline.
"""

from __future__ import annotations


class ThreatIntelError(Exception):
    """Base exception for all threat-intelligence errors."""


class ProviderConfigurationError(ThreatIntelError):
    """Raised when a provider is misconfigured (e.g. missing API key)."""


class ProviderAuthenticationError(ThreatIntelError):
    """Raised when the provider returns HTTP 401 or 403."""


class ProviderRateLimitError(ThreatIntelError):
    """Raised on HTTP 429 — caller should back off and retry later."""


class ProviderTemporaryError(ThreatIntelError):
    """Raised on 5xx, timeouts, network failures — transient errors."""


class ProviderParseError(ThreatIntelError):
    """Raised when the provider response cannot be parsed (e.g. bad JSON)."""
