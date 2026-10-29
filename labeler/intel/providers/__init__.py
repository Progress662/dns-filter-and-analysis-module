"""
Provider Registry
=================
Dynamically discovers and instantiates enabled threat providers.

To add a new provider:
    1. Create a new file in ``providers/``.
    2. Subclass :class:`BaseThreatProvider`, implement ``lookup(domain)``.
    3. Import the class below and add it to :data:`_PROVIDER_CLASSES`.

No other code in the framework needs modification.
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from ..correlation.models import ThreatProviderResult
from .base import BaseThreatProvider
from .virustotal import VirusTotalProvider
from .alienvault import AlienVaultOTXProvider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Registry — add new provider classes here
# ---------------------------------------------------------------------------
_PROVIDER_CLASSES: list[type[BaseThreatProvider]] = [
    VirusTotalProvider,
    AlienVaultOTXProvider,
]


def get_enabled_providers(
    config: dict,
) -> list[BaseThreatProvider]:
    """Instantiate and return all enabled providers.

    Each provider's ``is_enabled()`` method is called; only those that
    return ``True`` are included.

    Parameters
    ----------
    config : dict
        Configuration dictionary (typically from environment variables).

    Returns
    -------
    list[BaseThreatProvider]
        Enabled provider instances.
    """
    providers: list[BaseThreatProvider] = []
    for cls in _PROVIDER_CLASSES:
        instance = cls(config=config)
        if instance.is_enabled():
            providers.append(instance)
            logger.debug("Provider enabled: %s", instance.provider_name)
        else:
            logger.debug("Provider disabled: %s", instance.provider_name)

    logger.info(
        "Enabled providers (%d): %s",
        len(providers),
        [p.provider_name for p in providers],
    )
    return providers
