"""
API Key Manager
===============
Thread-safe, round-robin API key rotation with per-key rate-limit
cooldown support.

Designed for threat intelligence providers that have multiple API keys
and need to gracefully handle rate-limiting (HTTP 429) by temporarily
removing a key from rotation.
"""

from __future__ import annotations

import time
import threading
from typing import Optional


class APIKeyManager:
    """Manages a pool of API keys with round-robin rotation and rate-limit
    cooldown.

    Parameters
    ----------
    keys : list[str]
        One or more API keys.  Empty strings are silently ignored.
        If all keys are empty, the pool is empty and ``get_next_key()``
        returns ``None``.
    """

    def __init__(self, keys: list[str]) -> None:
        # Filter out empty strings
        self._keys: list[str] = [k for k in keys if k]

        # Round-robin state
        self._index: int = 0

        # Cooldown tracking: key -> timestamp when it becomes available again
        self._cooldowns: dict[str, float] = {}

        # Thread safety
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_next_key(self) -> Optional[str]:
        """Return the next available API key (round-robin).

        Keys currently on cooldown are skipped.  If all keys are on
        cooldown or the pool is empty, returns ``None``.

        Returns
        -------
        str or None
        """
        with self._lock:
            if not self._keys:
                return None

            now: float = time.monotonic()
            # Clean expired cooldowns so we don't accumulate stale entries
            self._cooldowns = {
                k: until for k, until in self._cooldowns.items()
                if until > now
            }

            # Try up to the number of keys to find an available one
            for _ in range(len(self._keys)):
                candidate: str = self._keys[self._index]
                self._index = (self._index + 1) % len(self._keys)

                if candidate not in self._cooldowns:
                    return candidate

            # All keys are on cooldown
            return None

    def mark_rate_limited(
        self, key: str, cooldown_seconds: int = 60
    ) -> None:
        """Mark *key* as rate-limited so it is not returned by
        ``get_next_key()`` until the cooldown expires.

        Parameters
        ----------
        key : str
            The API key that was rate-limited.
        cooldown_seconds : int
            Number of seconds to wait before the key becomes available
            again (default 60).
        """
        if not key:
            return

        until: float = time.monotonic() + max(float(cooldown_seconds), 0.0)
        with self._lock:
            self._cooldowns[key] = until

    def available_keys(self) -> list[str]:
        """Return a list of keys that are **not** currently on cooldown.

        Returns
        -------
        list[str]
        """
        with self._lock:
            now: float = time.monotonic()
            return [
                k
                for k in self._keys
                if k not in self._cooldowns
                or self._cooldowns[k] <= now
            ]

    def reset(self) -> None:
        """Reset the round-robin index and clear all cooldowns."""
        with self._lock:
            self._index = 0
            self._cooldowns.clear()