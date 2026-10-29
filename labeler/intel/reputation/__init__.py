"""
DNS Threat Intelligence — PostgreSQL Reputation Database
=======================================================
A production-quality, extensible reputation database module
that stores malicious domains detected by the DNS pipeline.

Exposed public API (single import):
    initialize_database()
    store_malicious_domain(domain, metadata=None)
    get_domain(domain)
    update_domain(domain, **kwargs)
    cleanup_old_domains(days=180)
    close_connection()

Design philosophy:
    - One function call from the pipeline stores a malicious domain.
    - Automatic deduplication via PostgreSQL ON CONFLICT.
    - Automatic cleanup of stale records (last_seen > 180 days).
    - Extensible architecture for future sources (VirusTotal, etc.).
"""

from .repository import (
    initialize_database,
    store_malicious_domain,
    get_domain,
    update_domain,
    cleanup_old_domains,
    close_connection,
)

__all__ = [
    "initialize_database",
    "store_malicious_domain",
    "get_domain",
    "update_domain",
    "cleanup_old_domains",
    "close_connection",
]
