"""
Cleanup Module
==============
Provides a scheduled / manual cleanup routine for expired reputation
records and documents *where* to invoke it.

Usage
-----
**Option A — Application startup** (recommended for most deployments)::

    from database import initialize_database, cleanup_old_domains

    initialize_database()
    cleanup_old_domains(days=180)   # ← purge stale records on boot

**Option B — Periodic background task** (e.g. APScheduler / cron)::

    # Inside a scheduler job:
    from database import cleanup_old_domains
    cleanup_old_domains(days=180)

**Option C — After every N insertions** (lightweight)::

    INSERT_THRESHOLD = 500
    insert_counter = 0

    for domain in stream_domains():
        store_malicious_domain(domain)
        insert_counter += 1
        if insert_counter >= INSERT_THRESHOLD:
            cleanup_old_domains(days=180)
            insert_counter = 0

**Option D — Standalone script** (cron entry)::

    $ python -m database.cleanup

Each option ensures the database stays compact and query performance
remains predictable over time.
"""

from __future__ import annotations

import argparse
import logging

from .repository import cleanup_old_domains

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
def main() -> None:
    """Run the cleanup once from the command line.

    Example::

        $ python -m database.cleanup                         # default 180 days
        $ python -m database.cleanup --days 90               # custom threshold
    """
    parser = argparse.ArgumentParser(
        description="Delete reputation records older than N days.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=180,
        help="Delete records whose last_seen is older than this many days (default: 180).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    deleted = cleanup_old_domains(days=args.days)
    print(f"Cleanup complete — {deleted} record(s) deleted.")


if __name__ == "__main__":
    main()
