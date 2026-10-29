"""
DNS Client Profiling Database Module

This module provides a simple interface for tracking DNS client behavior.
It maintains profiles for each client IP and records every unique domain
they query along with timestamps and visit counts.

Usage:
    from client_profiling import process_query
    
    process_query("192.168.1.39", "huggingface.co")
"""

from .manager import process_query
from .cleanup import cleanup_old_records
from .db import initialize_pool, close_pool

__version__ = "1.0.0"
__all__ = ["process_query", "cleanup_old_records", "initialize_pool", "close_pool"]