"""
Utility functions for the unknown domain repository subsystem.

This module provides common utilities for domain validation, performance monitoring,
data conversion, and helper functions used throughout the repository subsystem.
All functions are designed to be stateless and reusable.
"""

import hashlib
import ipaddress
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import (
    Any, Dict, List, Optional, Set, Tuple, Union, Iterator, Generator,
    Callable, TypeVar
)
from urllib.parse import urlparse

from .constants import DOMAIN_PATTERN, DOMAIN_LENGTH_MAX, DOMAIN_LABEL_MAX
from .exceptions import DomainValidationError

# Type variables for generic functions
T = TypeVar('T')
F = TypeVar('F', bound=Callable[..., Any])


# =============================================================================
# Domain Validation and Normalization
# =============================================================================

def is_valid_domain_format(domain: str) -> bool:
    """
    Check if domain has valid format without raising exceptions.
    
    Fast validation check for filtering before more expensive operations.
    
    Args:
        domain: Domain name to validate.
        
    Returns:
        True if domain format is valid, False otherwise.
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Basic length check
    if len(domain) > DOMAIN_LENGTH_MAX or len(domain) < 3:
        return False
    
    # Quick pattern check
    if not DOMAIN_PATTERN.match(domain.lower()):
        return False
    
    # Check for obvious invalid patterns
    if (domain.startswith('.') or domain.endswith('.') or 
        '..' in domain or domain.startswith('-') or domain.endswith('-')):
        return False
    
    return True


def normalize_domain(domain: str) -> str:
    """
    Normalize domain name to canonical form.
    
    Performs lowercase conversion, whitespace trimming, and basic cleanup
    without full validation.
    
    Args:
        domain: Raw domain name.
        
    Returns:
        Normalized domain name.
    """
    if not domain:
        return domain
    
    # Basic normalization
    normalized = domain.strip().lower()
    
    # Remove common prefixes that shouldn't be stored
    prefixes_to_remove = ['www.', 'ftp.', 'mail.']
    for prefix in prefixes_to_remove:
        if normalized.startswith(prefix) and len(normalized) > len(prefix):
            # Only remove if there's something after the prefix
            remaining = normalized[len(prefix):]
            if '.' in remaining:  # Ensure it's not just the prefix
                normalized = remaining
                break
    
    return normalized


def extract_root_domain(domain: str) -> str:
    """
    Extract root domain from subdomain.
    
    Attempts to identify the root domain by finding the last two labels,
    with special handling for known multi-part TLDs.
    
    Args:
        domain: Full domain name (may include subdomains).
        
    Returns:
        Root domain (e.g., "example.com" from "sub.example.com").
    """
    if not domain:
        return domain
    
    normalized = normalize_domain(domain)
    parts = normalized.split('.')
    
    if len(parts) < 2:
        return normalized
    
    # Special handling for common multi-part TLDs
    multi_part_tlds = {
        'co.uk', 'co.jp', 'com.au', 'com.br', 'co.za',
        'gov.uk', 'ac.uk', 'org.uk', 'net.au', 'gov.au'
    }
    
    if len(parts) >= 3:
        # Check for multi-part TLD
        potential_tld = '.'.join(parts[-2:])
        if potential_tld in multi_part_tlds:
            # Take domain + multi-part TLD
            if len(parts) >= 3:
                return '.'.join(parts[-3:])
        
    # Default: take last two parts
    return '.'.join(parts[-2:])


def is_ip_address(value: str) -> bool:
    """
    Check if string represents an IP address.
    
    Args:
        value: String to check.
        
    Returns:
        True if value is a valid IP address (IPv4 or IPv6).
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_domain(domain: str) -> bool:
    """
    Check if domain appears to be for internal/private use.
    
    Identifies domains that are likely internal networks or test domains
    that should not be stored in threat intelligence.
    
    Args:
        domain: Domain name to check.
        
    Returns:
        True if domain appears to be private/internal.
    """
    if not domain:
        return False
    
    domain = domain.lower()
    
    # RFC 6761 special-use domains
    special_domains = {
        'localhost', 'local', 'test', 'invalid',
        'example', 'example.com', 'example.net', 'example.org'
    }
    
    if domain in special_domains:
        return True
    
    # Check for special TLDs
    private_tlds = {'.local', '.test', '.invalid', '.localhost', '.lan', '.internal'}
    for tld in private_tlds:
        if domain.endswith(tld):
            return True
    
    # Check for IP addresses
    if is_ip_address(domain):
        return True
    
    # Check for obvious internal patterns
    internal_patterns = [
        r'^[0-9]+\.',  # Starts with numbers (likely IP-like)
        r'\.local$',   # Ends with .local
        r'\.lan$',     # Ends with .lan
        r'^localhost', # Starts with localhost
        r'internal',   # Contains "internal"
        r'intranet',   # Contains "intranet"
    ]
    
    for pattern in internal_patterns:
        if re.search(pattern, domain):
            return True
    
    return False


# =============================================================================
# Performance and Timing Utilities
# =============================================================================

@contextmanager
def timer() -> Generator[Callable[[], float], None, None]:
    """
    Context manager for timing operations.
    
    Yields:
        Function that returns elapsed time in seconds.
        
    Example:
        with timer() as get_time:
            # do work
            elapsed = get_time()
    """
    start_time = time.perf_counter()
    
    def get_elapsed() -> float:
        return time.perf_counter() - start_time
    
    yield get_elapsed


def timing_stats(func: F) -> F:
    """
    Decorator to collect timing statistics for functions.
    
    Adds timing information to function calls and tracks performance.
    
    Args:
        func: Function to wrap with timing.
        
    Returns:
        Wrapped function with timing collection.
    """
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            duration = time.perf_counter() - start_time
            
            # Store timing info in function attribute
            if not hasattr(wrapper, '_timing_stats'):
                wrapper._timing_stats = []
            wrapper._timing_stats.append(duration)
            
            # Keep only last 100 measurements
            if len(wrapper._timing_stats) > 100:
                wrapper._timing_stats = wrapper._timing_stats[-100:]
            
            return result
        except Exception as e:
            duration = time.perf_counter() - start_time
            # Log error timing too
            if not hasattr(wrapper, '_error_stats'):
                wrapper._error_stats = []
            wrapper._error_stats.append(duration)
            raise
    
    # Copy function metadata
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


def get_timing_summary(func: Callable) -> Dict[str, Any]:
    """
    Get timing summary for a function decorated with @timing_stats.
    
    Args:
        func: Function to get timing summary for.
        
    Returns:
        Dictionary with timing statistics.
    """
    if not hasattr(func, '_timing_stats'):
        return {'error': 'Function not decorated with @timing_stats'}
    
    timings = func._timing_stats
    if not timings:
        return {'calls': 0}
    
    return {
        'calls': len(timings),
        'total_time': sum(timings),
        'avg_time': sum(timings) / len(timings),
        'min_time': min(timings),
        'max_time': max(timings),
        'last_time': timings[-1] if timings else None
    }


# =============================================================================
# Data Conversion and Serialization
# =============================================================================

def safe_json_serialize(obj: Any) -> Any:
    """
    Safely serialize object for JSON output.
    
    Handles datetime objects, sets, and other non-JSON-serializable types.
    
    Args:
        obj: Object to serialize.
        
    Returns:
        JSON-serializable representation of the object.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif hasattr(obj, '__dict__'):
        # Handle custom objects
        return {k: safe_json_serialize(v) for k, v in obj.__dict__.items()
                if not k.startswith('_')}
    elif isinstance(obj, (list, tuple)):
        return [safe_json_serialize(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: safe_json_serialize(v) for k, v in obj.items()}
    else:
        return obj


def chunk_list(items: List[T], chunk_size: int) -> Iterator[List[T]]:
    """
    Split list into chunks of specified size.
    
    Args:
        items: List to chunk.
        chunk_size: Size of each chunk.
        
    Yields:
        List chunks of the specified size.
    """
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive")
    
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]


def deduplicate_domains(domains: List[str], preserve_order: bool = True) -> List[str]:
    """
    Remove duplicate domains from list.
    
    Args:
        domains: List of domain names.
        preserve_order: Whether to preserve original order.
        
    Returns:
        List of unique domains.
    """
    if preserve_order:
        seen = set()
        result = []
        for domain in domains:
            normalized = normalize_domain(domain)
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result
    else:
        return list(set(normalize_domain(d) for d in domains))


# =============================================================================
# Hashing and Fingerprinting
# =============================================================================

def domain_hash(domain: str, algorithm: str = 'sha256') -> str:
    """
    Generate hash of domain name for deduplication or fingerprinting.
    
    Args:
        domain: Domain name to hash.
        algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256').
        
    Returns:
        Hexadecimal hash string.
        
    Raises:
        ValueError: If algorithm is not supported.
    """
    normalized = normalize_domain(domain)
    
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hasher.update(normalized.encode('utf-8'))
    return hasher.hexdigest()


def batch_hash(domains: List[str], algorithm: str = 'sha256') -> str:
    """
    Generate hash of a batch of domains for integrity checking.
    
    Args:
        domains: List of domain names.
        algorithm: Hash algorithm to use.
        
    Returns:
        Hexadecimal hash string representing the batch.
    """
    # Sort domains to ensure consistent hash regardless of order
    sorted_domains = sorted(normalize_domain(d) for d in domains)
    combined = '\n'.join(sorted_domains)
    
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha1':
        hasher = hashlib.sha1()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hasher.update(combined.encode('utf-8'))
    return hasher.hexdigest()


# =============================================================================
# Validation Helpers
# =============================================================================

def validate_timestamp(timestamp: Any) -> bool:
    """
    Validate that object is a proper timestamp.
    
    Args:
        timestamp: Object to validate as timestamp.
        
    Returns:
        True if valid timestamp, False otherwise.
    """
    if not isinstance(timestamp, datetime):
        return False
    
    # Check if timezone-aware
    if timestamp.tzinfo is None:
        return False
    
    # Check reasonable date range (not too far in past/future)
    now = datetime.now(timezone.utc)
    min_date = datetime(2000, 1, 1, tzinfo=timezone.utc)
    max_date = now.replace(year=now.year + 10)  # 10 years in future
    
    return min_date <= timestamp <= max_date


def validate_metadata_size(metadata: Dict[str, Any], max_size_bytes: int = 1048576) -> bool:
    """
    Validate metadata size is within limits.
    
    Args:
        metadata: Metadata dictionary to validate.
        max_size_bytes: Maximum size in bytes (default: 1MB).
        
    Returns:
        True if metadata is within size limits.
    """
    if metadata is None:
        return True
    
    try:
        import json
        serialized = json.dumps(metadata, default=safe_json_serialize)
        return len(serialized.encode('utf-8')) <= max_size_bytes
    except Exception:
        return False


# =============================================================================
# URL and Domain Extraction
# =============================================================================

def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain name from URL.
    
    Args:
        url: URL string to parse.
        
    Returns:
        Domain name if successfully extracted, None otherwise.
    """
    if not url:
        return None
    
    try:
        # Add scheme if missing
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove username:password if present
        if '@' in domain:
            domain = domain.split('@')[-1]
        
        # Validate extracted domain
        if is_valid_domain_format(domain):
            return normalize_domain(domain)
        
        return None
        
    except Exception:
        return None


def extract_domains_from_text(text: str) -> Set[str]:
    """
    Extract domain names from text using pattern matching.
    
    Useful for parsing log files or extracting domains from various text formats.
    
    Args:
        text: Text to search for domain names.
        
    Returns:
        Set of unique domain names found.
    """
    if not text:
        return set()
    
    # Pattern for domain-like strings
    domain_pattern = re.compile(
        r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    
    matches = domain_pattern.findall(text)
    domains = set()
    
    for match in matches:
        if isinstance(match, tuple):
            # findall with groups returns tuples
            domain = match[0] if match[0] else match[1]
        else:
            domain = match
        
        # Additional validation
        if (domain and 
            is_valid_domain_format(domain) and 
            not is_private_domain(domain) and
            not is_ip_address(domain)):
            domains.add(normalize_domain(domain))
    
    return domains


# =============================================================================
# Testing and Development Utilities
# =============================================================================

def generate_test_domains(count: int, base_domain: str = "testdomain.com") -> List[str]:
    """
    Generate test domains for development and testing.
    
    Args:
        count: Number of test domains to generate.
        base_domain: Base domain name to use.
        
    Returns:
        List of unique test domain names.
    """
    import random
    import string
    
    domains = []
    root = extract_root_domain(base_domain)
    
    for i in range(count):
        # Generate random subdomain
        subdomain_length = random.randint(5, 15)
        subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=subdomain_length))
        
        # Avoid starting with digit or hyphen
        if subdomain[0].isdigit() or subdomain[0] == '-':
            subdomain = 'a' + subdomain[1:]
        
        domain = f"{subdomain}.{root}"
        domains.append(domain)
    
    return domains


def create_performance_test_data(domain_count: int) -> Tuple[List[str], Dict[str, Any]]:
    """
    Create test data for performance testing.
    
    Args:
        domain_count: Number of domains to generate.
        
    Returns:
        Tuple of (domain list, metadata dict with test info).
    """
    import random
    
    # Generate mix of domain patterns
    domains = []
    patterns = [
        "subdomain{}.example.com",
        "test{}.domain.org", 
        "site{}.company.net",
        "app{}.service.io",
        "api{}.platform.co"
    ]
    
    for i in range(domain_count):
        pattern = random.choice(patterns)
        domain = pattern.format(i)
        domains.append(domain)
    
    # Add some duplicates for testing deduplication
    duplicate_count = min(100, domain_count // 10)
    for _ in range(duplicate_count):
        domains.append(random.choice(domains))
    
    metadata = {
        'total_generated': len(domains),
        'unique_domains': domain_count,
        'duplicate_domains': duplicate_count,
        'patterns_used': len(patterns),
        'generation_timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    return domains, metadata


# =============================================================================
# Memory and Resource Utilities
# =============================================================================

def estimate_memory_usage(domains: List[str]) -> Dict[str, Any]:
    """
    Estimate memory usage for a list of domains.
    
    Args:
        domains: List of domain names.
        
    Returns:
        Dictionary with memory usage estimates.
    """
    import sys
    
    if not domains:
        return {'total_bytes': 0, 'avg_bytes_per_domain': 0}
    
    # Calculate string sizes
    total_string_bytes = sum(len(d.encode('utf-8')) for d in domains)
    
    # Python string object overhead (approximate)
    string_overhead = len(domains) * sys.getsizeof("")
    
    # List overhead
    list_overhead = sys.getsizeof(domains)
    
    total_bytes = total_string_bytes + string_overhead + list_overhead
    avg_bytes_per_domain = total_bytes / len(domains)
    
    return {
        'total_bytes': total_bytes,
        'total_mb': round(total_bytes / 1024 / 1024, 2),
        'avg_bytes_per_domain': round(avg_bytes_per_domain, 2),
        'string_data_bytes': total_string_bytes,
        'python_overhead_bytes': string_overhead + list_overhead,
        'domain_count': len(domains)
    }


@contextmanager
def memory_limit_check(max_mb: float) -> Generator[Callable[[], float], None, None]:
    """
    Context manager to monitor memory usage and enforce limits.
    
    Args:
        max_mb: Maximum memory usage in megabytes.
        
    Yields:
        Function that returns current memory usage in MB.
        
    Raises:
        MemoryError: If memory usage exceeds limit.
    """
    import psutil
    import os
    
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss / 1024 / 1024
    
    def get_current_memory() -> float:
        current_memory = process.memory_info().rss / 1024 / 1024
        return current_memory - initial_memory
    
    def check_limit() -> None:
        current = get_current_memory()
        if current > max_mb:
            raise MemoryError(f"Memory usage ({current:.2f} MB) exceeds limit ({max_mb} MB)")
    
    try:
        yield get_current_memory
    finally:
        check_limit()