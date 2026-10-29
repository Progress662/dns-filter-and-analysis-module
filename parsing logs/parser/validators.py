import re
import logging
from datetime import datetime
from typing import Optional
logger = logging.getLogger(__name__)


# All fields that MUST be present in every log record
REQUIRED_FIELDS = {"timestamp", "client_ip", "domain", "query_type", "response_code"}

# Valid DNS query types (most common ones used in practice)
# This list covers standard record types you'd see in real DNS logs
VALID_QUERY_TYPES = {
    "A",        # IPv4 address
    "AAAA",     # IPv6 address
    "MX",       # Mail exchange
    "CNAME",    # Canonical name (alias)
    "TXT",      # Text records (SPF, DKIM, etc.)
    "NS",       # Nameserver
    "SOA",      # Start of Authority
    "PTR",      # Reverse DNS lookup
    "SRV",      # Service locator
    "CAA",      # Certification Authority Authorization
    "ANY",      # Any record type (sometimes used in DNS amplification attacks)
    "HTTPS",    # HTTPS service binding (modern)
    "SVCB",     # Service binding (modern)
}

VALID_RESPONSE_CODES = {
    "NOERROR",      # Success
    "NXDOMAIN",     # Non-existent domain
    "SERVFAIL",     # Server failure
    "REFUSED",      # Query refused
    "FORMERR",      # Format error
    "NOTIMP",       # Not implemented
    "YXDOMAIN",     # Name exists when it should not
    "YXRRSET",      # RR set exists when it should not
    "NXRRSET",      # RR set does not exist
    "NOTAUTH",      # Not authoritative
    "NOTZONE",      # Name not in zone
}

IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9]"           # Start with alphanumeric
    r"(?:[a-zA-Z0-9\-]{0,61}"   # Middle part: alphanumeric or hyphen
    r"[a-zA-Z0-9])?\.)+"        # Each label ends with a dot
    r"[a-zA-Z]{2,}$"            # TLD: at least 2 alpha characters
)

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",   # ISO 8601 UTC with milliseconds
    "%Y-%m-%dT%H:%M:%SZ",      # ISO 8601 UTC
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
]

class ValidationError(Exception):
    pass


def validate_required_fields(record: dict) -> None:

    missing_fields = REQUIRED_FIELDS - set(record.keys())

    if missing_fields:
        raise ValidationError(
            f"Missing required fields: {missing_fields}. "
            f"Record keys found: {set(record.keys())}"
        )

    for field_name in REQUIRED_FIELDS:
        value = record.get(field_name)
        if value is None or str(value).strip() == "":
            raise ValidationError(
                f"Required field '{field_name}' is present but empty or None. "
                f"Value received: {repr(value)}"
            )


def validate_and_parse_timestamp(timestamp_str: str) -> datetime:

    timestamp_str = str(timestamp_str).strip()

    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:

            continue

    raise ValidationError(
        f"Cannot parse timestamp '{timestamp_str}'. "
        f"Tried formats: {TIMESTAMP_FORMATS}"
    )


def validate_ip_address(ip_str: str, field_name: str = "ip") -> str:

    ip_str = str(ip_str).strip()

    # Check basic format with regex
    match = IPV4_PATTERN.match(ip_str)
    if not match:
        raise ValidationError(
            f"Field '{field_name}' contains invalid IP address format: '{ip_str}'. "
            f"Expected format: X.X.X.X (e.g., 192.168.1.1)"
        )

    octets = [int(match.group(i)) for i in range(1, 5)]
    if any(octet > 255 for octet in octets):
        raise ValidationError(
            f"Field '{field_name}' has IP '{ip_str}' with octet out of range 0-255. "
            f"Octets parsed: {octets}"
        )

    return ip_str


def validate_domain(domain_str: str) -> str:
  
    domain_str = str(domain_str).strip().lower()  # Normalize to lowercase

    # Reject obviously empty values
    if not domain_str:
        raise ValidationError("Domain field is empty.")

    # Check minimum length (e.g., "a.b" is the shortest valid domain)
    if len(domain_str) < 3:
        raise ValidationError(
            f"Domain '{domain_str}' is too short to be valid (min 3 characters)."
        )

    # Check maximum length (RFC 1035: max 253 characters)
    if len(domain_str) > 253:
        raise ValidationError(
            f"Domain '{domain_str[:30]}...' exceeds maximum length of 253 characters. "
            f"Length: {len(domain_str)}"
        )

    # We allow domains that don't match our strict pattern (e.g., punycode domains)
    # but log a warning so analysts can review them
    if not DOMAIN_PATTERN.match(domain_str):
        logger.warning(
            "Domain '%s' does not match standard format. "
            "Accepting with warning (may be punycode or internal domain).",
            domain_str
        )

    return domain_str


def validate_query_type(query_type_str: str) -> str:

    query_type = str(query_type_str).strip().upper()

    if query_type not in VALID_QUERY_TYPES:
        raise ValidationError(
            f"Unknown DNS query type: '{query_type}'. "
            f"Valid types: {sorted(VALID_QUERY_TYPES)}"
        )

    return query_type


def validate_response_code(response_code_str: str) -> str:

    response_code = str(response_code_str).strip().upper()

    if response_code not in VALID_RESPONSE_CODES:
        raise ValidationError(
            f"Unknown DNS response code: '{response_code}'. "
            f"Valid codes: {sorted(VALID_RESPONSE_CODES)}"
        )

    return response_code


def validate_ttl(ttl_value) -> Optional[int]:

    # TTL is optional — if it's None or not provided, that's acceptable
    if ttl_value is None:
        return None

        ttl_str = str(ttl_value).strip().upper()

        if ttl_str in ("", "NULL", "NONE", "N/A"):
            return None
        
    # Try converting to integer (handles "300", 300.0, "300s", etc.)
    try:
        ttl = int(float(str(ttl_value).replace("s", "").strip()))
    except (ValueError, TypeError):
        raise ValidationError(
            f"TTL value '{ttl_value}' cannot be converted to an integer."
        )

    # TTL cannot be negative
    if ttl < 0:
        raise ValidationError(
            f"TTL value {ttl} is negative. TTL must be 0 or greater."
        )

    # Sanity check: extremely large TTLs are suspicious
    # RFC 2181 says TTL max is 2^31 - 1
    MAX_TTL = 2_147_483_647
    if ttl > MAX_TTL:
        raise ValidationError(
            f"TTL value {ttl} exceeds maximum allowed value of {MAX_TTL}."
        )

    return ttl


def validate_record(raw_record: dict) -> dict:
    """
    Master validation function — runs ALL validations on a raw record.

    This is the single entry point for validation. The parser calls this
    function and gets back a cleaned, validated dictionary ready for
    conversion into a DNSRecord object.

    Args:
        raw_record: Raw dictionary parsed from the log file.

    Returns:
        dict: Cleaned and validated record with correct Python types.

    Raises:
        ValidationError: If any validation step fails.

    Flow:
        raw dict → check required fields → validate each field → return clean dict
    """
    # Step 1: Make sure all required keys are present
    validate_required_fields(raw_record)

    # Step 2: Validate and convert each field
    # Build a new clean dict rather than modifying the original
    validated = {}

    # Timestamp: string → datetime object
    validated["timestamp"] = validate_and_parse_timestamp(raw_record["timestamp"])

    # Client IP: must be valid IPv4
    validated["client_ip"] = validate_ip_address(raw_record["client_ip"], "client_ip")

    # Domain: must be non-empty, reasonable length
    validated["domain"] = validate_domain(raw_record["domain"])

    # Query type: must be a recognized DNS type
    validated["query_type"] = validate_query_type(raw_record["query_type"])

    # Response code: must be a recognized RCODE
    validated["response_code"] = validate_response_code(raw_record["response_code"])

    # Resolved IP: optional, only validate if present
    resolved_ip = raw_record.get("resolved_ip")
    if resolved_ip and str(resolved_ip).strip().upper() not in ("", "NONE", "NULL", "N/A"):
        validated["resolved_ip"] = validate_ip_address(resolved_ip, "resolved_ip")
    else:
        validated["resolved_ip"] = None  # Explicitly set to None if missing/null

    # TTL: optional integer
    validated["ttl"] = validate_ttl(raw_record.get("ttl"))

    return validated