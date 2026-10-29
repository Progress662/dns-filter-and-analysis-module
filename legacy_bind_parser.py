"""
legacy_bind_parser.py

=====================

Legacy raw BIND 9 named log parser, extracted from run_live_pipeline.py.

This module is retained exclusively for file-based / non-Kafka ingestion
paths that still deliver raw BIND 9 named log lines.

The Kafka consumer path NEVER imports or calls anything from this module.
Kafka messages arrive as pre-parsed structured JSON from Fluent Bit and are
handled by _record_from_structured_json() in run_live_pipeline.py.

Public API
----------
    parse_bind_line(raw_line, source_file, line_number) -> BindParseResult

"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from parser.models import DNSRecord

# ---------------------------------------------------------------------------
# Month abbreviation → zero-padded number (for Layout A timestamps)
# ---------------------------------------------------------------------------

_MONTH_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Layout A — native BIND timestamp at the start of the line
#   DD-Mon-YYYY HH:MM:SS.mmm …
_RE_BIND_TS = re.compile(
    r"^(?P<day>\d{1,2})-(?P<mon>[A-Za-z]{3})-(?P<year>\d{4})"
    r"\s+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
)

# Layout B — syslog prefix
#   Jan  3 14:22:01 ns1 named[1234]: …
_RE_SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+named(?:\[\d+\])?:\s+"
)

# Core client + query fields shared by both layouts.
# Matches:  … client [@view] ip#port [(server)]: query: domain class type flags (resolver)
_RE_QUERY = re.compile(
    r"client\s+"
    r"(?:@\S+\s+)?"                                     # optional @view
    r"(?P<client_ip>[\d a-fA-F:.]+)"                    # client IP (v4 or v6)
    r"#(?P<client_port>\d+)"                            # client port
    r"(?:\s+\([^)]*\))?"                               # optional (server-name)
    r":\s+"
    r"(?:query|response):\s+"
    r"(?P<domain>\S+)\s+"
    r"(?P<query_class>IN|CH|HS|ANY)\s+"
    r"(?P<query_type>[A-Z0-9]+)\s+"
    r"(?P<flags>[+\-]\S*)?"                             # optional flags (+SETDC etc.)
    r"\s*(?:\((?P<resolver_ip>[^)]+)\))?"              # optional (resolver)
)

# Response-code / TTL / resolved-IP from answer sections if present.
# Example tail: "… NOERROR 300 1.2.3.4"
_RE_RESPONSE = re.compile(
    r"\b(?P<rcode>NOERROR|NXDOMAIN|SERVFAIL|REFUSED|FORMERR|NOTIMP|YXDOMAIN|YXRRSET|NXRRSET|NOTAUTH|NOTZONE)\b"
    r"(?:\s+(?P<ttl>\d+))?"
    r"(?:\s+(?P<resolved_ip>[\d a-fA-F:.]+))?"
)

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class BindParseResult:
    success: bool
    record: Optional[DNSRecord] = None
    error: Optional[str] = None

# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _setattr_safe(obj: object, name: str, value) -> None:
    """Set an attribute only if the object doesn't already define it as a slot."""
    try:
        setattr(obj, name, value)
    except (AttributeError, TypeError):
        pass  # dataclass with __slots__ and no such field — skip silently

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_bind_line(
    raw_line: str,
    source_file: str = "file",
    line_number: int = 0,
) -> BindParseResult:
    """
    Parse one raw BIND 9 named log line into a DNSRecord.

    Supports two layouts:

      Layout A (native BIND timestamp):
        DD-Mon-YYYY HH:MM:SS.mmm client [@view] ip#port [(server)]:
            query: domain class type [+/-][SETDC] (resolver)

      Layout B (syslog-prefixed):
        Month DD HH:MM:SS hostname named[pid]: <Layout-A-tail>

    Returns a BindParseResult whose .success flag indicates whether a usable
    record was extracted.  On failure .error contains a human-readable reason.

    NOTE: This function must NEVER be called from the Kafka consumer path.
          Use _record_from_structured_json() in run_live_pipeline.py instead.
    """

    line = raw_line.strip()
    if not line:
        return BindParseResult(success=False, error="empty line")

    # ── 1. Extract timestamp ─────────────────────────────────────────────────
    timestamp_iso: Optional[str] = None
    hostname: Optional[str]      = None
    tail = line  # portion of the line after the timestamp prefix

    syslog_m = _RE_SYSLOG_TS.match(line)
    if syslog_m:
        mon  = _MONTH_MAP.get(syslog_m.group("mon").capitalize(), "01")
        day  = syslog_m.group("day").zfill(2)
        t    = syslog_m.group("time")
        # Syslog has no year — use a placeholder that TimestampUtils can handle
        year = str(time.localtime().tm_year)
        timestamp_iso = f"{year}-{mon}-{day}T{t}"
        hostname      = syslog_m.group("host")
        tail          = line[syslog_m.end():]
    else:
        bind_m = _RE_BIND_TS.match(line)
        if bind_m:
            mon  = _MONTH_MAP.get(bind_m.group("mon").capitalize(), "01")
            day  = bind_m.group("day").zfill(2)
            year = bind_m.group("year")
            t    = bind_m.group("time")
            timestamp_iso = f"{year}-{mon}-{day}T{t}"
            tail          = line[bind_m.end():]
        # If neither pattern matches we still try to extract the query fields;
        # timestamp will remain None and downstream will write NULL.

    # ── 2. Extract client / query fields ─────────────────────────────────────
    query_m = _RE_QUERY.search(tail)
    if not query_m:
        return BindParseResult(
            success=False,
            error=f"no recognisable query/response fields in: {line[:120]}",
        )

    client_ip   = query_m.group("client_ip").strip()
    client_port = query_m.group("client_port")
    domain      = query_m.group("domain").rstrip(".")
    query_class = query_m.group("query_class")
    query_type  = query_m.group("query_type")
    resolver_ip = query_m.group("resolver_ip")

    # ── 3. Extract response code / TTL / resolved IP (optional) ──────────────
    response_code: Optional[str] = None
    ttl:           Optional[int] = None
    resolved_ip:   Optional[str] = None

    resp_m = _RE_RESPONSE.search(tail)
    if resp_m:
        response_code = resp_m.group("rcode")
        raw_ttl       = resp_m.group("ttl")
        raw_resolved  = resp_m.group("resolved_ip")
        if raw_ttl:
            try:
                ttl = int(raw_ttl)
            except ValueError:
                pass
        if raw_resolved:
            resolved_ip = raw_resolved.strip()

    # Sensible default for response_code when absent
    if not response_code:
        response_code = "NOERROR"

    # ── 4. Build DNSRecord ───────────────────────────────────────────────────
    record = DNSRecord(
        timestamp=timestamp_iso,
        client_ip=client_ip,
        domain=domain,
        query_type=query_type,
        response_code=response_code,
        resolved_ip=resolved_ip,
        ttl=ttl,
        raw_line=raw_line,
        source_file=source_file,
        # Fields that ParsedBINDLine carried but raw BIND lines may not expose
        # are set to None; DNSDatasetCSVWriter fills them with its defaults.
        label=None,
        threat_score=None,
        confidence=None,
        label_reason=None,
    )

    # Attach optional extra fields via setattr so we don't break DNSRecord if
    # it doesn't declare them, but csv_writer can still pick them up via getattr.
    _setattr_safe(record, "client_port",        client_port)
    _setattr_safe(record, "resolver_ip",         resolver_ip)
    _setattr_safe(record, "query_class",         query_class)
    _setattr_safe(record, "hostname",            hostname)
    _setattr_safe(record, "server_name",         None)
    _setattr_safe(record, "transport_protocol",  None)
    _setattr_safe(record, "log_category",        None)
    _setattr_safe(record, "severity",            None)
    _setattr_safe(record, "thread_id",           None)
    _setattr_safe(record, "process_id",          None)
    _setattr_safe(record, "line_number",         line_number)

    return BindParseResult(success=True, record=record)