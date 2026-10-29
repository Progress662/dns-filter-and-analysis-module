from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional


@dataclass
class DNSRecord:
    """
    Represents a single parsed DNS log entry.

    Each field maps directly to a column/key in the raw log file.
    Optional fields handle cases where some logs may omit certain data
    (e.g., NXDOMAIN responses have no resolved_ip).

    Attributes:
        timestamp    : When the DNS query was made (as a Python datetime object)
        client_ip    : IP address of the machine that made the DNS query
        domain       : The domain name that was queried (e.g., "google.com")
        query_type   : DNS record type requested (A, AAAA, MX, CNAME, TXT, etc.)
        response_code: Server response status (NOERROR, NXDOMAIN, SERVFAIL, etc.)
        resolved_ip  : IP address returned by the DNS server (None if query failed)
        ttl          : Time-To-Live in seconds (how long to cache the result)
        raw_line     : The original unparsed log line (kept for debugging)
        source_file  : Which log file this record came from
    """

    timestamp: datetime          
    client_ip: str               
    domain: str                  
    query_type: str              
    response_code: str           

    resolved_ip: Optional[str] = None   
    ttl: Optional[int] = None

    label: Optional[str] = None
    threat_score: Optional[int] = None
    confidence: Optional[int] = None
    label_reason: Optional[str] = None           

    raw_line: Optional[str] = field(default=None, repr=False)   
    source_file: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        data = asdict(self)
        if isinstance(data.get("timestamp"), datetime):
            data["timestamp"] = data["timestamp"].isoformat()
        return data

    def is_failed_query(self) -> bool:

        return self.response_code != "NOERROR"

    def is_private_client(self) -> bool:

        private_prefixes = ("10.", "172.16.", "172.17.", "192.168.")
        return self.client_ip.startswith(private_prefixes)

    def __str__(self) -> str:

        status = "✓" if not self.is_failed_query() else "✗"
        return (
            f"[{status}] {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | "
            f"{self.client_ip:>15} → {self.domain:<40} "
            f"[{self.query_type:>5}] → {self.resolved_ip or 'N/A'} "
            f"({self.response_code})"
        )