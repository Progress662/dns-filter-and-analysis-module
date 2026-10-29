"""
Domain models and data classes for the unknown domain repository subsystem.

This module provides the core domain entities used throughout the subsystem,
including domain validation, serialization, and database mapping support.
All models are designed to be immutable and type-safe.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Tuple
from uuid import UUID, uuid4

from .constants import (
    DomainStatus, 
    DomainSource, 
    SCHEMA_VERSION,
    ALL_COLUMNS,
    INSERT_COLUMNS
)
from .exceptions import DomainValidationError


# Domain validation patterns
DOMAIN_PATTERN = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)
"""
RFC-compliant domain name pattern.
- Labels can contain letters, numbers, and hyphens
- Labels cannot start or end with hyphens
- Labels cannot exceed 63 characters
- Total domain length validated separately
"""

DOMAIN_LENGTH_MAX = 253
"""Maximum total length for domain names per RFC 1035."""

DOMAIN_LABEL_MAX = 63
"""Maximum length for individual domain labels per RFC 1035."""


def validate_domain_name(domain: str) -> str:
    """
    Validate and normalize domain name according to RFC standards.
    
    Args:
        domain: Raw domain name to validate.
        
    Returns:
        Normalized domain name (lowercase, stripped).
        
    Raises:
        DomainValidationError: If domain name is invalid.
    """
    if not domain:
        raise DomainValidationError("Domain name cannot be empty")
    
    # Normalize: strip whitespace and convert to lowercase
    normalized = domain.strip().lower()
    
    if not normalized:
        raise DomainValidationError("Domain name cannot be empty after normalization")
    
    # Check total length
    if len(normalized) > DOMAIN_LENGTH_MAX:
        raise DomainValidationError(
            f"Domain name exceeds maximum length ({len(normalized)} > {DOMAIN_LENGTH_MAX})",
            domain=normalized,
            validation_rule="max_length"
        )
    
    # Check for invalid characters and structure
    if not DOMAIN_PATTERN.match(normalized):
        raise DomainValidationError(
            "Domain name contains invalid characters or structure",
            domain=normalized,
            validation_rule="rfc_pattern"
        )
    
    # Check individual label lengths
    labels = normalized.split('.')
    for label in labels:
        if len(label) > DOMAIN_LABEL_MAX:
            raise DomainValidationError(
                f"Domain label exceeds maximum length ({len(label)} > {DOMAIN_LABEL_MAX}): {label}",
                domain=normalized,
                validation_rule="label_max_length"
            )
        
        if not label:
            raise DomainValidationError(
                "Domain contains empty label",
                domain=normalized,
                validation_rule="empty_label"
            )
    
    # Check for localhost and other invalid domains
    invalid_domains = {'localhost', 'local', ''}
    if normalized in invalid_domains:
        raise DomainValidationError(
            f"Domain name is reserved: {normalized}",
            domain=normalized,
            validation_rule="reserved_domain"
        )
    
    return normalized


def validate_metadata(metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Validate metadata dictionary for JSON serialization.
    
    Args:
        metadata: Metadata dictionary to validate.
        
    Returns:
        Validated metadata or None.
        
    Raises:
        DomainValidationError: If metadata is not JSON serializable.
    """
    if metadata is None:
        return None
    
    if not isinstance(metadata, dict):
        raise DomainValidationError(
            "Metadata must be a dictionary",
            validation_rule="metadata_type"
        )
    
    # Test JSON serialization
    try:
        json.dumps(metadata)
    except (TypeError, ValueError) as e:
        raise DomainValidationError(
            f"Metadata is not JSON serializable: {e}",
            validation_rule="metadata_serialization"
        ) from e
    
    return metadata


@dataclass(frozen=True)
class UnknownDomain:
    """
    Immutable domain entity representing a domain not found in known threat intelligence.
    
    This is the core domain model used throughout the subsystem. It represents
    a domain that was encountered in DNS logs but was not found in the Tranco
    or URLhaus databases, making it an "unknown" domain requiring persistence
    and future enrichment.
    
    Attributes:
        domain: The normalized domain name.
        first_seen: When this domain was first encountered.
        last_seen: When this domain was last encountered.
        source: Where this domain was extracted from.
        status: Current processing status.
        metadata: Extensible metadata for enrichment data.
        id: Unique identifier (None for new domains).
        created_at: When the record was created (None for new domains).
        updated_at: When the record was last updated (None for new domains).
        schema_version: Database schema version for migration support.
        client_ip: Originating client IP address for the DNS query that
            surfaced this domain (optional; not a physical DB column —
            persisted inside ``metadata`` under the ``client_ip`` key).
        query_type: DNS query type (e.g. ``A``, ``AAAA``, ``MX``, ``TXT``,
            ``PTR``, ``CNAME``, ``NS``, ``SOA``) for the query that
            surfaced this domain (optional; persisted inside ``metadata``
            under the ``query_type`` key).
    """
    
    domain: str
    first_seen: datetime
    last_seen: datetime
    source: DomainSource
    status: DomainStatus = field(default=DomainStatus.NEW)
    metadata: Optional[Dict[str, Any]] = field(default=None)
    id: Optional[int] = field(default=None)
    created_at: Optional[datetime] = field(default=None)
    updated_at: Optional[datetime] = field(default=None)
    schema_version: int = field(default=SCHEMA_VERSION)
    client_ip: Optional[str] = field(default=None)
    query_type: Optional[str] = field(default=None)
    
    def __post_init__(self) -> None:
        """Validate domain entity after initialization."""
        # Validate domain name (this will raise if invalid)
        validated_domain = validate_domain_name(self.domain)
        
        # Use object.__setattr__ since dataclass is frozen
        object.__setattr__(self, 'domain', validated_domain)
        
        # Validate timestamps
        if self.first_seen.tzinfo is None:
            raise DomainValidationError(
                "first_seen must be timezone-aware",
                domain=self.domain,
                validation_rule="timezone_aware"
            )
        
        if self.last_seen.tzinfo is None:
            raise DomainValidationError(
                "last_seen must be timezone-aware", 
                domain=self.domain,
                validation_rule="timezone_aware"
            )
        
        if self.last_seen < self.first_seen:
            raise DomainValidationError(
                "last_seen cannot be before first_seen",
                domain=self.domain,
                validation_rule="timestamp_order"
            )
        
        # Validate metadata
        validated_metadata = validate_metadata(self.metadata)
        object.__setattr__(self, 'metadata', validated_metadata)
        
        # Validate status and source are proper enum values
        if not isinstance(self.status, DomainStatus):
            raise DomainValidationError(
                f"Invalid status: {self.status}",
                domain=self.domain,
                validation_rule="status_enum"
            )
        
        if not isinstance(self.source, DomainSource):
            raise DomainValidationError(
                f"Invalid source: {self.source}",
                domain=self.domain,
                validation_rule="source_enum"
            )
    
    @classmethod
    def create_new(
        cls,
        domain: str,
        first_seen: datetime,
        last_seen: Optional[datetime] = None,
        source: DomainSource = DomainSource.DNS_QUERY_LOG,
        metadata: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None
    ) -> 'UnknownDomain':
        """
        Create a new unknown domain entity for initial persistence.
        
        Args:
            domain: Domain name to create.
            first_seen: When domain was first encountered.
            last_seen: When domain was last seen (defaults to first_seen).
            source: Source of the domain.
            metadata: Optional metadata.
            client_ip: Optional originating client IP.
            query_type: Optional DNS query type.
            
        Returns:
            New UnknownDomain instance ready for persistence.
        """
        if last_seen is None:
            last_seen = first_seen
            
        return cls(
            domain=domain,
            first_seen=first_seen,
            last_seen=last_seen,
            source=source,
            status=DomainStatus.NEW,
            metadata=metadata,
            client_ip=client_ip,
            query_type=query_type
        )
    
    @classmethod
    def from_database_row(
        cls,
        row: Union[Tuple, Dict[str, Any]]
    ) -> 'UnknownDomain':
        """
        Create UnknownDomain from database row data.
        
        Args:
            row: Database row as tuple or dictionary.
            
        Returns:
            UnknownDomain instance populated from database data.
            
        Raises:
            DomainValidationError: If row data is invalid.
        """
        if isinstance(row, dict):
            return cls._from_dict(row)
        elif isinstance(row, (tuple, list)):
            return cls._from_tuple(row)
        else:
            raise DomainValidationError(
                f"Invalid row type: {type(row)}",
                validation_rule="row_type"
            )
    
    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> 'UnknownDomain':
        """Create instance from dictionary (named row access)."""
        # Parse metadata from JSON string if needed
        metadata = data.get('metadata')
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata) if metadata else None
            except json.JSONDecodeError as e:
                raise DomainValidationError(
                    f"Invalid metadata JSON: {e}",
                    domain=data.get('domain', 'unknown'),
                    validation_rule="metadata_json"
                ) from e
        
        # client_ip / query_type are not physical columns - they are
        # recovered from inside the metadata JSON blob if present there.
        client_ip = (metadata or {}).get('client_ip')
        query_type = (metadata or {}).get('query_type')
        
        return cls(
            id=data['id'],
            domain=data['domain'],
            first_seen=data['first_seen'],
            last_seen=data['last_seen'],
            source=DomainSource(data['source']),
            status=DomainStatus(data['status']),
            metadata=metadata,
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            schema_version=data.get('schema_version', SCHEMA_VERSION),
            client_ip=client_ip,
            query_type=query_type
        )
    
    @classmethod  
    def _from_tuple(cls, row: Tuple) -> 'UnknownDomain':
        """Create instance from tuple (positional row access)."""
        if len(row) != len(ALL_COLUMNS):
            raise DomainValidationError(
                f"Row has {len(row)} columns, expected {len(ALL_COLUMNS)}",
                validation_rule="column_count"
            )
        
        # Parse metadata from JSON string
        metadata_str = row[6]  # metadata column position
        metadata = None
        if metadata_str:
            try:
                metadata = json.loads(metadata_str)
            except json.JSONDecodeError as e:
                raise DomainValidationError(
                    f"Invalid metadata JSON: {e}",
                    domain=row[1],  # domain column position
                    validation_rule="metadata_json"
                ) from e
        
        # client_ip / query_type are not physical columns - they are
        # recovered from inside the metadata JSON blob if present there.
        client_ip = (metadata or {}).get('client_ip')
        query_type = (metadata or {}).get('query_type')
        
        return cls(
            id=row[0],
            domain=row[1],
            first_seen=row[2],
            last_seen=row[3],
            source=DomainSource(row[4]),
            status=DomainStatus(row[5]),
            metadata=metadata,
            created_at=row[7],
            updated_at=row[8],
            schema_version=row[9],
            client_ip=client_ip,
            query_type=query_type
        )
    
    def to_database_values(self, include_id: bool = False) -> Tuple[Any, ...]:
        """
        Convert domain to tuple of values for database insertion.

        ``client_ip`` and ``query_type`` are not physical columns in this
        table's schema (``ALL_COLUMNS``/``INSERT_COLUMNS`` are unchanged),
        so they are merged into the serialized ``metadata`` JSON blob
        rather than appended as new positional values. This keeps the
        returned tuple's length and column order identical to before.
        
        Args:
            include_id: Whether to include ID in values (for updates).
            
        Returns:
            Tuple of values matching database column order.
        """
        merged_metadata = dict(self.metadata) if self.metadata else {}
        if self.client_ip is not None:
            merged_metadata['client_ip'] = self.client_ip
        if self.query_type is not None:
            merged_metadata['query_type'] = self.query_type
        metadata_json = json.dumps(merged_metadata) if merged_metadata else None
        
        values = [
            self.domain,
            self.first_seen,
            self.last_seen,
            self.source.value,
            self.status.value,
            metadata_json,
            self.created_at or datetime.now(timezone.utc),
            self.updated_at or datetime.now(timezone.utc),
            self.schema_version
        ]
        
        if include_id:
            values.insert(0, self.id)
            
        return tuple(values)
    
    def to_dict(self, include_timestamps: bool = True) -> Dict[str, Any]:
        """
        Convert domain to dictionary for JSON serialization or logging.
        
        Args:
            include_timestamps: Whether to include audit timestamps.
            
        Returns:
            Dictionary representation of the domain.
        """
        result = {
            'domain': self.domain,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'source': self.source.value,
            'status': self.status.value,
            'schema_version': self.schema_version
        }
        
        if self.id is not None:
            result['id'] = self.id
            
        if self.metadata:
            result['metadata'] = self.metadata

        if self.client_ip is not None:
            result['client_ip'] = self.client_ip

        if self.query_type is not None:
            result['query_type'] = self.query_type
            
        if include_timestamps:
            if self.created_at:
                result['created_at'] = self.created_at.isoformat()
            if self.updated_at:
                result['updated_at'] = self.updated_at.isoformat()
        
        return result
    
    def with_updated_status(
        self, 
        status: DomainStatus,
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'UnknownDomain':
        """
        Create a new instance with updated status and optional metadata.
        
        This method supports future enrichment workflows where domain
        status and enrichment metadata need to be updated.
        
        Args:
            status: New status to set.
            metadata: Optional new metadata to merge or replace.
            
        Returns:
            New UnknownDomain instance with updated fields.
        """
        # Merge metadata if both exist
        new_metadata = self.metadata or {}
        if metadata:
            new_metadata = {**new_metadata, **metadata}
        
        return UnknownDomain(
            id=self.id,
            domain=self.domain,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            source=self.source,
            status=status,
            metadata=new_metadata if new_metadata else None,
            created_at=self.created_at,
            updated_at=datetime.now(timezone.utc),
            schema_version=self.schema_version,
            client_ip=self.client_ip,
            query_type=self.query_type
        )
    
    def with_updated_last_seen(
        self, 
        last_seen: datetime
    ) -> 'UnknownDomain':
        """
        Create a new instance with updated last_seen timestamp.
        
        Used when the same domain is encountered again to update
        the last observation time.
        
        Args:
            last_seen: New last seen timestamp.
            
        Returns:
            New UnknownDomain instance with updated last_seen.
        """
        return UnknownDomain(
            id=self.id,
            domain=self.domain,
            first_seen=self.first_seen,
            last_seen=last_seen,
            source=self.source,
            status=self.status,
            metadata=self.metadata,
            created_at=self.created_at,
            updated_at=datetime.now(timezone.utc),
            schema_version=self.schema_version,
            client_ip=self.client_ip,
            query_type=self.query_type
        )
    
    def __str__(self) -> str:
        """String representation showing key domain information."""
        return f"UnknownDomain(domain='{self.domain}', status={self.status.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"UnknownDomain(id={self.id}, domain='{self.domain}', "
            f"status={self.status.value}, source={self.source.value}, "
            f"first_seen={self.first_seen.isoformat()}, "
            f"last_seen={self.last_seen.isoformat()})"
        )


@dataclass
class DomainBatch:
    """
    Container for batch domain operations.
    
    Provides utilities for handling multiple domains efficiently
    in batch insert and upsert operations.
    
    Attributes:
        domains: List of UnknownDomain instances.
        batch_id: Unique identifier for this batch.
        created_at: When the batch was created.
    """
    
    domains: List[UnknownDomain]
    batch_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self) -> None:
        """Validate batch after initialization."""
        if not self.domains:
            raise DomainValidationError(
                "Domain batch cannot be empty",
                validation_rule="batch_empty"
            )
        
        # Validate uniqueness within batch
        domain_names = [d.domain for d in self.domains]
        if len(domain_names) != len(set(domain_names)):
            duplicates = [name for name in domain_names if domain_names.count(name) > 1]
            raise DomainValidationError(
                f"Batch contains duplicate domains: {duplicates}",
                validation_rule="batch_duplicates"
            )
    
    @property
    def size(self) -> int:
        """Number of domains in the batch."""
        return len(self.domains)
    
    @property
    def domain_names(self) -> List[str]:
        """List of domain names in the batch."""
        return [domain.domain for domain in self.domains]
    
    def to_database_values(self) -> List[Tuple[Any, ...]]:
        """
        Convert batch to list of value tuples for database insertion.
        
        Returns:
            List of tuples, each containing values for one domain.
        """
        return [domain.to_database_values() for domain in self.domains]
    
    def split(self, chunk_size: int) -> List['DomainBatch']:
        """
        Split large batch into smaller chunks.
        
        Args:
            chunk_size: Maximum size for each chunk.
            
        Returns:
            List of smaller DomainBatch instances.
        """
        if chunk_size <= 0:
            raise DomainValidationError(
                f"Chunk size must be positive, got {chunk_size}",
                validation_rule="chunk_size"
            )
        
        chunks = []
        for i in range(0, len(self.domains), chunk_size):
            chunk_domains = self.domains[i:i + chunk_size]
            chunks.append(DomainBatch(domains=chunk_domains))
        
        return chunks
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert batch to dictionary for logging or serialization."""
        return {
            'batch_id': str(self.batch_id),
            'size': self.size,
            'created_at': self.created_at.isoformat(),
            'domains': [domain.to_dict() for domain in self.domains]
        }