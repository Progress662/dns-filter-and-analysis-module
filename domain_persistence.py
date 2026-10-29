# domain_persistence.py (NEW FILE)
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import pandas as pd

from unknown_domain_repository import (
    UnknownDomainService,
    Config,
    DomainSource,
    ProcessingStats,
    configure_package_logging,
    UnknownDomainRepositoryError
)

class DomainPersistenceManager:
    """
    Manages persistence of unknown domains at the pipeline level.
    
    This component operates after all analysis is complete and handles
    the business logic of determining which domains should be persisted.
    """
    
    def __init__(self, enable_persistence: bool = True):
        """
        Initialize domain persistence manager.
        
        Args:
            enable_persistence: Whether to enable domain persistence.
        """
        self.enable_persistence = enable_persistence
        self._service: Optional[UnknownDomainService] = None
        self._initialized = False
        
        if self.enable_persistence:
            self._initialize_service()
    
    def _initialize_service(self) -> None:
        """Initialize the unknown domain repository service."""
        try:
            # Configure logging to match pipeline
            configure_package_logging(level="INFO", format="json")
            
            # Load configuration from environment
            config = Config.from_env()
            
            # Create and initialize service
            self._service = UnknownDomainService(config)
            self._service.initialize()
            
            self._initialized = True
            print("Domain persistence service initialized successfully")
            
        except Exception as e:
            print(f"WARNING: Failed to initialize domain persistence: {e}")
            print("Continuing without persistence - unknown domains will not be stored")
            self._service = None
            self.enable_persistence = False
    
    def process_final_dataset(
        self, 
        final_df: pd.DataFrame,
        observation_time: Optional[datetime] = None
    ) -> ProcessingStats:
        """
        Process final labeled dataset and persist unknown domains.
        
        Args:
            final_df: Final DataFrame with columns: domain, ti_source, final_label, etc.
                Optionally also carries `client_ip` and `query_type` columns
                (present when the upstream parser/labeler populated them);
                these are preserved through to persistence when available.
            observation_time: When domains were first observed.
            
        Returns:
            Processing statistics.
        """
        if not self.enable_persistence or not self._service:
            return ProcessingStats()
        
        # Filter to only unknown domains (not found in threat intelligence)
        unknown_domains_df = final_df[final_df['ti_source'] == 'unknown'].copy()
        
        if unknown_domains_df.empty:
            print("No unknown domains found - nothing to persist")
            return ProcessingStats()
        
        # ------------------------------------------------------------------
        # Build a richer per-domain structure instead of collapsing to a
        # bare list of domain strings, so client_ip / query_type survive
        # into persistence instead of being silently discarded.
        #
        # Chosen structure: List[Dict[str, Optional[str]]], one dict per
        # unique domain, each shaped as:
        #     {"domain": <str>, "client_ip": <str or None>, "query_type": <str or None>}
        #
        # Rationale:
        #   - A domain can appear on multiple rows (e.g. queried by several
        #     clients, or with several query types). We keep exactly one
        #     record per unique domain - the FIRST observed row for that
        #     domain in this dataset - to match the prior behaviour of
        #     `unique()`, which also produced one entry per domain and
        #     implicitly picked "first occurrence" ordering.
        #   - client_ip / query_type are optional: if the columns are not
        #     present on final_df (e.g. an older upstream stage that hasn't
        #     been updated to emit them yet), they are simply filled with
        #     None per record rather than raising, preserving existing
        #     behaviour for callers that don't have this data yet.
        #   - Plain dicts (not a custom dataclass) are used so this file
        #     does not need to import/depend on anything from
        #     unknown_domain_repository beyond what it already imports,
        #     keeping the "modify only this file" constraint clean. The
        #     next step (service.py) can accept
        #     List[Dict[str, Optional[str]]] directly, or map each dict
        #     into whatever richer type it defines.
        # ------------------------------------------------------------------
        has_client_ip = "client_ip" in unknown_domains_df.columns
        has_query_type = "query_type" in unknown_domains_df.columns

        # One row per unique domain, keeping first occurrence - mirrors the
        # previous `unique()` semantics instead of exploding into duplicate
        # per-row entries for the same domain.
        deduped_df = unknown_domains_df.drop_duplicates(subset="domain", keep="first")

        unknown_domain_records: List[Dict[str, Optional[str]]] = []
        for row in deduped_df.itertuples(index=False):
            row_dict = row._asdict()
            unknown_domain_records.append({
                "domain": row_dict["domain"],
                "client_ip": row_dict.get("client_ip") if has_client_ip else None,
                "query_type": row_dict.get("query_type") if has_query_type else None,
            })

        # Kept for logging/back-compat readability below.
        unknown_domain_list = [record["domain"] for record in unknown_domain_records]
        
        print(f"Found {len(unknown_domain_list)} unknown domains to persist")
        
        try:
            # Persist domains with observation time
            print(f"Domains being sent to repository: {len(unknown_domain_list)}")
            print(unknown_domain_list[:10])
            stats = self._service.process_domains(
                domains=unknown_domain_records,
                source=DomainSource.DNS_QUERY_LOG,
                observed_at=observation_time or datetime.now(timezone.utc),
                batch_process=True
            )
            
            print(f"Persistence completed: {stats.domains_stored} stored, "
                  f"{stats.domains_updated} updated, "
                  f"{stats.domains_skipped} skipped")
            
            return stats
            
        except UnknownDomainRepositoryError as e:
            print(f"ERROR: Failed to persist unknown domains: {e}")
            # Return empty stats but don't raise - pipeline should continue
            return ProcessingStats(total_processed=len(unknown_domain_list), errors=[str(e)])
    
    def get_pending_domains(self) -> List[str]:
        """
        Retrieve domains awaiting online threat-intelligence evaluation.

        Thin wrapper used by UnknownDomainProcessor to pull domains that
        have not yet been evaluated.

        Returns:
            List of pending domains, or an empty list if persistence is
            disabled.
        """
        if not self.enable_persistence or not self._service:
            return []

        return self._service.get_pending_domains()

    def update_status(
        self,
        domain_name: str,
        status,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update the status of a domain.

        Thin wrapper used by UnknownDomainProcessor to record the
        outcome of an online threat-intelligence evaluation.

        Args:
            domain_name: Domain name to update.
            status: New status to set.
            metadata: Optional metadata to store alongside the update.
        """
        if not self.enable_persistence or not self._service:
            return

        self._service.update_status(domain_name, status, metadata)

    def get_repository_stats(self) -> Dict[str, Any]:
        """Get current repository statistics."""
        if not self._service:
            return {"status": "disabled"}
        
        try:
            return self._service.get_repository_stats()
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on persistence service."""
        if not self._service:
            return {"status": "disabled"}
        
        try:
            return self._service.health_check()
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    def shutdown(self) -> None:
        """Shutdown persistence service and cleanup resources."""
        if self._service:
            try:
                self._service.shutdown()
                print("Domain persistence service shut down successfully")
            except Exception as e:
                print(f"WARNING: Error during persistence shutdown: {e}")
            finally:
                self._service = None
                self._initialized = False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.shutdown()