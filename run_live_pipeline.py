"""
run_live_pipeline.py

====================

Live (streaming) variant of the DNS Threat Detection pipeline.

Architecture
------------

DNS Server
      ↓
Raw DNS Logs
      ↓
Fluent Bit (Regex Parser — parsers.conf)
      ↓
Structured JSON
      ↓
Kafka
      ↓
_record_from_structured_json()
      ↓
DNSRecord
      ↓
Existing Threat Detection Pipeline:
  [DNSDatasetCSVWriter] → [DNSLabeller]
  → [DomainPersistenceManager / UnknownDomainProcessor]
  → [client_profiling] → [DomainProfilingService]
  → [EnrichmentManager] → [FeatureExtractor] → feature matrix CSV

Kafka ingestion
---------------
Fluent Bit pre-parses DNS server logs (BIND, Unbound, CoreDNS, PowerDNS,
Knot DNS, …) using per-server regex parsers in parsers.conf and publishes
structured JSON to Kafka.  This pipeline receives those dicts and builds
DNSRecord objects via _record_from_structured_json() — no raw-log regex
parsing is performed here.

The generic field mapping in _record_from_structured_json() accepts
alternate field names produced by different DNS server parsers, so only
Fluent Bit's parsers.conf needs to change when a new DNS server is added.

Legacy file ingestion
---------------------
For non-Kafka paths that still deliver raw BIND 9 log lines, import
parse_bind_line() from legacy_bind_parser.py and call process_line() on
LivePipelineProcessor.  The Kafka consumer never uses that path.

Usage
-----

    python run_live_pipeline.py \\
        --dataset /data/dns/dataset.csv \\
        --output  /data/dns/features.csv

Press Ctrl-C to stop cleanly.

"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Optional

import pandas as pd
from dotenv import load_dotenv
from kafka import KafkaConsumer

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent

load_dotenv(PROJECT_ROOT / "api.env")

sys.path.insert(0, str(PROJECT_ROOT / "bind converter"))
sys.path.insert(0, str(PROJECT_ROOT / "parsing logs"))
sys.path.insert(0, str(PROJECT_ROOT / "feature extraction"))

# --- parser models ---------------------------------------------------------

from parser.models import DNSRecord
from parser.validators import validate_record, ValidationError

# --- dataset CSV writer -----------------------------------------------------

from csv_writer import DNSDatasetCSVWriter

# --- labeller layer ---------------------------------------------------------

from labeler.label_dataset import DNSLabeller
from labeler.config import LabelingConfig
from labeler.intel.reputation import initialize_database
from labeler.intel.unknown_domain_processor import UnknownDomainProcessor

# --- domain / client profiling ----------------------------------------------

from domain_profiling.service import DomainProfilingService
from client_profiling import initialize_pool, close_pool, process_query
from client_profiling.schema import initialize_schema

# --- persistence ------------------------------------------------------------

from domain_persistence import DomainPersistenceManager

# --- enrichment + feature extraction ----------------------------------------

from enrichment.enrichment_manager import EnrichmentManager
from feature_extractor import FeatureExtractor

# --- legacy file-ingestion parser (NOT used by the Kafka consumer) ----------
#
# Imported here so that callers of process_line() (non-Kafka paths) do not
# need to import legacy_bind_parser themselves.  The Kafka consumer never
# references _parse_bind_line or anything from this import.

from legacy_bind_parser import parse_bind_line as _parse_bind_line, BindParseResult as _BindParseResult

# ---------------------------------------------------------------------------

logger = logging.getLogger("run_live_pipeline")

# ---------------------------------------------------------------------------
# Pipeline constants
# ---------------------------------------------------------------------------

MAX_LINE_LENGTH      = 4096
SKIP_COMMENTS        = True
COMMENT_CHARACTERS   = {"#", ";"}
ENABLE_DEDUPLICATION = True

# ---------------------------------------------------------------------------
# Structured-JSON → DNSRecord
# ---------------------------------------------------------------------------
#
# This is the ONLY ingestion function used by the Kafka consumer.
#
# Generic field mapping
# ---------------------
# Different DNS servers emit different field names even after Fluent Bit
# parsing.  Each lookup tries the most specific name first and falls back
# to common alternatives so the pipeline works regardless of whether logs
# originate from BIND, Unbound, CoreDNS, PowerDNS, or Knot DNS — only
# Fluent Bit's parsers.conf needs to change when a new server is added.
#
# Field-name alternatives by DNS server:
#
#   client_ip   : BIND → client_ip  | Unbound/CoreDNS → src_ip | PowerDNS → source_ip
#   domain      : BIND → domain     | Unbound → query_name      | CoreDNS/Knot → dns_question
#   query_type  : BIND → query_type | Unbound/PowerDNS → record_type
#   timestamp   : Fluent Bit default → @timestamp | plain → timestamp
#   resolver_ip : BIND → resolver   | others → resolver_ip
#   response_code: BIND → response_code | Unbound/CoreDNS/PowerDNS → rcode
#   query_class : BIND → query_class | others → dns_class
#   client_port : BIND → client_port | others → src_port
#   resolved_ip : BIND → resolved_ip | CoreDNS/PowerDNS → answer_ip
#   ttl         : universal → ttl
# ---------------------------------------------------------------------------

class _StructuredParseResult:
    """Thin result wrapper for _record_from_structured_json."""
    __slots__ = ("success", "record", "error")

    def __init__(
        self,
        success: bool,
        record: Optional[DNSRecord] = None,
        error: Optional[str] = None,
    ) -> None:
        self.success = success
        self.record  = record
        self.error   = error


def _setattr_safe(obj: object, name: str, value) -> None:
    """Set an attribute only if the object doesn't already define it as a slot."""
    try:
        setattr(obj, name, value)
    except (AttributeError, TypeError):
        pass  # dataclass with __slots__ and no such field — skip silently


def _record_from_structured_json(
    msg: dict,
    source_file: str = "kafka",
    line_number: int = 0,
) -> _StructuredParseResult:
    """
    Build a DNSRecord directly from a pre-parsed Fluent Bit JSON message.

    Fluent Bit's parsers.conf regex parser extracts all DNS fields before
    publishing to Kafka, so no raw-log regex parsing is needed here.

    Generic field mapping supports multiple DNS servers.  Each field tries
    the most common alternative names so only Fluent Bit parsers need to
    change when a new DNS server is added.

    Required fields (missing → failure, pipeline not crashed):
        client_ip, domain, query_type

    Optional fields (absent → None or safe default):
        @timestamp / timestamp, query_class / dns_class, client_port /
        src_port, resolver / resolver_ip, response_code / rcode,
        ttl, resolved_ip / answer_ip
    """

    # ── Generic field extraction with DNS-server fallbacks ──────────────────

    # client IP: BIND → client_ip | Unbound/CoreDNS → src_ip | PowerDNS → source_ip
    client_ip = (
        msg.get("client_ip")
        or msg.get("src_ip")
        or msg.get("source_ip")
        or ""
    ).strip()

    # domain: BIND → domain | Unbound → query_name | CoreDNS/Knot → dns_question
    domain = (
        msg.get("domain")
        or msg.get("query_name")
        or msg.get("dns_question")
        or ""
    ).strip().rstrip(".")

    # query type: BIND → query_type | Unbound/PowerDNS → record_type
    query_type = (
        msg.get("query_type")
        or msg.get("record_type")
        or ""
    ).strip()

    # ── Validate required fields ─────────────────────────────────────────────
    required = {
        "client_ip":  client_ip,
        "domain":     domain,
        "query_type": query_type,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        return _StructuredParseResult(
            success=False,
            error=f"Missing required fields: {', '.join(missing)} in message: {msg}",
        )

    # ── Optional fields with DNS-server fallbacks ────────────────────────────

    # timestamp: Fluent Bit default → @timestamp | plain → timestamp

    from datetime import datetime

    raw_timestamp = msg.get("@timestamp") or msg.get("timestamp")

    timestamp_iso = None

    if raw_timestamp is not None:
        try:
            if isinstance(raw_timestamp, (int,float)):
                timestamp_iso = datetime.fromtimestamp(
                    float(raw_timestamp)
                ).isoformat()
            
            else:
                timestamp_iso = str(raw_timestamp)
        
        except Exception:
            timestamp_iso = None

    # query class: BIND → query_class | others → dns_class | default "IN"
    query_class: str = (
        msg.get("query_class")
        or msg.get("dns_class")
        or "IN"
    )

    # client port: BIND → client_port | others → src_port
    client_port: str = str(
        msg.get("client_port")
        or msg.get("src_port")
        or ""
    )

    # resolver IP: BIND → resolver | others → resolver_ip
    resolver_ip: Optional[str] = (
        msg.get("resolver")
        or msg.get("resolver_ip")
        or None
    )

    # response code: BIND → response_code | Unbound/CoreDNS/PowerDNS → rcode
    # Default to NOERROR when absent (matches legacy parser behaviour)
    response_code: str = (
        msg.get("response_code")
        or msg.get("rcode")
        or "NOERROR"
    ).strip()

    # resolved IP: BIND → resolved_ip | CoreDNS/PowerDNS → answer_ip
    resolved_ip: Optional[str] = (
        msg.get("resolved_ip")
        or msg.get("answer_ip")
        or None
    )

    # TTL: universal field name across all servers
    ttl: Optional[int] = None
    raw_ttl = msg.get("ttl")
    if raw_ttl is not None:
        try:
            ttl = int(raw_ttl)
        except (ValueError, TypeError):
            pass

    # ── Build DNSRecord ──────────────────────────────────────────────────────
    record = DNSRecord(
        timestamp=timestamp_iso,
        client_ip=client_ip,
        domain=domain,
        query_type=query_type,
        response_code=response_code,
        resolved_ip=resolved_ip,
        ttl=ttl,
        # Store the serialised JSON as raw_line so downstream stages that
        # log or store raw_line still receive a meaningful string.
        raw_line=json.dumps(msg),
        source_file=source_file,
        label=None,
        threat_score=None,
        confidence=None,
        label_reason=None,
    )

    # Attach optional extra fields using setattr so we don't break DNSRecord
    # if it doesn't declare them; csv_writer picks them up via getattr.
    _setattr_safe(record, "client_port",        client_port)
    _setattr_safe(record, "resolver_ip",         resolver_ip)
    _setattr_safe(record, "query_class",         query_class)
    _setattr_safe(record, "hostname",            None)
    _setattr_safe(record, "server_name",         None)
    _setattr_safe(record, "transport_protocol",  None)
    _setattr_safe(record, "log_category",        None)
    _setattr_safe(record, "severity",            None)
    _setattr_safe(record, "thread_id",           None)
    _setattr_safe(record, "process_id",          None)
    _setattr_safe(record, "line_number",         line_number)

    return _StructuredParseResult(success=True, record=record)


# ---------------------------------------------------------------------------
# Minimal statistics tracker
# ---------------------------------------------------------------------------

class _PipelineStats:
    """Lightweight statistics tracker."""

    def __init__(self) -> None:
        self.total_input  = 0
        self.skipped      = 0
        self.malformed    = 0
        self.duplicates   = 0
        self.valid_events = 0
        self._seen: set[str] = set()

    def record_input(self) -> None:
        self.total_input += 1

    def record_skipped(self, reason: str = "") -> None:
        self.skipped += 1
        logger.debug("Skipped line (%s)", reason)

    def record_malformed(self, raw: str, reason: str = "") -> None:
        self.malformed += 1
        logger.debug("Malformed message — %s — %s", reason, raw[:120])

    def is_duplicate(self, key: str) -> bool:
        if not ENABLE_DEDUPLICATION:
            return False
        if key in self._seen:
            self.duplicates += 1
            return True
        self._seen.add(key)
        return False

    def record_valid(self) -> None:
        self.valid_events += 1

    def print_summary(self) -> None:
        logger.info(
            "Pipeline summary — input: %d | valid: %d | skipped: %d "
            "| malformed: %d | duplicates: %d",
            self.total_input, self.valid_events,
            self.skipped, self.malformed, self.duplicates,
        )

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-Based DNS Threat Detection System — Live Kafka Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  python run_live_pipeline.py \\
      --dataset /data/dns/live_dataset.csv \\
      --output  /data/dns/live_features.csv
""",
    )
    parser.add_argument("--dataset", required=True, help="Path for incremental dataset CSV")
    parser.add_argument("--output",  required=True, help="Path for incremental feature matrix CSV")
    parser.add_argument(
        "--kafka-bootstrap",
        default="localhost:9092",
        help="Kafka bootstrap server",
    )
    parser.add_argument(
        "--kafka-topic",
        default="dns-logs",
        help="Kafka topic name",
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

# ---------------------------------------------------------------------------
# Helper: row dict → pandas Series for DNSLabeller._process_row()
# ---------------------------------------------------------------------------

def row_dict_to_series(row: dict) -> pd.Series:
    return pd.Series(row)

# ---------------------------------------------------------------------------
# Helper: deduplication key
# ---------------------------------------------------------------------------

def _dedup_key(record: DNSRecord) -> str:
    return "|".join([
        str(record.timestamp or ""),
        record.client_ip   or "",
        record.domain      or "",
        record.query_type  or "",
        str(getattr(record, "client_port", "") or ""),
    ])

# ---------------------------------------------------------------------------
# Helper: patch label fields back onto a DNSRecord
# ---------------------------------------------------------------------------

def _apply_labels(record: DNSRecord, row: dict) -> DNSRecord:
    record.label        = row.get("label")
    record.threat_score = _safe_int(row.get("threat_score"))
    record.confidence   = _safe_int(row.get("confidence"))
    record.label_reason = row.get("label_reason")
    return record

def _safe_int(value) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None

# ---------------------------------------------------------------------------
# Feature CSV: incremental writer
# ---------------------------------------------------------------------------

class IncrementalFeatureWriter:
    """
    Appends single-row feature DataFrames to the output CSV without keeping
    all rows in memory.  Header is written once on the first flush.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._header_written = path.exists() and path.stat().st_size > 0
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, feature_df: pd.DataFrame) -> None:
        if feature_df.empty:
            return
        write_header = not self._header_written
        feature_df.to_csv(
            self._path,
            mode="a",
            index=False,
            header=write_header,
        )
        self._header_written = True

# ---------------------------------------------------------------------------
# Per-message processor
# ---------------------------------------------------------------------------

class LivePipelineProcessor:
    """
    Holds all long-lived service objects and exposes:

      process_structured_message(line_number, msg, source_path)
          — PRIMARY entry point for structured JSON messages from Kafka.
            Calls _record_from_structured_json() with generic field mapping
            that supports BIND, Unbound, CoreDNS, PowerDNS, and Knot DNS,
            then delegates to _process_record() for all downstream stages.

      process_line(line_number, raw_line, source_path)
          — LEGACY entry point for file-based / non-Kafka ingestion paths
            that still deliver raw BIND 9 log lines.  Calls _parse_bind_line()
            from legacy_bind_parser and then delegates to _process_record().
            The Kafka consumer NEVER calls this method.

      _process_record(record, line_number)
          — shared post-parse pipeline used by both entry points:
            dedup → CSV write → label → profile → persist →
            enrich → feature-extract.
    """

    def __init__(
        self,
        dataset_path: Path,
        feature_writer: IncrementalFeatureWriter,
        profiling_enabled: bool,
        domain_profiler: Optional[DomainProfilingService],
    ) -> None:

        # --- parse / dedup layer -------------------------------------------
        self.statistics = _PipelineStats()

        # Dataset CSV writer (opened in append mode so restarts are safe)
        self.dataset_writer = DNSDatasetCSVWriter(dataset_path, mode="a")
        self.dataset_writer.open()

        # --- labelling layer -----------------------------------------------
        self.label_config = LabelingConfig()
        self.labeller     = DNSLabeller(config=self.label_config)

        # --- persistence layer ---------------------------------------------
        self.persistence = DomainPersistenceManager(enable_persistence=True)
        self.persistence.__enter__()
        self.unknown_domain_processor = UnknownDomainProcessor(
            persistence=self.persistence,
            config=self.label_config,
        )

        # --- enrichment + feature extraction -------------------------------
        self.enricher = EnrichmentManager(
            enable_dns=True,
            enable_whois=True,
            enable_geoip=False,
            enable_asn=True,
        )
        self.extractor = FeatureExtractor(
            enable_whois=False,
            enable_ip_lookup=False,
        )
        self.feature_writer = feature_writer

        # --- profiling -----------------------------------------------------
        self.profiling_enabled = profiling_enabled
        self.domain_profiler   = domain_profiler

    # -----------------------------------------------------------------------
    # PRIMARY entry point: structured JSON from Fluent Bit via Kafka
    # -----------------------------------------------------------------------

    def process_structured_message(
        self,
        line_number: int,
        msg: dict,
        source_path: str,
    ) -> None:
        """
        Run the full pipeline for a pre-parsed Fluent Bit JSON message.

        Accepts structured JSON produced by any DNS server (BIND, Unbound,
        CoreDNS, PowerDNS, Knot DNS) after Fluent Bit parsing.  Field-name
        normalisation is handled inside _record_from_structured_json() so
        only parsers.conf needs to change when a new server is onboarded.

        Validates required fields (client_ip, domain, query_type) before
        constructing the DNSRecord; logs and counts failures without
        crashing the consumer loop.
        """

        logger.debug("Received structured Kafka message")

        self.statistics.record_input()

        parse_result = _record_from_structured_json(
            msg, source_file=source_path, line_number=line_number
        )

        if not parse_result.success:
            self.statistics.record_malformed(
                json.dumps(msg),
                parse_result.error or "Unknown structured-parse error",
            )
            return

        self._process_record(parse_result.record, line_number)

    # -----------------------------------------------------------------------
    # LEGACY entry point: raw BIND 9 log lines (non-Kafka / file ingestion)
    # -----------------------------------------------------------------------

    def process_line(
        self,
        line_number: int,
        raw_line: str,
        source_path: str,
    ) -> None:
        """
        Run the full pipeline for a single raw BIND 9 log line.

        Retained for file-based ingestion paths.
        The Kafka consumer NEVER calls this method.
        """

        logger.debug("Received raw log line")

        self.statistics.record_input()

        # ── 1. Skip empty / comment lines ───────────────────────────────────
        stripped = raw_line.strip() if raw_line else ""
        if not stripped:
            self.statistics.record_skipped("empty")
            return

        if SKIP_COMMENTS and stripped[0] in COMMENT_CHARACTERS:
            self.statistics.record_skipped("comment")
            return

        # ── 2. Truncate extremely long lines ────────────────────────────────
        if len(raw_line) > MAX_LINE_LENGTH:
            raw_line = raw_line[:MAX_LINE_LENGTH]
            logger.warning("Line %d truncated to %d chars", line_number, MAX_LINE_LENGTH)

        # ── 3. Parse raw BIND log line (legacy path only) ────────────────────
        parse_result = _parse_bind_line(raw_line, source_file=source_path, line_number=line_number)

        if not parse_result.success:
            self.statistics.record_malformed(
                raw_line,
                parse_result.error or "Unknown parse error",
            )
            return

        # ── 4–12. Shared downstream processing ──────────────────────────────
        self._process_record(parse_result.record, line_number)

    # -----------------------------------------------------------------------
    # Shared post-parse pipeline (called by both entry points above)
    # -----------------------------------------------------------------------

    def _process_record(self, record: DNSRecord, line_number: int) -> None:
        """
        Shared post-parse pipeline: dedup → CSV write → label → profile →
        persist → enrich → feature-extract.

        Called by both process_structured_message() (Kafka / structured JSON)
        and process_line() (legacy file ingestion).
        No downstream logic is changed from the original implementation.
        """

        # ── 4. Deduplicate ──────────────────────────────────────────────────
        if self.statistics.is_duplicate(_dedup_key(record)):
            return

        # ── 5. Write DNSRecord to dataset CSV ────────────────────────────────
        # write_event() accepts a DNSRecord, writes the row, and returns the
        # canonical row dict used by all downstream stages.
        row = self.dataset_writer.write_event(record)
        self.statistics.record_valid()

        # ── 6. Label ────────────────────────────────────────────────────────
        try:
            threat_score, label, confidence, label_reason, ti_source = (
                self.labeller._process_row(row_dict_to_series(row))
            )
        except Exception as exc:
            logger.warning("Labelling failed for line %d: %s", line_number, exc)
            threat_score, label, confidence, label_reason, ti_source = 0, "Benign", 50, "", "unknown"

        row.update({
            "threat_score": threat_score,
            "label":        label,
            "confidence":   confidence,
            "label_reason": label_reason,
            "ti_source":    ti_source,
        })

        logger.info("Processed %s", row.get("domain"))

        # ── 7. Domain profiling (pre-persistence) ───────────────────────────
        if self.profiling_enabled and self.domain_profiler:
            try:
                self.domain_profiler.process_dataframe(pd.DataFrame([row]))
            except Exception as exc:
                logger.warning("Domain profiling failed for line %d: %s", line_number, exc)

        # ── 8. Persistence + online TI evaluation ───────────────────────────
        #
        # Three distinct paths:
        #
        # A. Confirmed malicious (URLhaus offline DB hit): the domain was
        #    already persisted by store_malicious_domain() inside
        #    ThreatIntelligence.evaluate().  No persistence call needed here.
        #
        # B. Trusted (Tranco whitelist): skip persistence entirely — we must
        #    never write a trusted domain to reputation_domains as malicious.
        #
        # C. Unknown (not in offline DB, not trusted): persist to the
        #    unknown_domains table so the UnknownDomainProcessor can hand it
        #    to VirusTotal / OTX for online evaluation.
        #
        # NOTE: ti_source == "malicious" means the URLhaus offline DB already
        # called store_malicious_domain().  The label/threat_score fields on
        # `row` are correct regardless of this branch.
        if record.domain:
            if ti_source == "malicious":
                # Offline DB already persisted it; just log for visibility.
                logger.info(
                    "TI lookup: %s | Offline malicious DB: MATCH | PostgreSQL: UPSERT (already called) | Online TI: SKIPPED",
                    record.domain,
                )
            elif ti_source == "trusted":
                logger.info(
                    "TI lookup: %s | Offline DB: TRUSTED | Online TI: SKIPPED",
                    record.domain,
                )
            else:
                # Unknown domain — queue for online TI
                logger.info(
                    "TI lookup: %s | Offline malicious DB: MISS | Online TI: QUERY",
                    record.domain,
                )
                try:
                    self.persistence.process_final_dataset(
                        final_df=pd.DataFrame([row]),
                        observation_time=None,
                    )
                    self.unknown_domain_processor.process()
                except Exception as exc:
                    logger.warning(
                        "Domain persistence/TI evaluation failed for %s: %s",
                        record.domain, exc,
                    )

        # ── 9. Client profiling ──────────────────────────────────────────────
        if self.profiling_enabled and record.client_ip and record.domain:
            try:
                process_query(record.client_ip, record.domain)
            except Exception as exc:
                logger.warning("Client profiling failed for line %d: %s", line_number, exc)

        # ── 10. Patch label fields back onto DNSRecord ───────────────────────
        _apply_labels(record, row)

        # ── 11. Enrich ───────────────────────────────────────────────────────
        try:
            enriched = self.enricher.enrich([record])
        except Exception as exc:
            logger.warning("Enrichment failed for line %d: %s", line_number, exc)
            enriched = [record]

        # ── 12. Extract features and append to feature CSV ───────────────────
        try:
            feature_df = self.extractor.extract(enriched)
            self.feature_writer.append(feature_df)
        except Exception as exc:
            logger.warning("Feature extraction failed for line %d: %s", line_number, exc)

    # -----------------------------------------------------------------------

    def close(self) -> None:
        """Release all resources in reverse acquisition order."""
        try:
            if self.labeller and hasattr(self.labeller, "ti") and self.labeller.ti:
                self.labeller.ti.close()
        except Exception as exc:
            logger.warning("Failed to close labeller TI: %s", exc)

        try:
            self.dataset_writer.close()
        except Exception as exc:
            logger.warning("Failed to close dataset writer: %s", exc)

        if self.persistence:
            try:
                self.persistence.__exit__(None, None, None)
            except Exception as exc:
                logger.warning("Failed to shut down persistence manager: %s", exc)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    configure_logging()
    initialize_database()

    start_time        = time.perf_counter()
    profiling_enabled = False
    domain_profiler: Optional[DomainProfilingService] = None
    processor:       Optional[LivePipelineProcessor]  = None
    consumer:        Optional[KafkaConsumer]          = None

    try:
        # ── Initialize PostgreSQL pools ──────────────────────────────────────
        try:
            initialize_pool()
            initialize_schema()
            domain_profiler = DomainProfilingService()
            domain_profiler.initialize_database()
            profiling_enabled = True
            logger.info("Client + domain profiling pools initialized")
        except Exception as exc:
            profiling_enabled = False
            logger.warning("PostgreSQL profiling pool initialization failed: %s", exc)

        args         = parse_arguments()
        dataset_path = Path(args.dataset).expanduser().resolve()
        output_path  = Path(args.output).expanduser().resolve()

        kafka_topic     = args.kafka_topic
        kafka_bootstrap = args.kafka_bootstrap

        dataset_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # ── Build long-lived service objects ─────────────────────────────────
        feature_writer = IncrementalFeatureWriter(output_path)

        processor = LivePipelineProcessor(
            dataset_path=dataset_path,
            feature_writer=feature_writer,
            profiling_enabled=profiling_enabled,
            domain_profiler=domain_profiler,
        )

        # ── Kafka consumer ───────────────────────────────────────────────────
        consumer = KafkaConsumer(
            kafka_topic,
            bootstrap_servers=kafka_bootstrap,
            group_id="dns_threat_pipeline",
            auto_offset_reset="latest",
            enable_auto_commit=False,
            consumer_timeout_ms=3_600_000,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )

        # ── Graceful shutdown — no sys.exit() inside handler ─────────────────
        _stop = False

        def _shutdown(signum, frame):  # noqa: ANN001
            nonlocal _stop
            logger.info("Shutdown signal received — draining consumer …")
            _stop = True
            consumer.close()

        signal.signal(signal.SIGINT,  _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)

        # ── Report API credential status (no secrets printed) ────────────────
        import os as _os
        _vt_keys  = [k for k in _os.getenv("VT_API_KEYS",  "").split(",") if k.strip()]
        _otx_keys = [k for k in _os.getenv("OTX_API_KEYS", "").split(",") if k.strip()]
        _vt_single  = bool(_os.getenv("VT_API_KEY",  "").strip())
        _otx_single = bool(_os.getenv("OTX_API_KEY", "").strip())
        logger.info(
            "VirusTotal configured: %s (%d key(s))",
            "YES" if (_vt_keys or _vt_single)  else "NO",
            len(_vt_keys) if _vt_keys else (1 if _vt_single else 0),
        )
        logger.info(
            "OTX configured: %s (%d key(s))",
            "YES" if (_otx_keys or _otx_single) else "NO",
            len(_otx_keys) if _otx_keys else (1 if _otx_single else 0),
        )

        logger.info("=" * 60)
        logger.info("  Live DNS Threat Detection Pipeline")
        logger.info("  Kafka Topic : %s", kafka_topic)
        logger.info("  Bootstrap   : %s", kafka_bootstrap)
        logger.info("  Dataset     : %s", dataset_path)
        logger.info("  Features    : %s", output_path)
        logger.info("=" * 60)
        logger.info("Waiting for Kafka messages … Press Ctrl-C to stop.")

        # ── Main loop ────────────────────────────────────────────────────────
        # Fluent Bit pre-parses DNS server logs and publishes structured JSON
        # to Kafka.  message.value is already a field dict — no raw log line
        # extraction, no _parse_bind_line() call, no regex work here.
        line_number = 1
        for message in consumer:
            if _stop:
                break

            logger.debug("Kafka message: %s", message.value)

            try:
                processor.process_structured_message(line_number, message.value, "kafka")
                consumer.commit()
                line_number += 1
            except Exception as exc:
                logger.exception(
                    "Failed to process Kafka message at line %d: %s",
                    line_number,
                    exc,
                )

        processor.statistics.print_summary()

        elapsed = time.perf_counter() - start_time
        logger.info("Live pipeline stopped cleanly after %.2f s", elapsed)
        return 0

    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        return 130

    except Exception as exc:
        logger.exception("Live pipeline failed: %s", exc)
        return 1

    finally:
        if consumer is not None:
            try:
                consumer.close()
            except Exception as exc:
                logger.warning("Failed to close Kafka consumer: %s", exc)

        if processor is not None:
            processor.close()

        try:
            close_pool()
        except Exception as exc:
            logger.warning("Failed to close profiling pool: %s", exc)


if __name__ == "__main__":
    sys.exit(main())
