from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Dict, Iterator, List, Optional, TextIO

from parser.models import DNSRecord
from timestamp_utils import TimestampUtils
from event_id import EventIDGenerator

logger = logging.getLogger(__name__)

class DNSDatasetCSVWriter:

    MANDATORY_FIELDS = [
        'timestamp',
        'client_ip',
        'domain',
        'query_type',
        'response_code',
        'resolved_ip',
        'ttl',
        'raw_log',
        'source_file'
    ]

    ADDITIONAL_FIELDS = [
        'event_id',
        'timestamp_iso8601',
        'timestamp_unix',
        'date',
        'time',
        'year',
        'month',
        'day',
        'hour',
        'minute',
        'second',
        'millisecond',
        'weekday',
        'week_number',
        'day_of_year',
        'is_weekend',
        'timezone',
        'hostname',
        'server_name',
        'client_port',
        'resolver_ip',
        'transport_protocol',
        'query_class',
        'subdomain',
        'registered_domain',
        'tld',
        'is_ipv4',
        'is_ipv6',
        'log_category',
        'severity',
        'thread_id',
        'process_id',
        'source_file',
        'log_line_number',
        'raw_log'
    ]

    ALL_FIELDS = MANDATORY_FIELDS.copy()

    for field in ADDITIONAL_FIELDS:
         if field not in ALL_FIELDS:
             ALL_FIELDS.append(field)

    def __init__(self, output_path: Path, mode: str = 'w'):
        self.output_path = output_path
        self.mode = mode
        self._file: Optional[TextIO] = None
        self._writer: Optional[csv.DictWriter] = None
        self._rows_written = 0

        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self) -> None:
        self._file = open(
            self.output_path,
            mode=self.mode,
            encoding='utf-8',
            newline=''
        )

        self._writer = csv.DictWriter(
            self._file,
            fieldnames=self.ALL_FIELDS,
            extrasaction='ignore',
            restval='NULL',
            delimiter=',',
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL
        )

        if self.mode == "w" or self.output_path.stat().st_size == 0:
            self._writer.writeheader()

        logger.info(f"CSV file opened: {self.output_path}")

    def close(self) -> None:
        if self._file:
            self._file.close()
            logger.info(
                f"CSV file closed. Total rows written: {self._rows_written}"
            )

    def write_event(self, record: DNSRecord) -> Dict[str, str]:
        """
        Write a single DNSRecord to the dataset CSV.

        Fields that existed on ParsedBINDLine but are absent from DNSRecord
        are written as sensible defaults so the CSV schema is preserved.
        """
        if not self._writer:
            raise RuntimeError("CSV writer not opened. Call open() first.")

        event_id = EventIDGenerator.generate_event_id(
            timestamp=record.timestamp,
            client_ip=record.client_ip,
            domain=record.domain,
            query_type=record.query_type,
            client_port=getattr(record, 'client_port', None),
        )

        ts_data = TimestampUtils.normalize_timestamp(record.timestamp)

        subdomain, registered_domain, tld = self._extract_domain_components(
            record.domain
        )

        is_ipv4, is_ipv6 = self._check_ip_versions(record.client_ip)

        row = {
            # ── Mandatory fields ────────────────────────────────────────────
            'timestamp':     ts_data['timestamp'] or 'NULL',
            'client_ip':     record.client_ip or 'NULL',
            'domain':        record.domain or 'UNKNOWN',
            'query_type':    record.query_type or 'UNKNOWN',
            'response_code': record.response_code or 'NOERROR',
            'resolved_ip':   record.resolved_ip or 'NULL',
            'ttl':           record.ttl if record.ttl is not None else 'NULL',
            'raw_log':       record.raw_line or 'NULL',
            'source_file':   record.source_file or 'NULL',

            # ── Timestamp derivatives ────────────────────────────────────────
            'event_id':          event_id,
            'timestamp_iso8601': ts_data['timestamp'] or 'NULL',
            'timestamp_unix':    ts_data['timestamp_unix'] or 'NULL',
            'date':              ts_data['date'] or 'NULL',
            'time':              ts_data['time'] or 'NULL',
            'year':              ts_data['year'] or 'NULL',
            'month':             ts_data['month'] or 'NULL',
            'day':               ts_data['day'] or 'NULL',
            'hour':              ts_data['hour'] or 'NULL',
            'minute':            ts_data['minute'] or 'NULL',
            'second':            ts_data['second'] or 'NULL',
            'millisecond':       ts_data['millisecond'] or 'NULL',
            'weekday':           ts_data['weekday'] or 'NULL',
            'week_number':       ts_data['week_number'] or 'NULL',
            'day_of_year':       ts_data['day_of_year'] or 'NULL',
            'is_weekend':        ts_data['is_weekend'] or 'false',
            'timezone':          ts_data['timezone'] or 'UTC',

            # ── Fields present on DNSRecord (optional / may not exist) ───────
            'client_port':       str(getattr(record, 'client_port', None) or 'NULL'),
            'resolver_ip':       getattr(record, 'resolver_ip', None) or 'NULL',
            'transport_protocol': getattr(record, 'transport_protocol', None) or 'UNKNOWN',
            'query_class':       getattr(record, 'query_class', None) or 'IN',
            'hostname':          getattr(record, 'hostname', None) or 'UNKNOWN',
            'server_name':       getattr(record, 'server_name', None) or 'UNKNOWN',
            'log_category':      getattr(record, 'log_category', None) or 'UNKNOWN',
            'severity':          getattr(record, 'severity', None) or 'INFO',
            'thread_id':         getattr(record, 'thread_id', None) or 'NULL',
            'process_id':        getattr(record, 'process_id', None) or 'NULL',
            'log_line_number':   str(getattr(record, 'line_number', 'NULL')),

            # ── Derived domain components ────────────────────────────────────
            'subdomain':         subdomain,
            'registered_domain': registered_domain,
            'tld':               tld,
            'is_ipv4':           is_ipv4,
            'is_ipv6':           is_ipv6,
        }

        self._writer.writerow(row)
        self._rows_written += 1

        return row

    def write_row(self, row: Dict[str, str]) -> None:
        """
        Write a pre-built row dict directly to the CSV.
        Used by callers (e.g. run_live_pipeline) that construct the dict
        themselves rather than passing a DNSRecord.
        """
        if not self._writer:
            raise RuntimeError("CSV writer not opened. Call open() first.")

        self._writer.writerow(row)
        self._rows_written += 1

    def write_invalid_event(
        self,
        raw_line: str,
        source_file: str,
        line_number: int,
        error_message: str
    ) -> Dict[str, str]:
        if not self._writer:
            raise RuntimeError("CSV writer not opened. Call open() first.")

        row = {
            'timestamp':     'INVALID',
            'client_ip':     'INVALID',
            'domain':        'INVALID',
            'query_type':    'UNKNOWN',
            'response_code': 'UNKNOWN',
            'resolved_ip':   'NULL',
            'ttl':           'NULL',
            'raw_log':       raw_line,
            'source_file':   source_file,

            'event_id': EventIDGenerator.generate_event_id(
                timestamp=None,
                client_ip=None,
                domain=None,
                query_type=None,
                client_port=None
            ),
            'timestamp_iso8601': 'INVALID',
            'timestamp_unix':    'NULL',
            'date':              'INVALID',
            'time':              'INVALID',
            'year':              'NULL',
            'month':             'NULL',
            'day':               'NULL',
            'hour':              'NULL',
            'minute':            'NULL',
            'second':            'NULL',
            'millisecond':       'NULL',
            'weekday':           'NULL',
            'week_number':       'NULL',
            'day_of_year':       'NULL',
            'is_weekend':        'false',
            'timezone':          'UTC',
            'hostname':          'UNKNOWN',
            'server_name':       'UNKNOWN',
            'client_port':       'NULL',
            'resolver_ip':       'NULL',
            'transport_protocol': 'UNKNOWN',
            'query_class':       'UNKNOWN',
            'subdomain':         'NULL',
            'registered_domain': 'NULL',
            'tld':               'NULL',
            'is_ipv4':           'false',
            'is_ipv6':           'false',
            'log_category':      'INVALID',
            'severity':          'ERROR',
            'thread_id':         'NULL',
            'process_id':        'NULL',
            'log_line_number':   str(line_number),
        }

        self._writer.writerow(row)
        self._rows_written += 1

        return row

    @staticmethod
    def _extract_domain_components(
        domain: Optional[str]
    ) -> tuple:
        if not domain:
            return ('NULL', 'NULL', 'NULL')

        parts = domain.lower().rstrip('.').split('.')

        if len(parts) < 2:
            return ('NULL', 'NULL', 'NULL')

        tld = parts[-1]

        if len(parts) >= 3:
            registered_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
        else:
            registered_domain = '.'.join(parts[-2:])
            subdomain = 'NULL'

        return (subdomain or 'NULL', registered_domain, tld)

    @staticmethod
    def _check_ip_versions(ip: Optional[str]) -> tuple:
        import ipaddress

        if not ip or ip == 'NULL':
            return ('false', 'false')

        try:
            addr = ipaddress.ip_address(ip)
            return (
                'true' if isinstance(addr, ipaddress.IPv4Address) else 'false',
                'true' if isinstance(addr, ipaddress.IPv6Address) else 'false'
            )
        except ValueError:
            return ('false', 'false')

    @property
    def rows_written(self) -> int:
        return self._rows_written
