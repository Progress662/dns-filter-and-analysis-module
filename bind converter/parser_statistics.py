from __future__ import annotations

import json
import logging
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from bind_parser import ParsedBINDLine

logger = logging.getLogger(__name__)


@dataclass
class ParsingStatistics:

    # Input tracking
    total_input_lines: int = 0
    valid_dns_events: int = 0
    malformed_lines: int = 0
    skipped_lines: int = 0
    duplicate_events: int = 0
    
    # Data tracking
    unique_domains: set = field(default_factory=set)
    unique_client_ips: set = field(default_factory=set)
    top_domains: Counter = field(default_factory=Counter)
    top_query_types: Counter = field(default_factory=Counter)
    top_response_codes: Counter = field(default_factory=Counter)
    
    # File tracking
    source_files: set = field(default_factory=set)
    log_categories: Counter = field(default_factory=Counter)
    severities: Counter = field(default_factory=Counter)
    
    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    
    # Error tracking
    error_messages: Counter = field(default_factory=Counter)
    invalid_lines: List[Dict] = field(default_factory=list)
    
    # Event ID tracking for deduplication
    _seen_event_ids: set = field(default_factory=set)
    
    def __post_init__(self):
        self.start_time = time.time()
    
    def record_input_line(self, source_file: str) -> None:
        self.total_input_lines += 1
        self.source_files.add(source_file)
    
    def record_valid_event(self, parsed_line: ParsedBINDLine) -> None:
        self.valid_dns_events += 1
        
        # Track unique domains and IPs
        if parsed_line.domain:
            self.unique_domains.add(parsed_line.domain.lower())
            self.top_domains[parsed_line.domain.lower()] += 1
        
        if parsed_line.client_ip:
            self.unique_client_ips.add(parsed_line.client_ip)
        
        if parsed_line.query_type:
            self.top_query_types[parsed_line.query_type] += 1
        
        if parsed_line.response_code:
            self.top_response_codes[parsed_line.response_code] += 1
        
        if parsed_line.log_category:
            self.log_categories[parsed_line.log_category] += 1
        
        if parsed_line.severity:
            self.severities[parsed_line.severity] += 1
    
    def record_malformed_line(
        self,
        line: str,
        source_file: str,
        line_number: int,
        error_message: str
    ) -> None:
        self.malformed_lines += 1
        self.error_messages[error_message] += 1
        
        self.invalid_lines.append({
            'source_file': source_file,
            'line_number': line_number,
            'raw_line': line[:200],  # Truncate for storage
            'error': error_message
        })
        
        # Keep only last 100 invalid lines for memory management
        if len(self.invalid_lines) > 100:
            self.invalid_lines = self.invalid_lines[-100:]
    
    def record_skipped_line(self, reason: str = 'empty') -> None:
        self.skipped_lines += 1
    
    def check_duplicate(self, event_id: str) -> bool:
        if event_id in self._seen_event_ids:
            self.duplicate_events += 1
            return True
        
        self._seen_event_ids.add(event_id)
        return False
    
    def finish(self) -> None:
        self.end_time = time.time()
    
    def get_processing_time(self) -> float:
        if self.end_time > 0:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    def get_average_speed(self) -> float:
        proc_time = self.get_processing_time()
        if proc_time > 0:
            return self.total_input_lines / proc_time
        return 0.0
    
    def generate_report(self, output_csv_path: str) -> Dict:
        report = {
            'summary': {
                'total_input_lines': self.total_input_lines,
                'valid_dns_events': self.valid_dns_events,
                'malformed_lines': self.malformed_lines,
                'skipped_lines': self.skipped_lines,
                'duplicate_events': self.duplicate_events,
                'unique_domains': len(self.unique_domains),
                'unique_client_ips': len(self.unique_client_ips),
            },
            'top_domains': [
                {'domain': domain, 'count': count}
                for domain, count in self.top_domains.most_common(20)
            ],
            'top_query_types': [
                {'type': qtype, 'count': count}
                for qtype, count in self.top_query_types.most_common(10)
            ],
            'top_response_codes': [
                {'code': code, 'count': count}
                for code, count in self.top_response_codes.most_common(10)
            ],
            'log_categories': dict(self.log_categories.most_common()),
            'severities': dict(self.severities.most_common()),
            'top_errors': [
                {'error': msg, 'count': count}
                for msg, count in self.error_messages.most_common(10)
            ],
            'processing': {
                'processing_time_seconds': round(self.get_processing_time(), 2),
                'average_parsing_speed_lines_per_second': round(
                    self.get_average_speed(), 2
                ),
                'source_files_processed': len(self.source_files),
            },
            'output': {
                'csv_path': output_csv_path,
                'total_rows_written': self.valid_dns_events,
            }
        }
        
        return report
    
    def save_report(self, output_path: Path, report: Dict) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {output_path}")
    
    def print_summary(self) -> None:
        duration = self.get_processing_time()
        speed = self.get_average_speed()
        
        print("\n" + "=" * 60)
        print("  DNS DATASET GENERATOR - PARSING SUMMARY")
        print("=" * 60)
        print(f"  Total input lines       : {self.total_input_lines:>10,}")
        print(f"  Valid DNS events        : {self.valid_dns_events:>10,}")
        print(f"  Malformed lines         : {self.malformed_lines:>10,}")
        print(f"  Skipped lines           : {self.skipped_lines:>10,}")
        print(f"  Duplicate events        : {self.duplicate_events:>10,}")
        print(f"  Unique domains          : {len(self.unique_domains):>10,}")
        print(f"  Unique client IPs       : {len(self.unique_client_ips):>10,}")
        print("-" * 60)
        print(f"  Processing time         : {duration:>10.2f}s")
        print(f"  Average speed           : {speed:>10.2f} lines/s")
        print("=" * 60)
        
        if self.top_domains:
            print("\n  Top 5 Domains:")
            for domain, count in self.top_domains.most_common(5):
                print(f"    {domain:<40s} {count:>8,}")
        
        if self.top_query_types:
            print("\n  Top 5 Query Types:")
            for qtype, count in self.top_query_types.most_common(5):
                print(f"    {qtype:<15s} {count:>8,}")
        
        if self.top_response_codes:
            print("\n  Top 5 Response Codes:")
            for code, count in self.top_response_codes.most_common(5):
                print(f"    {code:<15s} {count:>8,}")
        
        print()