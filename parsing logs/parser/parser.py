from __future__ import annotations

import csv
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from parser.models import DNSRecord
from parser.validators import validate_record, ValidationError

logger = logging.getLogger(__name__)

REQUIRED_HEADER_COLUMNS: Tuple[str, ...] = (
    "timestamp",
    "client_ip",
    "domain",
    "query_type",
)

OPTIONAL_COLUMNS_WITH_DEFAULTS: Dict[str, Optional[str]] = {
    "response_code": "UNKNOWN",   
    "resolved_ip": None,          
    "ttl": None,                  
    "raw_log": None,             
    "source_file": None,          
}
NULL_SENTINELS = frozenset({"", "NULL", "null", "None", "-"})

@dataclass
class ParseResult:

    source_file: str
    records: List[DNSRecord] = field(default_factory=list)
    failed_count: int = 0
    failed_lines: List[tuple] = field(default_factory=list)
    total_lines_read: int = 0

    @property
    def success_count(self) -> int:
        return len(self.records)

    @property
    def success_rate(self) -> float:
        if self.total_lines_read == 0:
            return 0.0
        return (self.success_count / self.total_lines_read) * 100

    def __iter__(self) -> Iterator[DNSRecord]:

        return iter(self.records)

    def __len__(self) -> int:
        return self.success_count

    def summary(self) -> str:

        return (
            f"\n{'=' * 60}\n"
            f"  PARSE SUMMARY: {Path(self.source_file).name}\n"
            f"{'=' * 60}\n"
            f"  Total rows read     : {self.total_lines_read}\n"
            f"  Successfully parsed : {self.success_count}\n"
            f"  Failed / skipped    : {self.failed_count}\n"
            f"  Success rate        : {self.success_rate:.1f}%\n"
            f"{'=' * 60}"
        )

class DNSLogParser:


    SUPPORTED_EXTENSIONS = (".csv",)

    def __init__(self, strict_mode: bool = False):

        self.strict_mode = strict_mode
        logger.info("DNSLogParser initialized. Strict mode: %s", strict_mode)


    def parse_file(self, file_path: str) -> ParseResult:

        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Dataset file not found: '{file_path}'. "
                f"Please check the path and try again."
            )

        if not path.is_file():
            raise ValueError(f"'{file_path}' is a directory, not a file.")

        extension = path.suffix.lower()
        if extension not in self.SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Unsupported file format: '{extension}'. "
                f"The parser now consumes only the normalized CSV produced "
                f"by the Dataset Generator. Supported formats: .csv"
            )

        logger.info("Starting to parse dataset: %s", path.name)
        return self._parse_csv_file(path)

    def parse_multiple_files(self, file_paths: List[str]) -> List[ParseResult]:

        results: List[ParseResult] = []

        for file_path in file_paths:
            try:
                result = self.parse_file(file_path)
                results.append(result)
                logger.info(
                    "Parsed '%s': %d records (%.1f%% success rate)",
                    file_path, result.success_count, result.success_rate,
                )
            except (FileNotFoundError, ValueError) as e:
                logger.error("Skipping file '%s': %s", file_path, e)

        return results

    def get_all_records(self, results: List[ParseResult]) -> List[DNSRecord]:

        return [record for result in results for record in result]


    def _parse_csv_file(self, path: Path) -> ParseResult:

        result = ParseResult(source_file=str(path))

        try:
            with path.open(encoding="utf-8-sig", newline="") as csv_file:
                reader = csv.DictReader(csv_file)

                if reader.fieldnames is None:
                    logger.error("CSV file '%s' appears to be empty.", path.name)
                    return result

                header_ok, missing = self._check_header(reader.fieldnames)
                logger.debug(
                    "CSV columns found in '%s': %s",
                    path.name, list(reader.fieldnames),
                )

                if not header_ok:
                    logger.error(
                        "CSV '%s' is missing mandatory columns: %s. "
                        "No rows can be parsed.",
                        path.name, missing,
                    )
                    return result

                defaulted = [
                    column for column in OPTIONAL_COLUMNS_WITH_DEFAULTS
                    if column not in reader.fieldnames
                ]
                if defaulted:
                    logger.warning(
                        "CSV '%s' is missing optional columns %s — "
                        "defaults will be applied to every row.",
                        path.name, defaulted,
                    )

                for line_num, raw_row in enumerate(reader, start=2):
                    result.total_lines_read += 1
                    normalized = self._normalize_row(raw_row)
                    self._process_row(normalized, result, line_num, str(path))

        except UnicodeDecodeError as e:
            logger.error("Encoding error reading '%s': %s", path.name, e)
        except csv.Error as e:
            logger.error("CSV structure error in '%s': %s", path.name, e)

        logger.info(result.summary())
        return result

    @staticmethod
    def _check_header(fieldnames: List[str]) -> Tuple[bool, List[str]]:

        present = set(fieldnames)
        missing = [
            column for column in REQUIRED_HEADER_COLUMNS
            if column not in present
        ]
        return (len(missing) == 0), missing

    @staticmethod
    def _normalize_row(raw_row: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:

        normalized: Dict[str, Optional[str]] = {}

        for key, value in raw_row.items():
            if key is None:
                continue
            if value is None:
                normalized[key] = None
                continue
            cleaned = value.strip()
            normalized[key] = None if cleaned in NULL_SENTINELS else cleaned

        for column, default in OPTIONAL_COLUMNS_WITH_DEFAULTS.items():
            if normalized.get(column) is None:
                normalized[column] = default

        return normalized

    def _process_row(
        self,
        row: Dict[str, Optional[str]],
        result: ParseResult,
        line_num: int,
        csv_path: str,
    ) -> None:
        try:
            validated = validate_record(row)

            raw_line = row.get("raw_log") or str(
                {k: v for k, v in row.items() if v is not None}
            )
            source_file = row.get("source_file") or csv_path

            record = DNSRecord(
                timestamp=validated["timestamp"],
                client_ip=validated["client_ip"],
                domain=validated["domain"],
                query_type=validated["query_type"],
                response_code=validated["response_code"],
                resolved_ip=validated.get("resolved_ip"),
                ttl=validated.get("ttl"),

                label=row.get("label"),
                threat_score=int(row["threat_score"]) if row.get("threat_score") else None,
                confidence=int(row["confidence"]) if row.get("confidence") else None,
                label_reason=row.get("label_reason"),
                
                raw_line=raw_line,
                source_file=source_file,
            )

            result.records.append(record)

            logger.debug(
                "Successfully parsed row %d: %s → %s",
                line_num, record.client_ip, record.domain,
            )

        except ValidationError as e:
            error_msg = str(e)
            self._handle_parse_failure(result, line_num, error_msg)

            if self.strict_mode:
                raise ValidationError(
                    f"Strict mode: Stopping at line {line_num}. "
                    f"Error: {error_msg}"
                ) from e

        except Exception as e:
            error_msg = f"Unexpected error: {type(e).__name__}: {e}"
            self._handle_parse_failure(result, line_num, error_msg)
            logger.exception("Unexpected error processing row %d", line_num)

    def _handle_parse_failure(
        self,
        result: ParseResult,
        line_num: int,
        error_msg: str,
    ) -> None:
        result.failed_count += 1
        result.failed_lines.append((line_num, error_msg))

        logger.warning(
            "Skipping malformed record at line %d: %s",
            line_num, error_msg,
        )