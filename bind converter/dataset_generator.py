from __future__ import annotations

import argparse
import gzip
import logging
import sys
from pathlib import Path
from typing import List, Optional, Iterator
from datetime import datetime

from live_log_reader import LiveLogReader
from bind_parser import BINDLogParser, ParsedBINDLine
from csv_writer import DNSDatasetCSVWriter
from logger import DatasetLogger, get_logger
from config import DatasetGeneratorConfig, config
from parser_statistics import ParsingStatistics
from event_id import EventIDGenerator

logger = get_logger(__name__)


class DatasetGenerator:
    def __init__(self, cfg: DatasetGeneratorConfig):
        self.config = cfg
        self.parser = BINDLogParser()
        self.statistics = ParsingStatistics()
        self.writer: Optional[DNSDatasetCSVWriter] = None
        self.invalid_writer: Optional[DNSDatasetCSVWriter] = None

    def process_input(
        self,
        input_path: Path,
        output_path: Path,
        recursive: bool = False
    ) -> None:
        logger.info(f"Processing input: {input_path}")
        logger.info(f"Output file: {output_path}")

        # Configure paths
        self.config.set_input_output(input_path, output_path)

        # Open CSV writers
        self.writer = DNSDatasetCSVWriter(output_path, mode='w')
        self.writer.open()

        if self.config.invalid_log_path:
            self.invalid_writer = DNSDatasetCSVWriter(
                self.config.invalid_log_path,
                mode='w'
            )
            self.invalid_writer.open()

        try:
            # Find and process all log files
            log_files = self._find_log_files(input_path, recursive)

            if not log_files:
                logger.error(f"No BIND9 log files found in: {input_path}")
                return

            logger.info(f"Found {len(log_files)} log file(s) to process")

            for log_file in log_files:
                logger.info(f"Processing file: {log_file}")
                self._process_single_file(log_file)

            # Finalize statistics
            self.statistics.finish()

            # Generate summary
            self.statistics.print_summary()

            # Generate and save report
            if self.config.generate_report:
                report = self.statistics.generate_report(str(output_path))
                self.statistics.save_report(
                    self.config.report_path,
                    report
                )

            logger.info("Dataset generation completed successfully")

        except Exception as e:
            logger.error(f"Error during dataset generation: {e}", exc_info=True)
            raise

        finally:
            # Close writers
            if self.writer:
                self.writer.close()
            if self.invalid_writer:
                self.invalid_writer.close()

    def _find_log_files(
        self,
        input_path: Path,
        recursive: bool = False
    ) -> List[Path]:
        if input_path.is_file():
            return [input_path]

        if not input_path.is_dir():
            logger.error(f"Input path does not exist: {input_path}")
            return []

        # Supported file extensions
        extensions = {'.log', '.txt', '.gz'}

        if recursive:
            log_files = sorted([
                f for f in input_path.rglob('*')
                if f.is_file() and f.suffix in extensions
            ])
        else:
            log_files = sorted([
                f for f in input_path.glob('*')
                if f.is_file() and f.suffix in extensions
            ])

        # Also check for files without extension (common for rotated logs)
        if recursive:
            no_ext_files = sorted([
                f for f in input_path.rglob('*')
                if f.is_file() and f.suffix == '' and not f.name.startswith('.')
            ])
        else:
            no_ext_files = sorted([
                f for f in input_path.glob('*')
                if f.is_file() and f.suffix == '' and not f.name.startswith('.')
            ])

        # Check if they might be log files by reading first few bytes
        for f in no_ext_files:
            try:
                with open(f, 'rb') as fh:
                    first_bytes = fh.read(100)
                    # Check if contains typical BIND9 timestamp pattern
                    if b'-' in first_bytes and b':' in first_bytes:
                        log_files.append(f)
            except (IOError, OSError):
                continue

        return log_files

    def _process_single_file(self, file_path: Path) -> None:
        if getattr(self.config, "live_mode" , False):
            line_iterator = LiveLogReader(file_path)
        
        else:
            line_iterator = self._get_line_iterator(file_path)

        for line_number, line in line_iterator:
            self.statistics.record_input_line(str(file_path))

            # Skip empty lines and comments
            if not line or line.strip() == '':
                self.statistics.record_skipped_line('empty')
                continue

            if self.config.skip_comments and line.strip()[0] in self.config.comment_characters:
                self.statistics.record_skipped_line('comment')
                continue

            # Truncate extremely long lines
            if len(line) > self.config.max_line_length:
                line = line[:self.config.max_line_length]
                logger.warning(
                    f"Line {line_number} truncated to {self.config.max_line_length} chars"
                )

            # Parse the line
            parsed_line = self.parser.parse_line(
                line,
                str(file_path),
                line_number
            )

            if parsed_line.is_valid:
                # Check for duplicates if enabled
                if self.config.enable_deduplication:
                    event_id = EventIDGenerator.generate_event_id(
                        timestamp=parsed_line.timestamp,
                        client_ip=parsed_line.client_ip,
                        domain=parsed_line.domain,
                        query_type=parsed_line.query_type,
                        client_port=parsed_line.client_port
                    )

                    if self.statistics.check_duplicate(event_id):
                        continue

                # Write valid event to CSV
                if self.writer:
                    self.writer.write_event(parsed_line)

                self.statistics.record_valid_event(parsed_line)

            else:
                # Handle invalid/malformed lines
                self.statistics.record_malformed_line(
                    line,
                    str(file_path),
                    line_number,
                    parsed_line.error_message or 'Unknown parse error'
                )

                # Write to invalid logs CSV
                if self.invalid_writer:
                    self.invalid_writer.write_invalid_event(
                        line,
                        str(file_path),
                        line_number,
                        parsed_line.error_message or 'Unknown parse error'
                    )

    def _get_line_iterator(self, file_path: Path) -> Iterator:

        #live mode
        if getattr(self.config, "live_mode", False):
            reader = LiveLogReader(file_path)
            yield from reader
            return 


        if file_path.suffix == '.gz':
            # Handle gzip compressed files
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, start=1):
                    yield line_number, line
        else:
            # Handle regular text files
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for line_number, line in enumerate(f, start=1):
                    yield line_number, line

    def process_string(self, log_content: str, source: str = 'string_input') -> Path:
        import tempfile

        # Create temporary file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.log',
            delete=False,
            encoding='utf-8'
        ) as f:
            f.write(log_content)
            temp_path = Path(f.name)

        # Process the temporary file
        output_path = Path(temp_path.parent) / (temp_path.stem + '_dataset.csv')

        try:
            self.process_input(temp_path, output_path)
        finally:
            # Clean up temporary file
            temp_path.unlink()

        return output_path


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='DNS Threat Detection - Dataset Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dataset_generator.py --input bind.log --output dns_dataset.csv
  python dataset_generator.py --input logs/ --output dataset.csv --recursive
  python dataset_generator.py --input bind.log.gz --output dataset.csv --log-level DEBUG
        """
    )

    parser.add_argument(
        '--input', '-i',
        type=str,
        required=True,
        help='Path to BIND9 log file or directory'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        required=True,
        help='Output CSV file path'
    )

    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Recursively process log files in directories'
    )

    parser.add_argument(
        '--log-level',
        type=str,
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Logging level (default: INFO)'
    )

    parser.add_argument(
        '--log-file',
        type=str,
        default=None,
        help='Path to log file (optional)'
    )

    parser.add_argument(
        '--no-dedup',
        action='store_true',
        help='Disable event deduplication'
    )

    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Disable report generation'
    )

    parser.add_argument(
        '--hostname',
        type=str,
        default=None,
        help='Hostname to use in records'
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    # Setup logging
    DatasetLogger.setup_logging(
        log_level=args.log_level,
        log_file=Path(args.log_file) if args.log_file else None
    )

    logger.info("=" * 60)
    logger.info("  DNS Dataset Generator v1.0")
    logger.info("  AI-Based DNS Threat Detection System")
    logger.info("=" * 60)

    try:
        # Configure generator
        gen_config = DatasetGeneratorConfig()
        gen_config.enable_deduplication = not args.no_dedup
        gen_config.generate_report = not args.no_report
        gen_config.hostname = args.hostname

        # Create and run generator
        generator = DatasetGenerator(gen_config)

        input_path = Path(args.input)
        output_path = Path(args.output)

        generator.process_input(
            input_path,
            output_path,
            recursive=args.recursive
        )

    except KeyboardInterrupt:
        logger.info("Dataset generation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()