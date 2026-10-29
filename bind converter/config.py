from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional


class DatasetGeneratorConfig:

    
    def __init__(self):
        # File paths
        self.input_path: Optional[Path] = None
        self.output_path: Optional[Path] = None
        self.invalid_log_path: Optional[Path] = None
        self.report_path: Optional[Path] = None

        self.log_level: str = 'INFO'
        self.log_format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        self.log_file: Optional[Path] = None

        self.csv_delimiter: str = ','
        self.csv_quotechar: str = '"'
        self.csv_null_value: str = 'NULL'
        self.csv_unknown_value: str = 'UNKNOWN'
        self.csv_chunksize: int = 10000 

        self.max_line_length: int = 10000  
        self.skip_comments: bool = True  
        self.comment_characters: str = '#'

        self.supported_categories: List[str] = [
            'queries',
            'resolver',
            'client',
            'security',
            'dnssec',
            'default',
            'lame-servers',
            'network',
            'database',
            'xfer-in',
            'xfer-out',
            'notify',
            'maintenance',
            'load',
            'checks',
            'control',
            'dispatch',
            'general',
            'rate-limit',
            'rpz',
            'spill',
            'trust-anchors'
        ]
        
        
        self.default_timezone: str = 'UTC'
        self.server_name: str = 'bind9-server'
        self.hostname: Optional[str] = None
        
    
        self.buffer_size: int = 8192  
        self.max_invalid_lines_stored: int = 100 
        
        
        self.enable_deduplication: bool = True

        self.live_mode: bool = False
        
        
        self.generate_report: bool = True
        self.report_filename: str = 'report.json'
        self.invalid_log_filename: str = 'invalid_logs.csv'
    
    def set_input_output(
        self,
        input_path: Path,
        output_path: Path,
        output_dir: Optional[Path] = None
    ) -> None:

        self.input_path = input_path
        self.output_path = output_path
        
        if output_dir is None:
            output_dir = output_path.parent
        
        self.report_path = output_dir / self.report_filename
        self.invalid_log_path = output_dir / self.invalid_log_filename
        
        output_dir.mkdir(parents=True, exist_ok=True)
    
    def get_logging_config(self) -> Dict:

        config = {
            'level': getattr(__import__('logging'), self.log_level.upper()),
            'format': self.log_format,
        }
        
        if self.log_file:
            config['filename'] = str(self.log_file)
        
        return config


config = DatasetGeneratorConfig()