from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


class DatasetLogger:
 # Logger instances cache
    _loggers: dict = {}
    _initialized: bool = False
    _log_file: Optional[Path] = None
    
    @classmethod
    def setup_logging(
        cls,
        log_level: str = 'INFO',
        log_file: Optional[Path] = None,
        log_format: Optional[str] = None
    ) -> None:

        if cls._initialized:
            return
        
        if log_format is None:
            log_format = (
                '%(asctime)s - %(name)s - %(levelname)s - '
                '%(filename)s:%(lineno)d - %(message)s'
            )
        
        # Convert string level to numeric
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(numeric_level)
        
        # Remove existing handlers
        root_logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_formatter = logging.Formatter(log_format)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
        
        # File handler (optional)
        if log_file:
            cls._log_file = Path(log_file)
            cls._log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(
                str(cls._log_file),
                encoding='utf-8'
            )
            file_handler.setLevel(numeric_level)
            file_formatter = logging.Formatter(log_format)
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
        
        cls._initialized = True
        
        logger = logging.getLogger(__name__)
        logger.info(
            "Logging initialized: level=%s, file=%s",
            log_level,
            log_file or 'console only'
        )
    
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:

        if not cls._initialized:
            cls.setup_logging()
        
        if name not in cls._loggers:
            cls._loggers[name] = logging.getLogger(name)
        
        return cls._loggers[name]
    
    @classmethod
    def reset(cls) -> None:
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        cls._loggers.clear()
        cls._initialized = False
        cls._log_file = None


# Convenience function
def get_logger(name: str) -> logging.Logger:
    return DatasetLogger.get_logger(name)