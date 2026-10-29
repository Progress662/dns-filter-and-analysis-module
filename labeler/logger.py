"""
Logging utilities for the DNS Dataset Labeller.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"

# Logging configuration
LOG_FILE = LOG_DIR / "dns_labeller.log"
LOG_LEVEL = logging.INFO
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5


def setup_logger(name: str = "dns_labeller") -> logging.Logger:
    """
    Configure and return a logger for the DNS Dataset Labeller.

    The logger writes to both:
        - Console
        - Rotating log file

    Duplicate handlers are avoided if the logger has already been configured.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)

    if logger.hasHandlers():
        return logger

    logger.setLevel(LOG_LEVEL)
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler
    file_handler = RotatingFileHandler(
        filename=LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Global logger instance
logger = setup_logger()