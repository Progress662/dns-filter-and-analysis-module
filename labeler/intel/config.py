from datetime import timedelta
from pathlib import Path
import os

PACKAGE_DIR = Path(__file__).resolve().parent

DATABASE_FILENAME = "trusted_domains.db"
DATABASE_PATH = Path(
    os.environ.get(
        "TRUSTED_DOMAINS_DB",
        str(PACKAGE_DIR / DATABASE_FILENAME),
    )
).expanduser().resolve()

LOCK_PATH = PACKAGE_DIR / "trusted_domains.lock"

SQLITE_MMAP_SIZE = 256 * 1024 * 1024  # 256 MB

TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"
SOURCE_NAME = "tranco"

REFRESH_INTERVAL_DAYS = 30
REFRESH_INTERVAL = timedelta(days=REFRESH_INTERVAL_DAYS)

REQUEST_TIMEOUT = (10, 300)
CHUNK_SIZE = 1024 * 1024

SQLITE_TIMEOUT = 30.0
SQLITE_BATCH_SIZE = 10000
SQLITE_CACHED_STATEMENTS = 128

USER_AGENT = "TrustedWhitelistManager/1.0"
TEMP_PREFIX = "trusted_domains_"

METADATA_KEYS = (
    "last_update",
    "dataset_version",
    "record_count",
    "source",
)