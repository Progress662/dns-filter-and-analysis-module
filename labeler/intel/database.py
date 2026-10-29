from datetime import datetime, timezone
from pathlib import Path
import os
import sqlite3

from . import config


class TrustedDatabaseError(Exception):
    pass


CREATE_TRUSTED_DOMAINS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS trusted_domains (
    domain TEXT NOT NULL,
    rank INTEGER NOT NULL,
    source TEXT NOT NULL,
    downloaded_at TEXT NOT NULL,
    PRIMARY KEY (domain)
) WITHOUT ROWID
"""

CREATE_METADATA_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (key)
) WITHOUT ROWID
"""

CREATE_RANK_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_trusted_domains_rank
ON trusted_domains(rank)
"""

INSERT_DOMAIN_SQL = """
INSERT INTO trusted_domains(domain, rank, source, downloaded_at)
VALUES (?, ?, ?, ?)
"""

UPSERT_METADATA_SQL = """
INSERT INTO metadata(key, value)
VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value
"""

LOOKUP_SQL = "SELECT 1 FROM trusted_domains WHERE domain = ? LIMIT 1"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None

    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def normalize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        return ""

    value = domain.strip().strip("'\"").lower()

    if not value:
        return ""

    value = value.replace("\\", "/")

    if "://" in value:
        value = value.split("://", 1)[1]

    if value.startswith("//"):
        value = value[2:]

    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]

    if "@" in value:
        value = value.rsplit("@", 1)[1]

    if value.startswith("["):
        return ""

    if ":" in value:
        value = value.split(":", 1)[0]

    value = value.strip().strip(".")

    if not value or len(value) > 253:
        return ""

    try:
        ascii_domain = value.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return ""

    if not ascii_domain or len(ascii_domain) > 253:
        return ""

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        return ""

    for label in labels:
        if not label or len(label) > 63:
            return ""

        if label.startswith("-") or label.endswith("-"):
            return ""

        for character in label:
            if not (character.isascii() and (character.isalnum() or character == "-")):
                return ""

    if labels[-1].isdigit():
        return ""

    return ascii_domain


def _sidecar_paths(database_path: Path) -> tuple[Path, Path]:
    return Path(str(database_path) + "-wal"), Path(str(database_path) + "-shm")


def _remove_sidecars_best_effort(database_path: Path) -> None:
    for sidecar_path in _sidecar_paths(database_path):
        try:
            sidecar_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _finalize_prepared_database_files(database_path: Path) -> None:
    wal_path, shm_path = _sidecar_paths(database_path)
    try:
        if wal_path.exists():
            if wal_path.stat().st_size > 0:
                raise TrustedDatabaseError("Prepared database has an uncheckpointed WAL file")
            wal_path.unlink()

        if shm_path.exists():
            shm_path.unlink()
    except OSError as exc:
        raise TrustedDatabaseError("Failed to finalize prepared database files") from exc


def remove_database_files(database_path: Path) -> None:
    path = Path(database_path)

    for candidate in (path, *_sidecar_paths(path)):
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise TrustedDatabaseError(f"Failed to remove database file: {candidate}") from exc


def open_read_connection(database_path: Path) -> sqlite3.Connection:
    path = Path(database_path)
    if not path.exists():
        raise TrustedDatabaseError(f"Trusted domains database does not exist: {path}")

    try:
        connection = sqlite3.connect(
            str(path),
            timeout=config.SQLITE_TIMEOUT,
            isolation_level=None,
            cached_statements=config.SQLITE_CACHED_STATEMENTS,
        )
        connection.execute(f"PRAGMA busy_timeout = {int(config.SQLITE_TIMEOUT * 1000)}")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA query_only = ON")
        return connection
    except sqlite3.Error as exc:
        raise TrustedDatabaseError("Failed to open trusted domains database") from exc


def _open_write_connection(database_path: Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            str(database_path),
            timeout=config.SQLITE_TIMEOUT,
            isolation_level=None,
            cached_statements=config.SQLITE_CACHED_STATEMENTS,
        )
        connection.execute(f"PRAGMA busy_timeout = {int(config.SQLITE_TIMEOUT * 1000)}")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA cache_size = -65536")
        connection.execute("PRAGMA locking_mode = EXCLUSIVE")
        return connection
    except sqlite3.Error as exc:
        raise TrustedDatabaseError("Failed to open writable trusted domains database") from exc


def _create_tables(connection: sqlite3.Connection) -> None:
    connection.execute(CREATE_TRUSTED_DOMAINS_TABLE_SQL)
    connection.execute(CREATE_METADATA_TABLE_SQL)


def _create_indexes(connection: sqlite3.Connection) -> None:
    connection.execute(CREATE_RANK_INDEX_SQL)


def _write_metadata(connection: sqlite3.Connection, metadata: dict[str, str]) -> None:
    rows = [(key, metadata[key]) for key in config.METADATA_KEYS]
    connection.executemany(UPSERT_METADATA_SQL, rows)


def read_metadata(database_path: Path = config.DATABASE_PATH) -> dict[str, str]:
    path = Path(database_path)
    if not path.exists():
        return {}

    connection: sqlite3.Connection | None = None

    try:
        connection = open_read_connection(path)
        rows = connection.execute("SELECT key, value FROM metadata").fetchall()
        return {str(key): str(value) for key, value in rows}
    except sqlite3.Error as exc:
        raise TrustedDatabaseError("Failed to read trusted domains metadata") from exc
    finally:
        if connection is not None:
            connection.close()


def validate_database(
    database_path: Path,
    expected_count: int | None = None,
    require_integrity: bool = False,
) -> bool:
    path = Path(database_path)
    if not path.exists() or path.stat().st_size <= 0:
        raise TrustedDatabaseError("Trusted domains database file is missing or empty")

    connection: sqlite3.Connection | None = None

    try:
        connection = open_read_connection(path)

        trusted_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'trusted_domains' LIMIT 1"
        ).fetchone()
        metadata_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metadata' LIMIT 1"
        ).fetchone()

        if trusted_table is None or metadata_table is None:
            raise TrustedDatabaseError("Trusted domains database schema is incomplete")

        metadata_rows = connection.execute("SELECT key, value FROM metadata").fetchall()
        metadata = {str(key): str(value) for key, value in metadata_rows}

        for key in config.METADATA_KEYS:
            if not metadata.get(key):
                raise TrustedDatabaseError(f"Trusted domains metadata is missing: {key}")

        try:
            metadata_count = int(metadata["record_count"])
        except ValueError as exc:
            raise TrustedDatabaseError("Trusted domains metadata record_count is invalid") from exc

        if metadata_count <= 0:
            raise TrustedDatabaseError("Trusted domains database contains no records")

        actual_count = int(
            connection.execute("SELECT COUNT(*) FROM trusted_domains").fetchone()[0]
        )

        if actual_count <= 0:
            raise TrustedDatabaseError("Trusted domains database contains no trusted domains")

        if expected_count is not None and actual_count != expected_count:
            raise TrustedDatabaseError("Trusted domains database record count validation failed")

        if actual_count != metadata_count:
            raise TrustedDatabaseError("Trusted domains metadata count does not match database count")

        if require_integrity:
            integrity_result = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity_result is None or integrity_result[0] != "ok":
                raise TrustedDatabaseError("Trusted domains database integrity check failed")

        return True
    except sqlite3.Error as exc:
        raise TrustedDatabaseError("Trusted domains database validation failed") from exc
    finally:
        if connection is not None:
            connection.close()


def create_trusted_domains_database(
    database_path: Path,
    domain_rows: object,
    dataset_version: str,
    downloaded_at: str,
) -> int:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    remove_database_files(path)
    connection: sqlite3.Connection | None = None
    inserted_count = 0

    try:
        connection = _open_write_connection(path)
        connection.execute("BEGIN IMMEDIATE")
        _create_tables(connection)

        batch: list[tuple[str, int, str, str]] = []

        for rank, domain in domain_rows:
            normalized_domain = normalize_domain(domain)

            if not normalized_domain:
                continue

            try:
                normalized_rank = int(rank)
            except (TypeError, ValueError) as exc:
                raise TrustedDatabaseError("Extracted dataset contains an invalid rank") from exc

            if normalized_rank <= 0:
                raise TrustedDatabaseError("Extracted dataset contains a non-positive rank")

            batch.append((normalized_domain, normalized_rank, config.SOURCE_NAME, downloaded_at))

            if len(batch) >= config.SQLITE_BATCH_SIZE:
                connection.executemany(INSERT_DOMAIN_SQL, batch)
                inserted_count += len(batch)
                batch.clear()

        if batch:
            connection.executemany(INSERT_DOMAIN_SQL, batch)
            inserted_count += len(batch)
            batch.clear()

        if inserted_count <= 0:
            raise TrustedDatabaseError("No trusted domains were extracted from the dataset")

        _create_indexes(connection)

        metadata = {
            "last_update": downloaded_at,
            "dataset_version": dataset_version,
            "record_count": str(inserted_count),
            "source": config.SOURCE_NAME,
        }

        _write_metadata(connection, metadata)

        connection.commit()
        connection.execute("PRAGMA optimize")
        checkpoint_result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()

        if checkpoint_result is not None and int(checkpoint_result[0]) != 0:
            raise TrustedDatabaseError("Failed to checkpoint prepared trusted domains database")
    except Exception as exc:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass

            connection.close()
            connection = None

        remove_database_files(path)

        if isinstance(exc, TrustedDatabaseError):
            raise

        raise TrustedDatabaseError("Failed to create trusted domains database") from exc
    finally:
        if connection is not None:
            connection.close()

    try:
        _finalize_prepared_database_files(path)
        validate_database(path, expected_count=inserted_count, require_integrity=True)
        _finalize_prepared_database_files(path)
    except Exception as exc:
        remove_database_files(path)

        if isinstance(exc, TrustedDatabaseError):
            raise

        raise TrustedDatabaseError("Prepared trusted domains database validation failed") from exc

    return inserted_count


def replace_database(prepared_database_path: Path, active_database_path: Path) -> None:
    prepared_path = Path(prepared_database_path)
    active_path = Path(active_database_path)

    if not prepared_path.exists():
        raise TrustedDatabaseError("Prepared trusted domains database does not exist")

    try:
        _finalize_prepared_database_files(prepared_path)
        active_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(str(prepared_path), str(active_path))
        _remove_sidecars_best_effort(active_path)
    except OSError as exc:
        raise TrustedDatabaseError("Failed to atomically replace trusted domains database") from exc


def is_domain_trusted(database_path: Path, domain: str) -> bool:
    normalized_domain = normalize_domain(domain)

    if not normalized_domain:
        return False

    connection: sqlite3.Connection | None = None

    try:
        connection = open_read_connection(Path(database_path))
        return connection.execute(LOOKUP_SQL, (normalized_domain,)).fetchone() is not None
    except sqlite3.Error as exc:
        raise TrustedDatabaseError("Trusted domain lookup failed") from exc
    finally:
        if connection is not None:
            connection.close()