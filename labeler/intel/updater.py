from pathlib import Path
import tempfile

from . import config
from . import database
from . import downloader
from .lock import UpdateLock


class TrustedWhitelistUpdateError(Exception):
    pass


def _metadata_is_complete(metadata: dict[str, str]) -> bool:
    for key in config.METADATA_KEYS:
        if not metadata.get(key):
            return False
    return True


def whitelist_needs_update(database_path: Path = config.DATABASE_PATH) -> bool:
    path = Path(database_path)

    if not path.exists():
        return True

    try:
        database.validate_database(path, require_integrity=False)
        metadata = database.read_metadata(path)

    except database.TrustedDatabaseError:
        return True

    if not _metadata_is_complete(metadata):
        return True

    if metadata.get("source") != config.SOURCE_NAME:
        return True

    try:
        record_count = int(metadata.get("record_count", "0"))

    except ValueError:
        return True

    if record_count <= 0:
        return True

    last_update = database.parse_timestamp(metadata.get("last_update", ""))

    if last_update is None:
        return True

    age = database.utc_now() - last_update

    return age >= config.REFRESH_INTERVAL


def update_whitelist(database_path: Path = config.DATABASE_PATH) -> bool:
    active_database_path = Path(database_path)
    active_database_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(
            prefix=config.TEMP_PREFIX,
            dir=str(active_database_path.parent),
        ) as temporary_directory:

            temporary_path = Path(temporary_directory)
            prepared_database_path = temporary_path / config.DATABASE_FILENAME

            downloaded_dataset = downloader.download_latest_tranco(temporary_path)
            domain_rows = downloader.iter_tranco_domains(downloaded_dataset.path)

            record_count = database.create_trusted_domains_database(
                prepared_database_path,
                domain_rows,
                downloaded_dataset.sha256,
                downloaded_dataset.downloaded_at,
            )

            database.validate_database(
                prepared_database_path,
                expected_count=record_count,
                require_integrity=True,
            )

            database.replace_database(
                prepared_database_path,
                active_database_path,
            )

        return True

    except downloader.TrancoDownloadError as exc:
        raise TrustedWhitelistUpdateError(
            "Trusted whitelist download failed"
        ) from exc

    except downloader.TrancoExtractionError as exc:
        raise TrustedWhitelistUpdateError(
            "Trusted whitelist extraction failed"
        ) from exc

    except database.TrustedDatabaseError as exc:
        raise TrustedWhitelistUpdateError(
            "Trusted whitelist database update failed"
        ) from exc

    except OSError as exc:
        raise TrustedWhitelistUpdateError(
            "Trusted whitelist filesystem update failed"
        ) from exc


def ensure_updated(
    database_path: Path = config.DATABASE_PATH,
    force: bool = False,
) -> bool:

    path = Path(database_path)

    with UpdateLock():

        # Another process may have already updated the database
        # while we were waiting for the lock.
        if not force and not whitelist_needs_update(path):
            return False

        return update_whitelist(path)