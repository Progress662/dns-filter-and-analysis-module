from pathlib import Path
import gzip
import hashlib
import logging
import requests
import zipfile

from . import config
from .database import normalize_domain, timestamp_now

logger = logging.getLogger(__name__)


class TrancoDownloadError(Exception):
    pass


class TrancoExtractionError(Exception):
    pass


class DownloadedDataset:
    def __init__(self, path: Path, sha256: str, size: int, downloaded_at: str) -> None:
        self.path = path
        self.sha256 = sha256
        self.size = size
        self.downloaded_at = downloaded_at


def _is_gzip_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"\x1f\x8b"
    except OSError as exc:
        raise TrancoDownloadError("Failed to inspect downloaded Tranco dataset") from exc


def _verify_download(path: Path, expected_size: int | None = None) -> None:
    if not path.exists() or path.stat().st_size <= 0:
        raise TrancoDownloadError("Downloaded Tranco dataset is missing or empty")

    actual_size = path.stat().st_size

    if expected_size is not None and expected_size > 0 and actual_size != expected_size:
        raise TrancoDownloadError("Downloaded Tranco dataset size does not match Content-Length")

    lower_name = path.name.lower()

    if lower_name.endswith(".zip"):
        if not zipfile.is_zipfile(path):
            raise TrancoDownloadError("Downloaded Tranco dataset is not a valid ZIP archive")

        try:
            with zipfile.ZipFile(path) as archive:
                bad_member = archive.testzip()
                if bad_member is not None:
                    raise TrancoDownloadError("Downloaded Tranco ZIP archive failed validation")
        except zipfile.BadZipFile as exc:
            raise TrancoDownloadError("Downloaded Tranco ZIP archive is invalid") from exc

    if lower_name.endswith(".gz") and not _is_gzip_file(path):
        raise TrancoDownloadError("Downloaded Tranco dataset is not a valid gzip archive")


def download_latest_tranco(destination_dir: Path) -> DownloadedDataset:
    destination = Path(destination_dir)
    destination.mkdir(parents=True, exist_ok=True)

    output_path = destination / "tranco_top_1m.csv.zip"
    expected_size: int | None = None

    try:
        output_path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise TrancoDownloadError("Failed to prepare Tranco download path") from exc

    digest = hashlib.sha256()
    downloaded_size = 0

    headers = {
        "User-Agent": config.USER_AGENT,
        "Accept": "application/zip,text/csv,*/*",
    }

    try:
        with requests.get(
            config.TRANCO_DOWNLOAD_URL,
            headers=headers,
            timeout=config.REQUEST_TIMEOUT,
            stream=True,
        ) as response:
            response.raise_for_status()

            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    expected_size = int(content_length)
                except ValueError:
                    expected_size = None

            with output_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=config.CHUNK_SIZE):
                    if not chunk:
                        continue

                    handle.write(chunk)
                    digest.update(chunk)
                    downloaded_size += len(chunk)
    except requests.RequestException as exc:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise TrancoDownloadError("Failed to download latest Tranco dataset") from exc
    except OSError as exc:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise TrancoDownloadError("Failed to write downloaded Tranco dataset") from exc

    try:
        _verify_download(output_path, expected_size=expected_size)
    except Exception:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise

    if downloaded_size <= 0:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise TrancoDownloadError("Downloaded Tranco dataset contains no data")

    return DownloadedDataset(
        path=output_path,
        sha256=digest.hexdigest(),
        size=downloaded_size,
        downloaded_at=timestamp_now(),
    )


def _select_zip_member(archive: zipfile.ZipFile) -> zipfile.ZipInfo:
    members = [
        member
        for member in archive.infolist()
        if not member.is_dir() and not member.filename.startswith("__MACOSX/")
    ]
    if not members:
        raise TrancoExtractionError("Tranco ZIP archive contains no files")

    csv_members = [member for member in members if member.filename.lower().endswith(".csv")]

    if csv_members:
        return csv_members[0]

    return members[0]


def _parse_tranco_line(raw_line: bytes) -> tuple[int, str] | None:
    text = raw_line.decode("utf-8").strip()

    if not text:
        return None

    if text.startswith("\ufeff"):
        text = text.lstrip("\ufeff").strip()

    if not text:
        return None

    if "," not in text:
        raise TrancoExtractionError("Tranco dataset row is not comma separated")

    rank_text, domain_text = text.split(",", 1)
    rank_text = rank_text.strip().strip('"').strip("'")
    domain_text = domain_text.strip().strip('"').strip("'")

    if rank_text.lower() == "rank":
        return None

    try:
        rank = int(rank_text)
    except ValueError as exc:
        raise TrancoExtractionError("Tranco dataset row contains an invalid rank") from exc

    if rank <= 0:
        raise TrancoExtractionError("Tranco dataset row contains a non-positive rank")

    domain = normalize_domain(domain_text)

    if not domain:
        raise TrancoExtractionError("Tranco dataset row contains an invalid domain")

    return rank, domain


def _iter_lines(stream: object, source_name: str) -> object:
    line_number = 0
    skipped_count = 0
    
    for raw_line in stream:
        line_number += 1

        try:
            parsed = _parse_tranco_line(raw_line)
        except TrancoExtractionError as exc:
            logger.warning(
                "Skipping malformed row at %s:%d: %s", source_name, line_number, exc
            )
            skipped_count += 1
            continue
        except UnicodeDecodeError as exc:
            logger.warning(
                "Skipping row with decode error at %s:%d: %s", source_name, line_number, exc
            )
            skipped_count += 1
            continue

        if parsed is not None:
            yield parsed

    if skipped_count > 0:
        logger.info("Skipped %d malformed rows in %s", skipped_count, source_name)


def _iter_zip(path: Path) -> object:
    try:
        with zipfile.ZipFile(path) as archive:
            member = _select_zip_member(archive)
            with archive.open(member, "r") as stream:
                yield from _iter_lines(stream, member.filename)
    except TrancoExtractionError:
        raise
    except (OSError, zipfile.BadZipFile, EOFError) as exc:
        raise TrancoExtractionError("Failed to extract Tranco ZIP dataset") from exc


def _iter_gzip(path: Path) -> object:
    try:
        with gzip.open(path, "rb") as stream:
            yield from _iter_lines(stream, path.name)
    except TrancoExtractionError:
        raise
    except (OSError, EOFError) as exc:
        raise TrancoExtractionError("Failed to extract Tranco gzip dataset") from exc


def _iter_raw(path: Path) -> object:
    try:
        with path.open("rb") as stream:
            yield from _iter_lines(stream, path.name)
    except TrancoExtractionError:
        raise
    except OSError as exc:
        raise TrancoExtractionError("Failed to read Tranco dataset") from exc


def iter_tranco_domains(dataset_path: Path) -> object:
    path = Path(dataset_path)
    if not path.exists() or path.stat().st_size <= 0:
        raise TrancoExtractionError("Tranco dataset file is missing or empty")

    if zipfile.is_zipfile(path):
        yield from _iter_zip(path)
        return

    if _is_gzip_file(path):
        yield from _iter_gzip(path)
        return

    yield from _iter_raw(path)