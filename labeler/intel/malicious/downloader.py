"""
URLhaus Feeds Downloader.

Mirrors Trusted DB Downloader. Handles downloading, extracting, validating,
and parsing the URLhaus CSV feed.
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
import time
import traceback
import urllib.error
import urllib.request
import zipfile
from typing import Iterator, Optional, Tuple, List

from .config import (
    DATA_SOURCE_URL,
    DOWNLOAD_TIMEOUT,
    MAX_DOWNLOAD_RETRIES,
    TEMP_DOWNLOAD_BUFFER_SIZE,
    CHECKSUM_ALGORITHM,
)
from .database import MaliciousDatabaseError, MaliciousDBValidationError

logger = logging.getLogger(__name__)


def normalize_domain(url_or_domain: str) -> str:
    """
    Normalizes domain strings to a canonical form.
    """
    if url_or_domain is None:
        return ""
    domain = str(url_or_domain).strip().lower()
    if not domain:
        return ""
    for scheme in ("https://", "http://"):
        if domain.startswith(scheme):
            domain = domain[len(scheme):]
            break
    if "?" in domain:
        domain = domain.split("?", 1)[0]
    if "#" in domain:
        domain = domain.split("#", 1)[0]
    domain = domain.split("/", 1)[0]
    if ":" in domain and "[" not in domain:
        domain = domain.rsplit(":", 1)[0]
    if domain.startswith("www."):
        domain = domain[4:]
    if not domain or len(domain) < 3:
        return ""
    return domain


def download_file(url: str, retries: int = MAX_DOWNLOAD_RETRIES) -> bytes:
    last_error: Optional[Exception] = None
    for attempt in range(retries):
        try:
            logger.info("Downloading data from %s (attempt %d/%d)", url, attempt + 1, retries)
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Linux; Intel)",
                    "Accept": (
                        "text/csv,application/zip,application/gzip,"
                        "application/octet-stream,text/plain"
                    ),
                },
            )
            with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
                final_url = resp.geturl()
                content_type = resp.headers.get("Content-Type", "unknown")
                content_disp = resp.headers.get("Content-Disposition", "unknown")
                logger.info(
                    "[DIAGNOSTIC] Final redirected URL: %s | Content-Type: %s | Content-Disposition: %s",
                    final_url,
                    content_type,
                    content_disp,
                )
                if resp.status != 200:
                    raise MaliciousDatabaseError(f"Server returned HTTP {resp.status}")
                raw_data = resp.read()
            if not raw_data:
                raise MaliciousDatabaseError("Empty response received")
            if raw_data[:100].lstrip().startswith(b"<"):
                snippet = raw_data[:200].decode("utf-8", errors="replace").replace("\n", " ")
                raise MaliciousDBValidationError(
                    f"Response appears to be HTML, not CSV/archive. Snippet: {snippet}"
                )
            logger.info("Downloaded %d bytes", len(raw_data))
            return raw_data
        except urllib.error.HTTPError as exc:
            last_error = exc
            logger.warning("HTTP error: %s", exc)
        except urllib.error.URLError as exc:
            last_error = exc
            logger.warning("Network error: %s", exc)
        except Exception as exc:
            last_error = exc
            logger.warning("Download error: %s", exc)
        if attempt < retries - 1:
            delay = 2 * (attempt + 1)
            logger.info("Waiting %d seconds before retry...", delay)
            time.sleep(delay)
    raise MaliciousDatabaseError(
        f"Failed to download after {retries} attempts. Last error: {last_error}"
    ) from last_error


def _extract_feed_bytes(data: bytes) -> Tuple[bytes, List[str], str]:
    members = []
    format_label = "unknown"
    if zipfile.is_zipfile(io.BytesIO(data)):
        format_label = "ZIP"
        logger.info("Detected file type: ZIP")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = [n for n in archive.namelist() if not n.endswith("/")]
                csv_members = [n for n in members if n.lower().endswith(".csv")]
                selected = csv_members[0] if csv_members else (members[0] if members else None)
                if selected is None:
                    raise MaliciousDBValidationError("ZIP archive contains no members.")
                logger.info("[DIAGNOSTIC] Archive members: %s", members)
                logger.info("[DIAGNOSTIC] Selected archive member: %s", selected)
                return archive.read(selected), members, format_label
        except zipfile.BadZipFile as exc:
            raise MaliciousDBValidationError(f"Invalid ZIP archive: {exc}") from exc

    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        format_label = "GZIP"
        logger.info("Detected file type: GZIP")
        try:
            decompressed = gzip.decompress(data)
            return decompressed, members, format_label
        except Exception as exc:
            raise MaliciousDBValidationError(f"GZIP decompression failed: {exc}") from exc

    logger.info("Detected file type: plain CSV")
    return data, members, format_label


def _find_column_index(row_values: List[str], *candidates: str) -> Optional[int]:
    for idx, val in enumerate(row_values):
        v = val.lower()
        for cand in candidates:
            if cand.lower() in v:
                return idx
    return None


def parse_urlhaus_csv(data: bytes) -> Iterator[Tuple[str, str]]:
    if data is None or len(data) == 0:
        raise MaliciousDBValidationError("Input data is empty or None")

    csv_bytes, archive_members, fmt = _extract_feed_bytes(data)

    try:
        decoded_text = csv_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MaliciousDBValidationError(f"Failed to decode feed as UTF-8: {exc}") from exc

    lines = decoded_text.splitlines()
    logger.info("[DIAGNOSTIC] First 30 raw lines after extraction (%s):", fmt)
    for i, line in enumerate(lines[:30], start=1):
        logger.info("[DIAGNOSTIC] Line %02d: %s", i, line)

    # FIX 1: Detect and preserve the official URLhaus column-header comment line.
    # The feed ships its CSV header as a comment, e.g.:
    #   # id,dateadded,url,url_status,last_online,...
    # We strip the leading '#' and inject it as the real first data line so
    # DictReader picks it up correctly.  Decorative banner/comment lines are
    # still discarded as before.
    filtered = []
    first_non_comment = None
    csv_header_from_comment = None
    for line in lines:
        stripped = line.strip()
        if stripped == "":
            continue
        if stripped.startswith("#"):
            # Identify the official URLhaus column-header comment: after
            # stripping the leading '#' and whitespace it must start with "id"
            # and contain a "url" field.
            candidate = stripped.lstrip("#").strip()
            candidate_lower = candidate.lower()
            if (
                csv_header_from_comment is None
                and candidate_lower.startswith("id")
                and "url" in candidate_lower
            ):
                csv_header_from_comment = candidate
                logger.info(
                    "[DIAGNOSTIC] Detected URLhaus column-header comment: %s",
                    csv_header_from_comment,
                )
            # Always skip comment lines from the data body
            continue
        filtered.append(line)
        if first_non_comment is None:
            first_non_comment = stripped

    # Prepend the recovered header so DictReader sees it as the header row.
    if csv_header_from_comment is not None:
        filtered.insert(0, csv_header_from_comment)

    logger.info("[DIAGNOSTIC] First non-comment non-empty line: %s", first_non_comment)

    if not filtered:
        raise MaliciousDBValidationError("Feed contains no CSV data after removing comments/blank lines")

    stream_text = "\n".join(filtered)
    stream = io.StringIO(stream_text)

    sample_reader = csv.reader(io.StringIO(stream_text.splitlines()[0]))
    try:
        first_row_fields = next(sample_reader)
    except StopIteration:
        first_row_fields = []

    header_detected = False

    header_lookup = {f.strip().lower(): f.strip() for f in first_row_fields}
    if "url" in header_lookup:
        header_detected = True
    elif "url_status" in header_lookup or "status" in header_lookup:
        header_detected = True
    else:
        url_idx = _find_column_index(first_row_fields, "http://", "https://")
        status_idx = _find_column_index(first_row_fields, "online", "offline")
        has_url_like = url_idx is not None
        has_status_like = status_idx is not None
        first_col_numeric = False
        if len(first_row_fields) > 0:
            try:
                int(first_row_fields[0].split(",")[0].strip().split()[0])
                first_col_numeric = True
            except (ValueError, IndexError):
                pass
        if has_url_like or has_status_like or first_col_numeric:
            logger.info(
                "[DIAGNOSTIC] No CSV header detected; treating feed as headerless with %d columns",
                len(first_row_fields),
            )
            header_detected = False
        else:
            header_detected = True

    if header_detected:
        stream.seek(0)
        reader = csv.DictReader(stream)
        headers = reader.fieldnames or []
        logger.info("[DIAGNOSTIC] CSV header detected: %s", headers)

        url_col = None
        for h in headers:
            if h and h.strip().lower() == "url":
                url_col = h.strip()
                break

        if not url_col:
            lookup = {str(f).lower(): str(f) for f in headers}
            url_col = lookup.get("url")

        if not url_col:
            stream.seek(0)
            reader = csv.DictReader(stream)
            first_data_row = None
            for row in reader:
                first_data_row = row
                break
            if first_data_row is None:
                raise MaliciousDBValidationError(
                    "CSV contains a header but zero data rows. Cannot determine URL column."
                )
            stream.seek(0)
            reader = csv.DictReader(stream)
            for h in (reader.fieldnames or []):
                if h:
                    val = (first_data_row.get(h) or "").strip()
                    if val.startswith("http://") or val.startswith("https://"):
                        url_col = h
                        break
            stream.seek(0)
            reader = csv.DictReader(stream)

        if not url_col:
            raise MaliciousDBValidationError(
                f"Feed does not contain a URL column. Headers: {headers if 'headers' in locals() else first_row_fields}"
            )

        lookup = {str(f).lower(): str(f) for f in (reader.fieldnames or [])}
        status_col = lookup.get("status") or lookup.get("url_status")

        stream.seek(0)
        reader = csv.DictReader(stream)

    else:
        # FIX 2: Assign synthetic column names without duplicating "url".
        # Previously every column whose value contained "http://" or "https://"
        # was named "url", so urlhaus_link (also an HTTP URL) would shadow the
        # real url column and DictReader would bind "url" to the wrong field.
        # Now only the FIRST HTTP-URL-valued column receives the name "url";
        # all subsequent ones get a generic positional name.
        synthetic_headers = []
        url_col_assigned = False
        for idx, val in enumerate(first_row_fields):
            v_lower = val.lower()
            if (not url_col_assigned) and ("http://" in v_lower or "https://" in v_lower):
                synthetic_headers.append("url")
                url_col_assigned = True
            elif v_lower in ("online", "offline", "status"):
                synthetic_headers.append("status")
            elif idx == 0:
                synthetic_headers.append("date")
            elif idx == 1:
                synthetic_headers.append("date")
            else:
                synthetic_headers.append(f"col_{idx}")

        logger.info(
            "[DIAGNOSTIC] Synthetic headers for headerless feed: %s",
            synthetic_headers,
        )

        stream.seek(0)
        reader = csv.DictReader(stream, fieldnames=synthetic_headers)
        url_col = "url"
        status_col = "status" if "status" in synthetic_headers else None

    parsed_rows = 0
    yielded = 0
    skipped = 0

    try:
        for row_idx, row in enumerate(reader, start=2):
            parsed_rows += 1
            try:
                raw_url = str(row.get(url_col) or "").strip()

                if not raw_url:
                    skipped += 1
                    logger.debug(
                        "Skipping row %d: empty URL value (col=%s)",
                        row_idx,
                        url_col,
                    )
                    continue

                domain = normalize_domain(raw_url)

                if not domain:
                    skipped += 1
                    logger.debug(
                        "Skipping row %d: domain normalization failed for %r",
                        row_idx,
                        raw_url,
                    )
                    continue

                status = ""
                if status_col and status_col in row:
                    status = str(row.get(status_col) or "").strip()

                yielded += 1
                yield domain, status

            except Exception as exc:
                skipped += 1
                logger.warning("Skipping malformed row %d: %s", row_idx, exc)
                logger.debug("Exception details: %s", traceback.format_exc())

    finally:
        logger.info(
            "[DIAGNOSTIC] Parsing summary: parsed_rows=%d yielded_domains=%d skipped_rows=%d header_detected=%s",
            parsed_rows,
            yielded,
            skipped,
            header_detected,
        )

    if yielded == 0:
        raise MaliciousDBValidationError(
            f"Feed parsed but produced zero valid domains (parsed={parsed_rows}, skipped={skipped}, format={fmt})."
        )


def validate_download_hash(expected_hash: str = None) -> bool:
    return True