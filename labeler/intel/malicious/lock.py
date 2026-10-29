"""
File Locking Mechanism.

Prevents concurrent database builds/writes.
Mirrors Trusted DB locking strategy.
"""

from __future__ import annotations

import errno
import logging
import os
import platform
import time
from contextlib import contextmanager

logger = logging.getLogger(__name__)

LOCK_FILE_PATH = "./data/malicious.lock"

# Detect platform
_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    import msvcrt
else:
    import fcntl


@contextmanager
def acquire_lock(timeout: float = 60.0):
    """
    Acquires an exclusive file lock with timeout.

    Uses:
    - fcntl on Linux/macOS
    - msvcrt on Windows

    Public API remains unchanged.
    """

    os.makedirs(os.path.dirname(LOCK_FILE_PATH), exist_ok=True)

    fd = os.open(LOCK_FILE_PATH, os.O_CREAT | os.O_RDWR)
    lock_acquired = False

    try:
        start_time = time.time()

        while True:
            try:
                if _IS_WINDOWS:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

                lock_acquired = True
                logger.debug("Acquired lock")
                break

            except (OSError, IOError) as e:
                if (
                    getattr(e, "errno", None) in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK)
                    or _IS_WINDOWS
                ):
                    if time.time() - start_time >= timeout:
                        logger.error("Lock acquisition timed out")
                        raise RuntimeError("Could not acquire database lock")

                    time.sleep(1)
                else:
                    raise

        yield

    finally:
        try:
            if lock_acquired:
                if _IS_WINDOWS:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)

                logger.debug("Released lock")
        finally:
            os.close(fd)