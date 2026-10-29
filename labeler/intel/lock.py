import os
import time
from pathlib import Path

from . import config


class UpdateLock:
    def __init__(self) -> None:
        self._fd: int | None = None
        self._lock_path: Path = config.LOCK_PATH

    def __enter__(self):
        while True:
            try:
                self._fd = os.open(
                    self._lock_path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR,
                )
                return self
            except FileExistsError:
                time.sleep(1)

    def __exit__(self, exc_type, exc, tb):
        if self._fd is not None:
            os.close(self._fd)

        try:
            os.remove(self._lock_path)
        except FileNotFoundError:
            pass