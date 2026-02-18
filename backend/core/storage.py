"""
core/storage.py — Single source of truth for all file I/O.

All JSON reads and writes go through here. Cross-platform threading lock
prevents race conditions under concurrent requests.

Rules:
  - load(path)       → returns dict or list, creates file if missing
  - save(path, data) → writes via temp file + rename for crash safety
"""

import json
import os
import tempfile
import threading
from typing import Union

JsonValue = Union[dict, list]

# Cross-platform in-process lock (replaces fcntl which is Linux-only).
_lock = threading.Lock()


def _ensure_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def load(path: str, default: JsonValue = None) -> JsonValue:
    """
    Read and return parsed JSON from `path`.
    Returns `default` (empty dict) if the file doesn't exist.
    """
    if default is None:
        default = {}

    if not os.path.exists(path):
        return default

    with _lock:
        with open(path, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return default


def save(path: str, data: JsonValue) -> None:
    """
    Write `data` as JSON to `path`.
    Writes to a temp file then renames for crash safety.
    """
    _ensure_dir(path)

    dir_ = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_, suffix=".tmp")

    try:
        with _lock:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_set(path: str) -> set:
    """Convenience: load a JSON array as a Python set."""
    return set(load(path, default=[]))


def save_set(path: str, data: set) -> None:
    """Convenience: save a Python set as a JSON array."""
    save(path, list(data))
