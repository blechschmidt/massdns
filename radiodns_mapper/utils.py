"""Shared helpers: logging, normalization, validation, hashing."""
from __future__ import annotations

import hashlib
import logging
import re
import sys
from typing import Optional

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]+$")

log = logging.getLogger("radiodns_mapper")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def normalize_domain(value: str) -> str:
    """Lowercase, strip trailing dot and surrounding whitespace."""
    if value is None:
        return ""
    s = str(value).strip().lower()
    while s.endswith("."):
        s = s[:-1]
    return s


def is_valid_domain(value: str) -> bool:
    s = normalize_domain(value)
    if not s or len(s) > 253:
        return False
    labels = s.split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL_RE.match(lbl) for lbl in labels)


def is_hex(value: str, length: Optional[int] = None) -> bool:
    if not value:
        return False
    s = value.lower()
    if length is not None and len(s) != length:
        return False
    return bool(_HEX_RE.match(s))


def sha256_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def safe_filename(value: str, max_len: int = 200) -> str:
    """Make a string safe to use as a filename component."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    s = s.strip("._") or "x"
    return s[:max_len]


def iter_nonblank_lines(path: str):
    """Yield non-blank, non-comment lines from a file. Use '-' for stdin."""
    if path == "-":
        fh = sys.stdin
        close_after = False
    else:
        fh = open(path, "r", encoding="utf-8", errors="replace")
        close_after = True
    try:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            yield line
    finally:
        if close_after:
            fh.close()
