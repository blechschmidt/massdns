"""Tiny sqlite3-vs-PyMySQL compatibility layer.

Lets the existing sqlite3-flavoured SQL in ``storage.py`` run unchanged
against either backend. Backend is chosen by URL scheme:

  ``mysql://user:pass@host:port/dbname?...``  -> PyMySQL
  ``mysql+pymysql://...``                     -> PyMySQL (alias)
  anything else (a path)                      -> sqlite3

We translate the few sqlite-isms that don't survive into MySQL:

  ``?``                  -> ``%s``                  (placeholders)
  ``INSERT OR IGNORE``   -> ``INSERT IGNORE``       (idempotent insert)
  ``datetime('now')``    -> ``CURRENT_TIMESTAMP``   (default timestamp)
  ``ON CONFLICT(x) DO UPDATE SET ...``
                          -> ``ON DUPLICATE KEY UPDATE ...``
  ``excluded.col``        -> ``VALUES(col)``
  ``AUTOINCREMENT``       -> ``AUTO_INCREMENT``
  ``TEXT``                -> kept (MySQL has TEXT)
  ``PRAGMA foreign_keys = ON`` / ``journal_mode = WAL`` -> no-op on MySQL

Returned connection wraps both backends behind ``execute``,
``executemany``, ``executescript``, ``commit``, ``rollback``, ``close``,
and a ``row_factory``-like interface so callers can do ``dict(row)``.
"""
from __future__ import annotations

import contextlib
import os
import re
import sqlite3
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import unquote, urlparse


# ---------------------------------------------------------------------------
# Translation
# ---------------------------------------------------------------------------

_RE_DATETIME_NOW = re.compile(r"datetime\(\s*['\"]now['\"]\s*\)", re.IGNORECASE)
_RE_ON_CONFLICT = re.compile(
    r"ON\s+CONFLICT\s*\([^)]*\)\s*DO\s+UPDATE\s+SET",
    re.IGNORECASE,
)
_RE_EXCLUDED = re.compile(r"\bexcluded\.([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
_RE_AUTOINCREMENT = re.compile(r"\bAUTOINCREMENT\b", re.IGNORECASE)
_RE_INSERT_OR_IGNORE = re.compile(r"\bINSERT\s+OR\s+IGNORE\b", re.IGNORECASE)
_RE_INSERT_OR_REPLACE = re.compile(r"\bINSERT\s+OR\s+REPLACE\b", re.IGNORECASE)
_RE_PRAGMA = re.compile(r"^\s*PRAGMA\b", re.IGNORECASE | re.MULTILINE)


def _translate_sql(sql: str) -> str:
    """Translate sqlite3 SQL into MySQL 8-compatible SQL."""
    s = sql
    s = _RE_INSERT_OR_IGNORE.sub("INSERT IGNORE", s)
    s = _RE_INSERT_OR_REPLACE.sub("REPLACE", s)
    s = _RE_DATETIME_NOW.sub("CURRENT_TIMESTAMP", s)
    s = _RE_ON_CONFLICT.sub("ON DUPLICATE KEY UPDATE", s)
    s = _RE_EXCLUDED.sub(r"VALUES(\1)", s)
    s = _RE_AUTOINCREMENT.sub("AUTO_INCREMENT", s)
    # Convert positional ? to %s, leaving %s alone
    out = []
    in_str = False
    quote = ""
    for ch in s:
        if in_str:
            out.append(ch)
            if ch == quote:
                in_str = False
        else:
            if ch in ("'", '"', "`"):
                in_str = True
                quote = ch
                out.append(ch)
            elif ch == "?":
                out.append("%s")
            else:
                out.append(ch)
    return "".join(out)


def _translate_script(sql: str) -> str:
    """Translate a CREATE-tables script, splitting on ; and dropping pragmas
    that don't apply to MySQL."""
    out_stmts = []
    for stmt in sql.split(";"):
        s = stmt.strip()
        if not s:
            continue
        if _RE_PRAGMA.search(s):
            continue
        out_stmts.append(_translate_sql(s))
    return ";\n".join(out_stmts) + ";"


# ---------------------------------------------------------------------------
# Connection wrapper
# ---------------------------------------------------------------------------

class _RowDict:
    """Minimal Row-like object that supports both ``r[0]`` and ``r['col']``
    and ``dict(r)`` so ``[dict(row) for row in conn.execute(...)]`` works."""
    __slots__ = ("_keys", "_values", "_map")

    def __init__(self, keys, values):
        self._keys = tuple(keys)
        self._values = tuple(values)
        self._map = {k: v for k, v in zip(self._keys, self._values)}

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return self._map[key]

    def keys(self):
        return self._keys

    def values(self):
        return self._values

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


class _MySQLCursor:
    """Wraps a PyMySQL cursor so it iterates _RowDict objects and exposes
    .rowcount / .lastrowid like sqlite3."""

    def __init__(self, raw_cursor):
        self._cur = raw_cursor

    def __iter__(self):
        cols = [d[0] for d in (self._cur.description or [])]
        for row in self._cur:
            yield _RowDict(cols, row)

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in (self._cur.description or [])]
        return _RowDict(cols, row)

    def fetchall(self):
        cols = [d[0] for d in (self._cur.description or [])]
        return [_RowDict(cols, r) for r in self._cur.fetchall()]

    @property
    def rowcount(self):
        return self._cur.rowcount

    @property
    def lastrowid(self):
        return self._cur.lastrowid

    def close(self):
        try:
            self._cur.close()
        except Exception:
            pass


class _MySQLConn:
    """Wraps a PyMySQL Connection so it presents the subset of the sqlite3
    API used by storage.py."""

    def __init__(self, raw_conn):
        self._conn = raw_conn
        self.row_factory = None  # accepted but ignored

    def execute(self, sql: str, params: Iterable[Any] = ()):
        sql = _translate_sql(sql)
        cur = self._conn.cursor()
        cur.execute(sql, tuple(params) if params else None)
        return _MySQLCursor(cur)

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]):
        sql = _translate_sql(sql)
        cur = self._conn.cursor()
        rows = [tuple(r) for r in rows]
        if rows:
            cur.executemany(sql, rows)
        return _MySQLCursor(cur)

    def executescript(self, script: str):
        translated = _translate_script(script)
        cur = self._conn.cursor()
        for stmt in translated.split(";"):
            s = stmt.strip()
            if s:
                cur.execute(s)
        cur.close()

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------

def is_mysql_url(url: str) -> bool:
    if not url:
        return False
    s = url.strip().lower()
    return s.startswith("mysql://") or s.startswith("mysql+pymysql://")


@contextlib.contextmanager
def connect(url: str) -> Iterator[Any]:
    """Yield a connection presenting the sqlite3-flavoured API.
    Commits on clean exit, rolls back on exception, always closes."""
    if is_mysql_url(url):
        try:
            import pymysql  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "DATABASE_URL is mysql:// but PyMySQL is not installed; "
                "add 'PyMySQL' to app/requirements.txt"
            ) from e

        u = urlparse(url)
        kwargs = {
            "host": u.hostname,
            "port": u.port or 3306,
            "user": unquote(u.username or ""),
            "password": unquote(u.password or ""),
            "database": (u.path or "/").lstrip("/") or None,
            "autocommit": False,
            "charset": "utf8mb4",
        }
        # Honour ?ssl-mode=REQUIRED (DigitalOcean managed MySQL default).
        # Passing a dict (even empty) makes PyMySQL negotiate TLS using the
        # system CA bundle, which is what DO's managed MySQL expects.
        qs = u.query.lower()
        if "ssl-mode=required" in qs or "ssl=true" in qs or "sslmode=required" in qs:
            kwargs["ssl"] = {}

        raw = pymysql.connect(**{k: v for k, v in kwargs.items() if v is not None})
        wrap = _MySQLConn(raw)
        try:
            yield wrap
            wrap.commit()
        except Exception:
            wrap.rollback()
            raise
        finally:
            wrap.close()
    else:
        # sqlite path — preserves prior behaviour exactly
        path = url
        if path.startswith("sqlite:///"):
            path = path[len("sqlite:///"):]
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def backend_for(url: str) -> str:
    return "mysql" if is_mysql_url(url) else "sqlite"
