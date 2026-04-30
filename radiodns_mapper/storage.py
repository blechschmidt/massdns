"""SQLite storage layer with idempotent inserts."""
from __future__ import annotations

import contextlib
import sqlite3
from typing import Iterable, Iterator, Optional

from .models import (
    Bearer,
    CandidateDomain,
    CnameHit,
    MediaItem,
    SiDocument,
    SrvRecord,
    Station,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_domains (
    domain     TEXT PRIMARY KEY,
    freq       INTEGER,
    pi         TEXT,
    ecc        TEXT,
    gcc        TEXT,
    source     TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cname_hits (
    queried_domain   TEXT PRIMARY KEY,
    broadcaster_fqdn TEXT NOT NULL,
    resolver         TEXT,
    raw_json         TEXT,
    created_at       TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cname_hits_broadcaster
    ON cname_hits (broadcaster_fqdn);

CREATE TABLE IF NOT EXISTS srv_records (
    service_domain TEXT NOT NULL,
    service_type   TEXT NOT NULL,
    priority       INTEGER,
    weight         INTEGER,
    port           INTEGER,
    target         TEXT NOT NULL,
    raw_json       TEXT,
    created_at     TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (service_domain, target, port)
);
CREATE INDEX IF NOT EXISTS idx_srv_target ON srv_records (target);
CREATE INDEX IF NOT EXISTS idx_srv_type   ON srv_records (service_type);

CREATE TABLE IF NOT EXISTS si_documents (
    target      TEXT PRIMARY KEY,
    url         TEXT,
    status_code INTEGER,
    filepath    TEXT,
    sha256      TEXT,
    fetched_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS stations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    source_target      TEXT NOT NULL,
    short_name         TEXT,
    medium_name        TEXT,
    long_name          TEXT,
    radiodns_fqdn      TEXT,
    service_identifier TEXT,
    raw_xml_fragment   TEXT,
    UNIQUE (source_target, service_identifier, radiodns_fqdn)
);
CREATE INDEX IF NOT EXISTS idx_stations_target ON stations (source_target);

CREATE TABLE IF NOT EXISTS bearers (
    station_id INTEGER NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
    bearer_id  TEXT NOT NULL,
    cost       INTEGER,
    mime       TEXT,
    offset     INTEGER,
    UNIQUE (station_id, bearer_id)
);

CREATE TABLE IF NOT EXISTS media (
    station_id INTEGER NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    width      INTEGER,
    height     INTEGER,
    mime_value TEXT,
    UNIQUE (station_id, url, width, height)
);
"""


@contextlib.contextmanager
def connect(path: str) -> Iterator[sqlite3.Connection]:
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


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


# --- candidate_domains ----------------------------------------------------
def insert_candidates(conn: sqlite3.Connection, items: Iterable[CandidateDomain]) -> int:
    rows = (
        (c.domain, c.freq, c.pi, c.ecc, c.gcc, c.source)
        for c in items
    )
    cur = conn.executemany(
        "INSERT OR IGNORE INTO candidate_domains "
        "(domain, freq, pi, ecc, gcc, source) VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    return cur.rowcount or 0


# --- cname_hits -----------------------------------------------------------
def insert_cname_hit(conn: sqlite3.Connection, hit: CnameHit) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO cname_hits "
        "(queried_domain, broadcaster_fqdn, resolver, raw_json) "
        "VALUES (?, ?, ?, ?)",
        (hit.queried_domain, hit.broadcaster_fqdn, hit.resolver, hit.raw_json),
    )
    return cur.rowcount > 0


def iter_cname_hits(conn: sqlite3.Connection) -> Iterator[CnameHit]:
    for row in conn.execute(
        "SELECT queried_domain, broadcaster_fqdn, resolver, raw_json FROM cname_hits"
    ):
        yield CnameHit(**dict(row))


def iter_unique_broadcasters(conn: sqlite3.Connection) -> Iterator[str]:
    for row in conn.execute(
        "SELECT DISTINCT broadcaster_fqdn FROM cname_hits ORDER BY broadcaster_fqdn"
    ):
        yield row[0]


# --- srv_records ----------------------------------------------------------
def insert_srv_record(conn: sqlite3.Connection, rec: SrvRecord) -> bool:
    cur = conn.execute(
        "INSERT OR IGNORE INTO srv_records "
        "(service_domain, service_type, priority, weight, port, target, raw_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            rec.service_domain, rec.service_type, rec.priority, rec.weight,
            rec.port, rec.target, rec.raw_json,
        ),
    )
    return cur.rowcount > 0


def iter_radioepg_targets(conn: sqlite3.Connection) -> Iterator[tuple]:
    """Yield distinct (target, port) pairs for the _radioepg._tcp service."""
    for row in conn.execute(
        "SELECT DISTINCT target, port FROM srv_records "
        "WHERE service_type = '_radioepg._tcp' ORDER BY target"
    ):
        yield row[0], row[1]


# --- si_documents ---------------------------------------------------------
def upsert_si_document(conn: sqlite3.Connection, doc: SiDocument) -> None:
    conn.execute(
        "INSERT INTO si_documents (target, url, status_code, filepath, sha256) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(target) DO UPDATE SET "
        "  url=excluded.url, status_code=excluded.status_code, "
        "  filepath=excluded.filepath, sha256=excluded.sha256, "
        "  fetched_at=datetime('now')",
        (doc.target, doc.url, doc.status_code, doc.filepath, doc.sha256),
    )


def iter_si_documents(conn: sqlite3.Connection) -> Iterator[SiDocument]:
    for row in conn.execute(
        "SELECT target, url, status_code, filepath, sha256 FROM si_documents "
        "WHERE filepath IS NOT NULL"
    ):
        yield SiDocument(**dict(row))


# --- stations / bearers / media ------------------------------------------
def insert_station(conn: sqlite3.Connection, st: Station) -> Optional[int]:
    cur = conn.execute(
        "INSERT OR IGNORE INTO stations "
        "(source_target, short_name, medium_name, long_name, "
        " radiodns_fqdn, service_identifier, raw_xml_fragment) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            st.source_target, st.short_name, st.medium_name, st.long_name,
            st.radiodns_fqdn, st.service_identifier, st.raw_xml_fragment,
        ),
    )
    if cur.rowcount > 0:
        sid = cur.lastrowid
    else:
        row = conn.execute(
            "SELECT id FROM stations WHERE source_target=? AND "
            "  IFNULL(service_identifier,'')=IFNULL(?, '') AND "
            "  IFNULL(radiodns_fqdn,'')=IFNULL(?, '')",
            (st.source_target, st.service_identifier, st.radiodns_fqdn),
        ).fetchone()
        sid = row["id"] if row else None
    if sid is None:
        return None

    for b in st.bearers:
        conn.execute(
            "INSERT OR IGNORE INTO bearers (station_id, bearer_id, cost, mime, offset) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, b.bearer_id, b.cost, b.mime, b.offset),
        )
    for m in st.media:
        conn.execute(
            "INSERT OR IGNORE INTO media (station_id, url, width, height, mime_value) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, m.url, m.width, m.height, m.mime_value),
        )
    return sid


def export_stations_jsonl(conn: sqlite3.Connection, output_path: str) -> int:
    import json
    count = 0
    with open(output_path, "w", encoding="utf-8") as out:
        for row in conn.execute("SELECT * FROM stations ORDER BY id"):
            sid = row["id"]
            bearers = [dict(b) for b in conn.execute(
                "SELECT bearer_id, cost, mime, offset FROM bearers WHERE station_id=?",
                (sid,),
            )]
            media = [dict(m) for m in conn.execute(
                "SELECT url, width, height, mime_value FROM media WHERE station_id=?",
                (sid,),
            )]
            obj = {
                "id": sid,
                "source_target": row["source_target"],
                "short_name": row["short_name"],
                "medium_name": row["medium_name"],
                "long_name": row["long_name"],
                "radiodns_fqdn": row["radiodns_fqdn"],
                "service_identifier": row["service_identifier"],
                "bearers": bearers,
                "media": media,
            }
            out.write(json.dumps(obj, ensure_ascii=False) + "\n")
            count += 1
    return count
