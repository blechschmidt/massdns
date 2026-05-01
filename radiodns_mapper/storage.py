"""SQLite/MySQL storage layer with idempotent inserts."""
from __future__ import annotations

import contextlib
import sqlite3
from typing import Iterable, Iterator, Optional

from .db_compat import connect as _db_connect
from .models import (
    Bearer,
    CandidateDomain,
    CnameHit,
    MediaItem,
    SiDocument,
    SrvRecord,
    Station,
)

# Schema is written in sqlite3 dialect; db_compat translates it for MySQL
# (INSERT OR IGNORE -> INSERT IGNORE, AUTOINCREMENT -> AUTO_INCREMENT,
# datetime('now') -> CURRENT_TIMESTAMP, etc). All columns that participate
# in PRIMARY KEY or UNIQUE constraints use VARCHAR(N) so MySQL accepts
# them as keys; SQLite treats VARCHAR as TEXT.
SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_domains (
    domain     VARCHAR(255) PRIMARY KEY,
    freq       INTEGER,
    pi         VARCHAR(8),
    ecc        VARCHAR(4),
    gcc        VARCHAR(8),
    source     VARCHAR(32),
    created_at VARCHAR(32) DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cname_hits (
    queried_domain   VARCHAR(255) PRIMARY KEY,
    broadcaster_fqdn VARCHAR(255) NOT NULL,
    resolver         VARCHAR(64),
    raw_json         TEXT,
    created_at       VARCHAR(32) DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cname_hits_broadcaster
    ON cname_hits (broadcaster_fqdn);

CREATE TABLE IF NOT EXISTS srv_records (
    service_domain VARCHAR(255) NOT NULL,
    service_type   VARCHAR(64) NOT NULL,
    priority       INTEGER,
    weight         INTEGER,
    port           INTEGER NOT NULL,
    target         VARCHAR(255) NOT NULL,
    raw_json       TEXT,
    created_at     VARCHAR(32) DEFAULT (datetime('now')),
    PRIMARY KEY (service_domain, target, port)
);
CREATE INDEX IF NOT EXISTS idx_srv_target ON srv_records (target);
CREATE INDEX IF NOT EXISTS idx_srv_type   ON srv_records (service_type);

CREATE TABLE IF NOT EXISTS si_documents (
    target      VARCHAR(255) PRIMARY KEY,
    url         VARCHAR(512),
    status_code INTEGER,
    filepath    VARCHAR(512),
    sha256      VARCHAR(64),
    fetched_at  VARCHAR(32) DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS stations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    source_target      VARCHAR(255) NOT NULL,
    short_name         VARCHAR(128),
    medium_name        VARCHAR(128),
    long_name          VARCHAR(255),
    radiodns_fqdn      VARCHAR(255),
    service_identifier VARCHAR(128),
    raw_xml_fragment   TEXT,
    UNIQUE (source_target, service_identifier, radiodns_fqdn)
);
CREATE INDEX IF NOT EXISTS idx_stations_target ON stations (source_target);

CREATE TABLE IF NOT EXISTS bearers (
    station_id INTEGER NOT NULL,
    bearer_id  VARCHAR(255) NOT NULL,
    cost       INTEGER,
    mime       VARCHAR(64),
    `offset`   INTEGER,
    UNIQUE (station_id, bearer_id)
);

CREATE TABLE IF NOT EXISTS media (
    station_id INTEGER NOT NULL,
    url        VARCHAR(512) NOT NULL,
    width      INTEGER,
    height     INTEGER,
    mime_value VARCHAR(64),
    UNIQUE (station_id, url, width, height)
);
"""


@contextlib.contextmanager
def connect(path: str) -> Iterator[sqlite3.Connection]:
    """Open a connection. Accepts a sqlite path or a mysql:// URL.
    Returns a sqlite3-compatible Connection-like object."""
    with _db_connect(path) as conn:
        yield conn


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
            "INSERT OR IGNORE INTO bearers (station_id, bearer_id, cost, mime, `offset`) "
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
                "SELECT bearer_id, cost, mime, `offset` FROM bearers WHERE station_id=?",
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
