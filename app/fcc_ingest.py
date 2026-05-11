"""FCC facility data ingestion and ZTR Broadcast Identity Registry.

Sources supported (in preference order):
  1. FCC CDBS bulk ZIP (transition.fcc.gov) — pipe-delimited facility.dat
  2. FCC LMS CSV upload — header-based CSV
  3. Radio Browser seed — for dev / when FCC is offline

ZTR namespace strategy (separate from official RadioDNS):
  facility-{facility_id}.broadcast.zerotrustradio.org
  {callsign}-{freq}-{state}.{band}.zerotrustradio.org   (slug)
  {callsign}.svc.radiodns.zerotrustradio.org             (shared with onboarding)

Official RadioDNS bearer (radiodns.org) only generated when station
provides verified RDS parameters (PI + ECC) — never faked for AM.
"""
from __future__ import annotations

import io
import json
import os
import re
import time
import zipfile
from datetime import datetime, timezone
from typing import Any

import requests

# ── FCC data URLs ──────────────────────────────────────────────────────────

CDBS_FACILITY_URL = (
    "https://transition.fcc.gov/ftp/Bureaus/MB/Databases/cdbs/facility.zip"
)
LMS_FACILITY_URL = (
    "https://enterpriseefiling.fcc.gov/dataentry/api/download/dbfile/facility.zip"
)

# ── Band normalisation ────────────────────────────────────────────────────

_FAC_TYPE_TO_BAND: dict[str, str] = {
    "FM":  "FM",
    "FL":  "TRANSLATOR",   # FM translator
    "FX":  "TRANSLATOR",   # FM translator (alt code)
    "FS":  "FM",           # FM satellite (treat as FM)
    "LD":  "LPFM",         # Low Power FM
    "LPF": "LPFM",
    "AM":  "AM",
    "DRM": "AM",
    # HD Radio uses same facility as FM — handled separately
}

_SKIP_SERVICES = {"TV", "DTV", "LP", "LPT", "CA", "CD", "DD", "TS", "TX"}


def normalize_band(fac_type: str) -> str | None:
    ft = (fac_type or "").strip().upper()
    if ft in _SKIP_SERVICES:
        return None
    return _FAC_TYPE_TO_BAND.get(ft, "FM" if ft else None)


def _normalize_callsign(cs: str) -> str:
    return re.sub(r"[^A-Z0-9-]", "", (cs or "").upper().strip())


def _normalize_freq(band: str, raw: str) -> str | None:
    """Return frequency as a clean decimal string, or None."""
    s = re.sub(r"[^\d.]", "", (raw or "").strip())
    if not s:
        return None
    try:
        f = float(s)
        if band in ("FM", "TRANSLATOR", "LPFM"):
            if f < 50:
                return None
            if f > 200:
                f = f / 100.0  # 10kHz units → MHz
            return f"{f:.1f}"
        if band == "AM":
            return str(int(round(f)))
        return s
    except ValueError:
        return None


def _freq_to_5digit(freq_mhz: str) -> str | None:
    try:
        return str(int(round(float(freq_mhz) * 100))).zfill(5)
    except (ValueError, TypeError):
        return None


def _slug(callsign: str, freq: str, state: str) -> str:
    cs  = re.sub(r"[^a-z0-9]", "", (callsign or "").lower())
    fr  = re.sub(r"[^a-z0-9]", "", (freq or "").lower().replace(".", ""))
    st  = re.sub(r"[^a-z]", "", (state or "").lower())
    return f"{cs}-{fr}-{st}" if (cs and fr and st) else cs or "unknown"


def build_ztr_fqdns(
    facility_id: str,
    callsign: str,
    band: str,
    frequency: str | None,
    state: str | None,
    pdns_zone: str = "radiodns.zerotrustradio.org",
) -> dict:
    zone = pdns_zone.strip().rstrip(".")
    broadcast_zone = zone.replace("radiodns.", "broadcast.", 1) if "radiodns." in zone else f"broadcast.{zone}"
    band_zone = (band or "fm").lower()
    slug = _slug(callsign, frequency or "", state or "")
    return {
        "facility_fqdn": f"facility-{facility_id}.{broadcast_zone}",
        "slug_fqdn":     f"{slug}.{band_zone}.{zone}",
        "svc_fqdn":      f"{_normalize_callsign(callsign).lower()}.svc.{zone}",
    }


# ── Database schema ───────────────────────────────────────────────────────

_REGISTRY_SCHEMA = """
CREATE TABLE IF NOT EXISTS fcc_facilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    facility_id TEXT UNIQUE NOT NULL,
    callsign    TEXT,
    service     TEXT,
    band        TEXT,
    frequency   TEXT,
    city        TEXT,
    state       TEXT,
    country     TEXT DEFAULT 'US',
    licensee    TEXT,
    fac_status  TEXT,
    lat         REAL,
    lon         REAL,
    raw_json    TEXT,
    ingested_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS station_identities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    facility_id     TEXT UNIQUE,
    callsign        TEXT NOT NULL,
    band            TEXT NOT NULL,
    frequency       TEXT,
    city            TEXT,
    state           TEXT,
    licensee        TEXT,
    fcc_status      TEXT,
    facility_fqdn   TEXT,
    slug_fqdn       TEXT,
    svc_fqdn        TEXT,
    radiodns_bearer TEXT,
    claim_status    TEXT NOT NULL DEFAULT 'unclaimed',
    claimed_by      TEXT,
    claimed_at      TEXT,
    activated_at    TEXT,
    pi_code         TEXT,
    ecc             TEXT,
    country_code    TEXT,
    fcc_json        TEXT,
    source          TEXT DEFAULT 'fcc',
    created_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS station_claims (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id      INTEGER NOT NULL,
    facility_id      TEXT,
    callsign         TEXT,
    claimant_name    TEXT NOT NULL,
    claimant_email   TEXT NOT NULL,
    claimant_title   TEXT,
    claim_reason     TEXT,
    evidence_type    TEXT,
    evidence_data    TEXT,
    pi_code          TEXT,
    ecc              TEXT,
    country_code     TEXT,
    status           TEXT NOT NULL DEFAULT 'pending',
    reviewer_notes   TEXT,
    created_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    reviewed_at      TEXT
);

CREATE TABLE IF NOT EXISTS identity_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id  INTEGER NOT NULL,
    fqdn         TEXT NOT NULL,
    record_type  TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl          INTEGER DEFAULT 300,
    namespace    TEXT,
    pdns_applied INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS verification_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER,
    claim_id    INTEGER,
    event_type  TEXT NOT NULL,
    actor       TEXT,
    details     TEXT,
    created_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_fcc_callsign  ON fcc_facilities(callsign);
CREATE INDEX IF NOT EXISTS idx_fcc_state     ON fcc_facilities(state);
CREATE INDEX IF NOT EXISTS idx_fcc_band      ON fcc_facilities(band);
CREATE INDEX IF NOT EXISTS idx_si_callsign   ON station_identities(callsign);
CREATE INDEX IF NOT EXISTS idx_si_status     ON station_identities(claim_status);
CREATE INDEX IF NOT EXISTS idx_si_band       ON station_identities(band);
CREATE INDEX IF NOT EXISTS idx_claims_iid    ON station_claims(identity_id);
CREATE INDEX IF NOT EXISTS idx_irec_iid      ON identity_records(identity_id);
"""


def init_registry_schema(conn) -> None:
    for stmt in _REGISTRY_SCHEMA.strip().split(";"):
        s = stmt.strip()
        if s:
            conn.execute(s)
    conn.commit()


# ── FCC CDBS parser ───────────────────────────────────────────────────────

# CDBS facility.dat pipe-delimited column positions (0-indexed)
_CDBS_COLS = {
    "comm_city":    0,
    "comm_state":   1,
    "facility_id":  2,
    "callsign":     3,
    "fac_type":     5,
    "country":      6,
    "fac_status":   10,
    "fac_frequency": 12,
    "licensee":     25,
    "owner_name":   30,
    "lat_deg":      None,   # varies; parsed from lat/lon fields if present
    "lon_deg":      None,
}


def parse_cdbs_dat(text: str) -> list[dict]:
    """Parse FCC CDBS facility.dat (pipe-delimited)."""
    records = []
    for line in text.splitlines():
        line = line.rstrip("|").strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 13:
            continue

        def col(i: int, default: str = "") -> str:
            try:
                return parts[i].strip()
            except IndexError:
                return default

        fac_type = col(5)
        band = normalize_band(fac_type)
        if band is None:
            continue  # skip TV/LPT etc.

        facility_id = col(2)
        if not facility_id or not facility_id.isdigit():
            continue

        callsign = _normalize_callsign(col(3))
        frequency_raw = col(12)
        freq = _normalize_freq(band, frequency_raw)

        # Try lat/lon (positions vary; attempt 16-23 range)
        lat, lon = None, None
        if len(parts) > 23:
            try:
                ld, lm, ls, ldir = col(16), col(17), col(18), col(19)
                la, lm2, ls2, lndir = col(20), col(21), col(22), col(23)
                if ld and lm and ls:
                    lat = int(ld) + int(lm) / 60 + float(ls) / 3600
                    if ldir.upper() == "S":
                        lat = -lat
                if la and lm2 and ls2:
                    lon = int(la) + int(lm2) / 60 + float(ls2) / 3600
                    if lndir.upper() in ("E", ""):
                        lon = -lon  # US conventions
            except (ValueError, IndexError):
                pass

        licensee = col(25) or col(30)

        records.append({
            "facility_id": facility_id,
            "callsign":    callsign,
            "service":     fac_type,
            "band":        band,
            "frequency":   freq,
            "city":        col(0),
            "state":       col(1),
            "country":     col(6) or "US",
            "licensee":    licensee,
            "fac_status":  col(10),
            "lat":         lat,
            "lon":         lon,
        })
    return records


def parse_csv_data(text: str) -> list[dict]:
    """Parse CSV with header row (FCC LMS or custom export)."""
    import csv
    reader = csv.DictReader(io.StringIO(text))

    # Normalise header names to lowercase with underscores
    def norm_key(k: str) -> str:
        return re.sub(r"[^a-z0-9_]", "_", k.lower().strip())

    records = []
    for row in reader:
        row = {norm_key(k): (v or "").strip() for k, v in row.items()}

        # Map common column name variants
        def get(*keys: str) -> str:
            for k in keys:
                if row.get(k):
                    return row[k]
            return ""

        fac_type = get("service", "fac_type", "station_type", "service_type", "type")
        band = normalize_band(fac_type)
        if band is None:
            continue

        facility_id = get("facility_id", "fac_id", "id")
        if not facility_id:
            continue

        callsign = _normalize_callsign(get("callsign", "call_sign", "call"))
        freq_raw  = get("frequency", "fac_frequency", "freq", "freq_mhz", "freq_khz")
        freq = _normalize_freq(band, freq_raw)

        lat_raw = get("latitude", "lat", "fac_lat")
        lon_raw = get("longitude", "lon", "long", "fac_lon")
        lat = float(lat_raw) if lat_raw else None
        lon = float(lon_raw) if lon_raw else None

        records.append({
            "facility_id": facility_id,
            "callsign":    callsign,
            "service":     fac_type,
            "band":        band,
            "frequency":   freq,
            "city":        get("city", "comm_city", "city_of_license"),
            "state":       get("state", "comm_state", "state_code"),
            "country":     get("country", "country_code") or "US",
            "licensee":    get("licensee", "licensee_name", "owner_name", "entity_name"),
            "fac_status":  get("status", "fac_status", "license_status"),
            "lat":         lat,
            "lon":         lon,
        })
    return records


# ── FCC fetch ─────────────────────────────────────────────────────────────

def fetch_fcc_cdbs(timeout: int = 60) -> tuple[list[dict], str]:
    """Try to fetch and parse CDBS facility.zip. Returns (records, source_url)."""
    for url in (CDBS_FACILITY_URL, LMS_FACILITY_URL):
        try:
            r = requests.get(url, timeout=timeout, stream=True)
            if r.status_code != 200:
                continue
            zdata = io.BytesIO(r.content)
            with zipfile.ZipFile(zdata) as zf:
                names = zf.namelist()
                # prefer facility.dat (CDBS) or facility.csv (LMS)
                dat_names = [n for n in names if re.search(r"facility\.(dat|csv|txt)$", n, re.I)]
                if not dat_names:
                    dat_names = names[:1]
                content = zf.read(dat_names[0]).decode("latin-1", errors="replace")
            if "," in content[:500]:
                records = parse_csv_data(content)
            else:
                records = parse_cdbs_dat(content)
            if records:
                return records, url
        except Exception:
            continue
    return [], ""


# ── DB operations ─────────────────────────────────────────────────────────

def ingest_facilities(conn, records: list[dict]) -> int:
    count = 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in records:
        fid = str(r.get("facility_id", "")).strip()
        if not fid:
            continue
        raw = json.dumps({k: v for k, v in r.items() if k not in ("lat", "lon")})
        conn.execute("""
            INSERT INTO fcc_facilities
                (facility_id, callsign, service, band, frequency,
                 city, state, country, licensee, fac_status, lat, lon,
                 raw_json, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(facility_id) DO UPDATE SET
                callsign   = excluded.callsign,
                service    = excluded.service,
                band       = excluded.band,
                frequency  = excluded.frequency,
                city       = excluded.city,
                state      = excluded.state,
                country    = excluded.country,
                licensee   = excluded.licensee,
                fac_status = excluded.fac_status,
                lat        = excluded.lat,
                lon        = excluded.lon,
                raw_json   = excluded.raw_json,
                updated_at = excluded.updated_at
        """, (
            fid,
            r.get("callsign") or "",
            r.get("service") or "",
            r.get("band") or "",
            r.get("frequency"),
            r.get("city") or "",
            r.get("state") or "",
            r.get("country") or "US",
            r.get("licensee") or "",
            r.get("fac_status") or "",
            r.get("lat"),
            r.get("lon"),
            raw,
            now,
        ))
        count += 1
    conn.commit()
    return count


def provision_identities(
    conn,
    pdns_zone: str = "radiodns.zerotrustradio.org",
    facility_ids: list[str] | None = None,
) -> int:
    """Generate station_identities for all fcc_facilities rows that don't have one yet."""
    if facility_ids:
        rows = conn.execute(
            "SELECT * FROM fcc_facilities WHERE facility_id IN ({})".format(
                ",".join("?" * len(facility_ids))
            ),
            facility_ids,
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM fcc_facilities WHERE facility_id NOT IN "
            "(SELECT facility_id FROM station_identities WHERE facility_id IS NOT NULL)"
        ).fetchall()

    col_names = [d[0] for d in conn.execute("SELECT * FROM fcc_facilities LIMIT 0").description or
                  [("id",), ("facility_id",), ("callsign",), ("service",), ("band",),
                   ("frequency",), ("city",), ("state",), ("country",), ("licensee",),
                   ("fac_status",), ("lat",), ("lon",), ("raw_json",), ("ingested_at",), ("updated_at",)]]
    try:
        col_names = [d[0] for d in conn.execute("SELECT * FROM fcc_facilities LIMIT 0").description]
    except Exception:
        col_names = []

    def get_col(row, name: str) -> Any:
        if col_names:
            try:
                return row[col_names.index(name)]
            except (ValueError, IndexError):
                pass
        try:
            return row[name]
        except Exception:
            return None

    count = 0
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for row in rows:
        fid      = str(get_col(row, "facility_id") or "").strip()
        callsign = str(get_col(row, "callsign") or "").strip()
        band     = str(get_col(row, "band") or "").strip()
        freq     = get_col(row, "frequency")
        city     = get_col(row, "city") or ""
        state    = get_col(row, "state") or ""
        licensee = get_col(row, "licensee") or ""
        fac_status = get_col(row, "fac_status") or ""
        raw_json = get_col(row, "raw_json")

        if not fid or not callsign or not band:
            continue

        fqdns = build_ztr_fqdns(fid, callsign, band, freq, state, pdns_zone)

        conn.execute("""
            INSERT INTO station_identities
                (facility_id, callsign, band, frequency, city, state, licensee,
                 fcc_status, facility_fqdn, slug_fqdn, svc_fqdn,
                 claim_status, fcc_json, source, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(facility_id) DO UPDATE SET
                callsign     = excluded.callsign,
                frequency    = excluded.frequency,
                city         = excluded.city,
                state        = excluded.state,
                licensee     = excluded.licensee,
                fcc_status   = excluded.fcc_status,
                facility_fqdn = excluded.facility_fqdn,
                slug_fqdn    = excluded.slug_fqdn,
                svc_fqdn     = excluded.svc_fqdn,
                fcc_json     = excluded.fcc_json,
                updated_at   = excluded.updated_at
        """, (
            fid, callsign, band, freq, city, state, licensee,
            fac_status,
            fqdns["facility_fqdn"],
            fqdns["slug_fqdn"],
            fqdns["svc_fqdn"],
            "unclaimed",
            raw_json,
            "fcc",
            now, now,
        ))
        count += 1
    conn.commit()
    return count


# ── Stats ─────────────────────────────────────────────────────────────────

def get_registry_stats(conn) -> dict:
    def count(sql: str, params=()) -> int:
        try:
            return (conn.execute(sql, params).fetchone() or (0,))[0]
        except Exception:
            return 0

    return {
        "fcc_facilities":   count("SELECT COUNT(*) FROM fcc_facilities"),
        "identities_total": count("SELECT COUNT(*) FROM station_identities"),
        "unclaimed":        count("SELECT COUNT(*) FROM station_identities WHERE claim_status='unclaimed'"),
        "claim_requested":  count("SELECT COUNT(*) FROM station_identities WHERE claim_status='claim_requested'"),
        "verified":         count("SELECT COUNT(*) FROM station_identities WHERE claim_status='verified'"),
        "active":           count("SELECT COUNT(*) FROM station_identities WHERE claim_status='active'"),
        "suspended":        count("SELECT COUNT(*) FROM station_identities WHERE claim_status='suspended'"),
        "bands": {
            "FM":         count("SELECT COUNT(*) FROM station_identities WHERE band='FM'"),
            "AM":         count("SELECT COUNT(*) FROM station_identities WHERE band='AM'"),
            "LPFM":       count("SELECT COUNT(*) FROM station_identities WHERE band='LPFM'"),
            "TRANSLATOR": count("SELECT COUNT(*) FROM station_identities WHERE band='TRANSLATOR'"),
        },
        "open_claims": count("SELECT COUNT(*) FROM station_claims WHERE status='pending'"),
    }
