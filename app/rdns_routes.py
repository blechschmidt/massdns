"""Flask Blueprint exposing the radiodns_mapper pipeline over HTTP."""
from __future__ import annotations

import csv
import json
import os
import shlex
import signal
import subprocess
import tempfile
from typing import Iterator, Optional

from flask import (Blueprint, Response, current_app, jsonify, request,
                   send_file, stream_with_context)

from radiodns_mapper.generator import (
    DEFAULT_STEP, FREQ_MAX, FREQ_MIN, build_fqdn, iter_candidates,
    iter_expansion, parse_ecc_list, parse_freq,
)
from radiodns_mapper.models import CandidateDomain
from radiodns_mapper.parsers import parse_cname_jsonl, parse_si_xml, parse_srv_jsonl
from radiodns_mapper.si_fetcher import fetch_one
from radiodns_mapper.storage import (
    connect, init_schema, insert_candidates, insert_cname_hit,
    insert_srv_record, insert_station, iter_radioepg_targets,
    iter_unique_broadcasters, upsert_si_document,
)
from radiodns_mapper.utils import normalize_domain


bp = Blueprint("rdns", __name__, url_prefix="/rdns",
               template_folder=os.path.join(os.path.dirname(__file__), "templates"))


import sys as _sys
_sys.path.insert(0, os.path.dirname(__file__))
import pdns as _pdns

SRV_DEFAULT_SERVICES = ("_radioepg._tcp", "_radiovis._tcp")

# ---------------------------------------------------------------------------
# Onboarding schema – additional tables not in storage.py
# ---------------------------------------------------------------------------
_ONBOARD_TABLES = [
    """CREATE TABLE IF NOT EXISTS registered_stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    callsign TEXT NOT NULL,
    band TEXT NOT NULL DEFAULT 'FM',
    frequency TEXT NOT NULL,
    freq5 TEXT,
    pi_code TEXT,
    ecc TEXT,
    gcc TEXT,
    fqdn TEXT,
    svc_fqdn TEXT,
    epg_host TEXT,
    spi_host TEXT,
    website TEXT,
    contact_email TEXT,
    provider_name TEXT,
    pdns_applied INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
)""",
    """CREATE TABLE IF NOT EXISTS radiodns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER NOT NULL REFERENCES registered_stations(id),
    fqdn TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl INTEGER DEFAULT 300,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
)""",
    """CREATE TABLE IF NOT EXISTS dns_change_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    station_id INTEGER,
    action TEXT NOT NULL,
    fqdn TEXT,
    record_type TEXT,
    old_value TEXT,
    new_value TEXT,
    pdns_response TEXT,
    created_at TEXT DEFAULT (datetime('now'))
)""",
]


def _init_onboard_schema(conn) -> None:
    for stmt in _ONBOARD_TABLES:
        conn.execute(stmt)
ALLOWED_TABLES = {
    "candidate_domains", "cname_hits", "srv_records",
    "si_documents", "stations", "bearers", "media",
}


# --- helpers --------------------------------------------------------------

def _cfg_db() -> str:
    return current_app.config["RADIODNS_DB"]


def _cfg_workdir() -> str:
    d = current_app.config["RADIODNS_WORK"]
    os.makedirs(d, exist_ok=True)
    return d


def _cfg_si_dir() -> str:
    d = os.path.join(_cfg_workdir(), "si_xml")
    os.makedirs(d, exist_ok=True)
    return d


def _massdns_bin() -> str:
    return current_app.config["MASSDNS_BIN"]


def _resolvers() -> str:
    return current_app.config["RESOLVERS"]


def _ndjson(line: dict) -> bytes:
    return (json.dumps(line, ensure_ascii=False) + "\n").encode("utf-8")


def _ensure_db():
    """Open the configured DB once to apply the schema. The underlying
    db_compat.connect handles per-backend setup (including makedirs for
    sqlite) so we don't duplicate it here."""
    with connect(_cfg_db()) as conn:
        init_schema(conn)
        _init_onboard_schema(conn)


# --- seed --------------------------------------------------------------

# Bundled example_stations.csv lives next to the radiodns_mapper package.
_SEED_CANDIDATES = [
    # (frequency_str, pi, ecc) — kept inline so the seed works even if the
    # csv file isn't shipped with the image.
    ("95.8", "c479", "e1"),    # Capital-class UK
    ("101.9", "c123", "e1"),
    ("88.7", "c201", "e1"),
    ("98.5", "1234", "d0"),    # Test/Eu fallback
    ("107.5", "f001", "a0"),
    ("104.4", "c479", "e1"),
    ("88.1", "2c08", "a0"),    # KKQA Akutan AK (added in earlier PR)
    ("106.2", "c460", "e1"),   # Heart UK (canonical worked example)
]


def _seed_candidate_rows():
    """Yield CandidateDomain rows from the bundled CSV (if present) plus the
    inline list. Tolerant of malformed csv lines."""
    rows = []
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "radiodns", "example_stations.csv"),
        os.path.join(here, "..", "radiodns", "example_stations.csv"),
        "/app/radiodns/example_stations.csv",
        "/radiodns/example_stations.csv",
    ]
    for csv_path in candidates:
        csv_path = os.path.normpath(csv_path)
        if not os.path.isfile(csv_path):
            continue
        try:
            with open(csv_path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    f = row.get("frequency"); p = row.get("pi"); e = row.get("ecc")
                    if f and p and e:
                        rows.append((f, p, e))
        except Exception:
            continue
        break
    rows.extend(_SEED_CANDIDATES)

    seen = set()
    for f, p, e in rows:
        try:
            freq = parse_freq(f)
            domain = build_fqdn(freq, p, e)
        except Exception:
            continue
        if domain in seen:
            continue
        seen.add(domain)
        yield CandidateDomain(
            domain=domain,
            freq=freq,
            pi=p.strip().lower(),
            ecc=e.strip().lower(),
            gcc=p.strip().lower()[0] + e.strip().lower(),
            source="seed",
        )


def seed_db_if_empty(db_path: str) -> dict:
    """Insert seed candidate FQDNs into candidate_domains if the table is
    empty. Idempotent. Returns a small summary dict."""
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
    summary = {"db": db_path, "seeded": 0, "skipped_existing": False}
    with connect(db_path) as conn:
        init_schema(conn)
        existing = conn.execute(
            "SELECT COUNT(*) FROM candidate_domains"
        ).fetchone()[0]
        if existing > 0:
            summary["skipped_existing"] = True
            summary["existing_rows"] = existing
            return summary
        rows = list(_seed_candidate_rows())
        if rows:
            insert_candidates(conn, rows)
            summary["seeded"] = len(rows)
            summary["sample"] = [r.domain for r in rows[:5]]
    return summary


def _body_json() -> dict:
    if request.is_json:
        return request.get_json(silent=True) or {}
    return {}


# --- generate -------------------------------------------------------------

@bp.post("/generate")
def generate():
    body = _body_json()
    try:
        eccs = parse_ecc_list(body.get("ecc") or "e0,e1,d0,f0,a0,c0")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    pi_start = (body.get("pi_start") or "0000")
    pi_end = (body.get("pi_end") or "ffff")
    freq_start = int(body.get("freq_start") or FREQ_MIN)
    freq_end = int(body.get("freq_end") or FREQ_MAX)
    freq_step = int(body.get("freq_step") or DEFAULT_STEP)
    limit = body.get("limit")
    limit = int(limit) if limit not in (None, "", 0) else None
    if freq_step <= 0:
        return jsonify({"error": "freq_step must be positive"}), 400

    _ensure_db()

    def stream() -> Iterator[bytes]:
        seen: set = set()
        buf: list = []
        count = 0
        try:
            with connect(_cfg_db()) as conn:
                init_schema(conn)
                try:
                    candidates = iter_candidates(
                        freq_start=freq_start, freq_end=freq_end,
                        freq_step=freq_step,
                        pi_start=pi_start, pi_end=pi_end,
                        eccs=eccs, limit=limit,
                    )
                except ValueError as e:
                    yield _ndjson({"event": "error", "message": str(e)})
                    return
                for c in candidates:
                    if c.domain in seen:
                        continue
                    seen.add(c.domain)
                    buf.append(c)
                    count += 1
                    if count <= 200:
                        yield _ndjson({"event": "item", "domain": c.domain})
                    if len(buf) >= 5000:
                        insert_candidates(conn, buf)
                        buf.clear()
                        yield _ndjson({"event": "progress", "stage": "generate", "count": count})
                if buf:
                    insert_candidates(conn, buf)
            yield _ndjson({"event": "done", "stage": "generate", "count": count})
        except Exception as e:  # pragma: no cover
            yield _ndjson({"event": "error", "message": f"{type(e).__name__}: {e}"})

    return Response(stream_with_context(stream()), mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# --- generic massdns streamer --------------------------------------------

def _stream_massdns_scan(record_type: str, domains: list, rate: Optional[int],
                          parse_kind: str) -> Iterator[bytes]:
    """Run massdns -t <record_type>, parse stdout, store rows, stream events."""
    if not domains:
        yield _ndjson({"event": "error", "message": "no input domains"})
        return

    massdns = _massdns_bin()
    if not (os.path.isfile(massdns) and os.access(massdns, os.X_OK)):
        yield _ndjson({"event": "error", "message": f"massdns binary not found: {massdns}"})
        return
    if not os.path.isfile(_resolvers()):
        yield _ndjson({"event": "error", "message": f"resolvers file missing: {_resolvers()}"})
        return

    workdir = _cfg_workdir()
    tmp_in = tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                         prefix=f"{parse_kind}-in-",
                                         dir=workdir, delete=False)
    tmp_out_path = os.path.join(workdir, next(tempfile._get_candidate_names()) + f".{parse_kind}.jsonl")
    try:
        for d in domains:
            tmp_in.write(d.strip() + "\n")
        tmp_in.flush()
        tmp_in.close()
    except Exception as e:
        yield _ndjson({"event": "error", "message": f"input write failed: {e}"})
        try:
            os.unlink(tmp_in.name)
        except OSError:
            pass
        return

    cmd = [
        massdns,
        "-r", _resolvers(),
        "-t", record_type,
        "-o", "Je",
        "--root",
        "-q",
        tmp_in.name,
    ]
    if rate:
        cmd += ["-s", str(int(rate))]

    yield _ndjson({
        "event": "log",
        "message": f"running: {shlex.join(cmd)}",
    })

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        bufsize=1, preexec_fn=os.setsid,
    )

    parsed = 0
    inserted = 0
    out_fh = open(tmp_out_path, "wb")
    try:
        with connect(_cfg_db()) as conn:
            init_schema(conn)
            assert proc.stdout is not None
            for raw in iter(proc.stdout.readline, b""):
                out_fh.write(raw)
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("status") and rec["status"] != "NOERROR":
                    parsed += 1
                    if parsed % 500 == 0:
                        yield _ndjson({"event": "progress", "stage": parse_kind,
                                       "parsed": parsed, "hits": inserted})
                    continue
                if parse_kind == "cname":
                    hit = _extract_cname(rec, line)
                    if hit and insert_cname_hit(conn, hit):
                        inserted += 1
                        yield _ndjson({
                            "event": "item",
                            "kind": "cname",
                            "queried": hit.queried_domain,
                            "broadcaster": hit.broadcaster_fqdn,
                        })
                elif parse_kind == "srv":
                    for srv in _extract_srv(rec, line):
                        if insert_srv_record(conn, srv):
                            inserted += 1
                            yield _ndjson({
                                "event": "item",
                                "kind": "srv",
                                "service_domain": srv.service_domain,
                                "service_type": srv.service_type,
                                "priority": srv.priority,
                                "weight": srv.weight,
                                "port": srv.port,
                                "target": srv.target,
                            })
                parsed += 1
                if parsed % 500 == 0:
                    yield _ndjson({"event": "progress", "stage": parse_kind,
                                   "parsed": parsed, "hits": inserted})
    except GeneratorExit:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        raise
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait()
        out_fh.close()
        try:
            os.unlink(tmp_in.name)
        except OSError:
            pass
        try:
            os.unlink(tmp_out_path)
        except OSError:
            pass

    yield _ndjson({"event": "done", "stage": parse_kind,
                   "parsed": parsed, "hits": inserted})


def _extract_cname(rec, raw_line):
    from radiodns_mapper.models import CnameHit
    from radiodns_mapper.utils import is_valid_domain
    queried = normalize_domain(rec.get("name") or "")
    if not queried:
        return None
    answers = []
    if isinstance(rec.get("data"), dict):
        a = rec["data"].get("answers") or []
        answers.extend(a)
    if isinstance(rec.get("answers"), list):
        answers.extend(rec["answers"])
    resolver = None
    r = rec.get("resolver")
    if isinstance(r, str):
        resolver = r
    elif isinstance(r, dict):
        resolver = r.get("ip") or r.get("address")
    for ans in answers:
        if str(ans.get("type", "")).upper() != "CNAME":
            continue
        target = normalize_domain(ans.get("data") or "")
        if target and is_valid_domain(target):
            return CnameHit(queried_domain=queried, broadcaster_fqdn=target,
                            resolver=resolver, raw_json=raw_line)
    return None


def _extract_srv(rec, raw_line):
    from radiodns_mapper.models import SrvRecord
    service_domain = normalize_domain(rec.get("name") or "")
    if not service_domain:
        return
    service_type = ".".join(service_domain.split(".")[:2])
    answers = []
    if isinstance(rec.get("data"), dict):
        answers.extend(rec["data"].get("answers") or [])
    if isinstance(rec.get("answers"), list):
        answers.extend(rec["answers"])
    for ans in answers:
        if str(ans.get("type", "")).upper() != "SRV":
            continue
        parts = str(ans.get("data") or "").split()
        if len(parts) < 4:
            continue
        try:
            priority = int(parts[0]); weight = int(parts[1]); port = int(parts[2])
        except ValueError:
            continue
        target = normalize_domain(parts[3])
        if not target:
            continue
        yield SrvRecord(
            service_domain=service_domain, service_type=service_type,
            priority=priority, weight=weight, port=port,
            target=target, raw_json=raw_line,
        )


# --- scan-cname / scan-srv ------------------------------------------------

@bp.post("/scan-cname")
def scan_cname():
    body = _body_json()
    rate = body.get("rate")
    domains = body.get("domains")
    _ensure_db()

    if not domains:
        with connect(_cfg_db()) as conn:
            init_schema(conn)
            domains = [r[0] for r in conn.execute(
                "SELECT domain FROM candidate_domains"
            )]

    return Response(stream_with_context(
                        _stream_massdns_scan("CNAME", domains, rate, "cname")),
                    mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@bp.post("/scan-srv")
def scan_srv():
    body = _body_json()
    rate = body.get("rate")
    services = body.get("services") or list(SRV_DEFAULT_SERVICES)
    domains = body.get("targets")
    _ensure_db()

    if not domains:
        with connect(_cfg_db()) as conn:
            init_schema(conn)
            broadcasters = list(iter_unique_broadcasters(conn))
        domains = []
        for host in broadcasters:
            for svc in services:
                domains.append(f"{svc}.{host}")

    return Response(stream_with_context(
                        _stream_massdns_scan("SRV", domains, rate, "srv")),
                    mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# --- extract-broadcasters / generate-srv ---------------------------------

@bp.post("/extract-broadcasters")
def extract_broadcasters():
    _ensure_db()
    with connect(_cfg_db()) as conn:
        init_schema(conn)
        out = list(iter_unique_broadcasters(conn))
    return jsonify({"count": len(out), "broadcasters": out})


@bp.post("/generate-srv")
def generate_srv():
    body = _body_json()
    services = body.get("services") or list(SRV_DEFAULT_SERVICES)
    hosts = body.get("hosts")
    _ensure_db()
    if not hosts:
        with connect(_cfg_db()) as conn:
            init_schema(conn)
            hosts = list(iter_unique_broadcasters(conn))
    targets = []
    seen = set()
    for h in hosts:
        host = normalize_domain(h)
        if not host:
            continue
        for svc in services:
            d = f"{svc}.{host}"
            if d in seen:
                continue
            seen.add(d)
            targets.append(d)
    return jsonify({"count": len(targets), "targets": targets,
                    "services": list(services)})


# --- fetch-si -------------------------------------------------------------

@bp.post("/fetch-si")
def fetch_si():
    body = _body_json()
    timeout = float(body.get("timeout") or 8.0)
    http_only = bool(body.get("http_only", False))
    _ensure_db()

    with connect(_cfg_db()) as conn:
        init_schema(conn)
        targets = list(iter_radioepg_targets(conn))

    si_dir = _cfg_si_dir()

    def stream():
        if not targets:
            yield _ndjson({"event": "error", "message": "no _radioepg._tcp SRV targets in DB; run scan-srv first"})
            return
        ok = bad = 0
        try:
            with connect(_cfg_db()) as conn:
                init_schema(conn)
                yield _ndjson({"event": "log",
                               "message": f"fetching SI.xml for {len(targets)} targets"})
                for target, port in targets:
                    try:
                        doc = fetch_one(target, port, si_dir,
                                        timeout=timeout, try_https=not http_only)
                    except Exception as e:
                        yield _ndjson({"event": "item", "kind": "si", "target": target,
                                       "ok": False, "error": str(e)})
                        bad += 1
                        continue
                    upsert_si_document(conn, doc)
                    if doc.filepath:
                        ok += 1
                        yield _ndjson({
                            "event": "item", "kind": "si", "target": target,
                            "ok": True, "url": doc.url, "status": doc.status_code,
                            "bytes": os.path.getsize(doc.filepath) if doc.filepath else 0,
                            "sha256": (doc.sha256 or "")[:12],
                        })
                    else:
                        bad += 1
                        yield _ndjson({
                            "event": "item", "kind": "si", "target": target,
                            "ok": False, "url": doc.url, "status": doc.status_code,
                        })
            yield _ndjson({"event": "done", "stage": "fetch-si",
                           "ok": ok, "failed": bad})
        except Exception as e:
            yield _ndjson({"event": "error", "message": f"{type(e).__name__}: {e}"})

    return Response(stream_with_context(stream()), mimetype="application/x-ndjson",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# --- parse-si -------------------------------------------------------------

@bp.post("/parse-si")
def cmd_parse_si():
    _ensure_db()
    si_dir = _cfg_si_dir()
    files = []
    for entry in sorted(os.listdir(si_dir)):
        full = os.path.join(si_dir, entry)
        if os.path.isfile(full) and entry.lower().endswith(".xml"):
            files.append(full)
    if not files:
        return jsonify({"error": f"no *.xml files in {si_dir}; run fetch-si first"}), 400

    inserted = 0
    per_file = []
    with connect(_cfg_db()) as conn:
        init_schema(conn)
        for fp in files:
            base = os.path.splitext(os.path.basename(fp))[0]
            stations = parse_si_xml(fp, source_target=base)
            for st in stations:
                if insert_station(conn, st) is not None:
                    inserted += 1
            per_file.append({"file": os.path.basename(fp),
                             "stations": len(stations)})
    return jsonify({"files": per_file, "stations_inserted": inserted,
                    "files_count": len(files)})


# --- expand-hits ----------------------------------------------------------

@bp.post("/expand-hits")
def cmd_expand_hits():
    body = _body_json()
    window = int(body.get("window") or 32)
    freq_window = int(body.get("freq_window") or 0)
    freq_step = int(body.get("freq_step") or DEFAULT_STEP)
    persist = bool(body.get("persist", True))
    _ensure_db()

    with connect(_cfg_db()) as conn:
        init_schema(conn)
        seeds = [row[0] for row in conn.execute(
            "SELECT queried_domain FROM cname_hits"
        )]

    if not seeds:
        return jsonify({"error": "no cname_hits in DB; run scan-cname first"}), 400

    seen = set()
    expanded = []
    cands = []
    for seed in seeds:
        try:
            for cand in iter_expansion(seed, pi_window=window,
                                       freq_window=freq_window,
                                       freq_step=freq_step):
                if cand.domain in seen:
                    continue
                seen.add(cand.domain)
                expanded.append(cand.domain)
                cands.append(cand)
        except ValueError:
            continue

    if persist and cands:
        with connect(_cfg_db()) as conn:
            init_schema(conn)
            insert_candidates(conn, cands)

    return jsonify({"seeds": len(seeds), "count": len(expanded),
                    "domains": expanded[:5000],
                    "truncated": len(expanded) > 5000,
                    "persisted": bool(persist and cands)})


# --- DB inspector ---------------------------------------------------------

@bp.get("/db/<table>")
def db_table(table):
    if table not in ALLOWED_TABLES:
        return jsonify({"error": f"unknown table: {table}",
                        "allowed": sorted(ALLOWED_TABLES)}), 400
    limit = max(1, min(int(request.args.get("limit", 200)), 5000))
    offset = max(0, int(request.args.get("offset", 0)))
    _ensure_db()
    with connect(_cfg_db()) as conn:
        init_schema(conn)
        total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM {table} LIMIT ? OFFSET ?", (limit, offset)
        )]
    return jsonify({"table": table, "total": total,
                    "limit": limit, "offset": offset, "rows": rows})


@bp.get("/db/summary")
def db_summary():
    _ensure_db()
    counts = {}
    with connect(_cfg_db()) as conn:
        init_schema(conn)
        for t in sorted(ALLOWED_TABLES):
            counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    return jsonify({"db": _cfg_db(), "counts": counts})


@bp.get("/db/download")
def db_download():
    _ensure_db()
    return send_file(_cfg_db(), as_attachment=True,
                     download_name="radiodns.sqlite",
                     mimetype="application/x-sqlite3")


@bp.get("/db/export-stations")
def db_export_stations():
    from radiodns_mapper.storage import export_stations_jsonl
    _ensure_db()
    out_path = os.path.join(_cfg_workdir(), "stations.jsonl")
    with connect(_cfg_db()) as conn:
        init_schema(conn)
        n = export_stations_jsonl(conn, out_path)
    if n == 0:
        return jsonify({"error": "no stations to export"}), 404
    return send_file(out_path, as_attachment=True,
                     download_name="stations.jsonl",
                     mimetype="application/x-ndjson")


@bp.post("/db/seed")
def db_seed():
    """Re-run the candidate seed (only adds rows if the table is empty)."""
    summary = seed_db_if_empty(_cfg_db())
    return jsonify(summary)


@bp.post("/db/reset")
def db_reset():
    db = _cfg_db()
    if os.path.exists(db):
        try:
            os.unlink(db)
        except OSError as e:
            return jsonify({"error": str(e)}), 500
    for sfx in ("-wal", "-shm", "-journal"):
        side = db + sfx
        if os.path.exists(side):
            try:
                os.unlink(side)
            except OSError:
                pass
    _ensure_db()
    return jsonify({"ok": True, "db": db})


# ---------------------------------------------------------------------------
# Station Onboarding Endpoints
# ---------------------------------------------------------------------------

_PDNS_ZONE = os.environ.get("PDNS_ZONE", "radiodns.zerotrustradio.org")


def _check_admin(req):
    """Return (ok, response_or_None). If ADMIN_KEY not set, always ok."""
    admin_key = os.environ.get("ADMIN_KEY", "")
    if not admin_key:
        return True, None
    provided = (req.headers.get("X-Admin-Key") or
                (req.get_json(silent=True) or {}).get("admin_key", ""))
    if provided != admin_key:
        return False, (jsonify({"error": "forbidden"}), 403)
    return True, None


def _abs_dot(name: str) -> str:
    """Ensure trailing dot."""
    return name.strip().rstrip(".") + "."


def _validate_zone(fqdn: str, zone: str) -> bool:
    """Return True if fqdn is within the given zone."""
    f = fqdn.rstrip(".").lower()
    z = zone.rstrip(".").lower()
    return f == z or f.endswith("." + z)


# FM band: 87.5–108.0 MHz expressed as 10 kHz units (8750–10800)
_FM_FREQ_MIN = 8750
_FM_FREQ_MAX = 10800
# AM band: 530–1710 kHz
_AM_FREQ_MIN = 530
_AM_FREQ_MAX = 1710

PUBLIC_RADIODNS_SUFFIX = "fm.radiodns.org"


def _parse_freq_for_band(band: str, frequency: str):
    """Parse and range-validate a frequency string for the given band.

    Returns (freq5_str_or_None, freq_int, error_str_or_None).
    freq5 is the 5-digit 10 kHz representation used in FM FQDNs.
    For non-FM bands freq5 is None.
    """
    import re as _re
    band = band.upper()
    raw = str(frequency).strip().lower().replace("mhz", "").replace("khz", "").strip()

    if band == "STREAMING":
        return None, None, None

    if not raw:
        return None, None, f"frequency is required for {band}"

    try:
        if "." in raw:
            val_f = float(raw)
        else:
            val_f = float(raw)
    except ValueError:
        return None, None, f"invalid frequency: {frequency!r}"

    if band == "FM":
        # Accept MHz float (< 200) or already-converted 10 kHz int (>= 200)
        if val_f >= 200:
            freq_10khz = round(val_f)
        else:
            freq_10khz = round(val_f * 100)
        if not (_FM_FREQ_MIN <= freq_10khz <= _FM_FREQ_MAX):
            mhz_lo = _FM_FREQ_MIN / 100
            mhz_hi = _FM_FREQ_MAX / 100
            return None, None, (
                f"FM frequency must be {mhz_lo}–{mhz_hi} MHz "
                f"(got {frequency!r}). Use AM band for AM kHz frequencies."
            )
        return f"{freq_10khz:05d}", freq_10khz, None

    if band == "AM":
        # Accept kHz integer
        if val_f != round(val_f):
            return None, None, "AM frequency must be a whole number of kHz (e.g. 780)"
        freq_khz = round(val_f)
        if not (_AM_FREQ_MIN <= freq_khz <= _AM_FREQ_MAX):
            return None, None, (
                f"AM frequency must be {_AM_FREQ_MIN}–{_AM_FREQ_MAX} kHz "
                f"(got {frequency!r})"
            )
        return None, freq_khz, None

    if band == "HD":
        return None, None, "HD band is not yet implemented; use FM or AM"

    return None, None, f"unsupported band: {band}"


def _check_bearer_dns(bearer_fqdn: str, managed_zone: str) -> dict:
    """Query Cloudflare DNS-over-HTTPS for a CNAME on the public bearer FQDN.

    Returns dict with keys: exists, target, conflict, message.
    """
    import requests as _req
    managed_zone = managed_zone.rstrip(".").lower()
    try:
        r = _req.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": bearer_fqdn, "type": "CNAME"},
            headers={"Accept": "application/dns-json"},
            timeout=6,
        )
        if r.status_code != 200:
            return {"exists": False, "target": None, "conflict": False,
                    "message": f"DoH lookup returned HTTP {r.status_code}"}
        body = r.json()
        answers = body.get("Answer") or []
        cname_answers = [a for a in answers if a.get("type") == 5]  # CNAME type=5
        if not cname_answers:
            return {"exists": False, "target": None, "conflict": False,
                    "message": "available — no public RadioDNS record found"}
        target = cname_answers[0].get("data", "").rstrip(".")
        target_lower = target.lower()
        conflict = not (target_lower == managed_zone or target_lower.endswith("." + managed_zone))
        msg = ("existing RadioDNS record points outside managed zone"
               if conflict else "existing — already points to our managed zone")
        return {"exists": True, "target": target, "conflict": conflict, "message": msg}
    except Exception as e:
        return {"exists": None, "target": None, "conflict": False,
                "message": f"DNS check unavailable: {e}"}


_RADIO_BROWSER_HOST = "de1.api.radio-browser.info"

# Matches FM bearer FQDNs: freq5.pi.gcc.fm.radiodns.org or freq5.pi.gcc.fm.<zone>
import re as _re
_BEARER_FQDN_RE = _re.compile(
    r'^(\d{5})\.([0-9a-f]{4})\.([0-9a-f]{3})\.fm\.',
    _re.IGNORECASE,
)


def _parse_bearer_fqdn(fqdn: str) -> dict | None:
    """Extract freq5, pi, ecc, gcc from a RadioDNS FM bearer FQDN.

    Works with both public (fm.radiodns.org) and managed zone FQDNs.
    Returns None if the FQDN doesn't match the expected format.
    """
    m = _BEARER_FQDN_RE.match(fqdn.strip().lower().rstrip("."))
    if not m:
        return None
    freq5, pi, gcc = m.group(1), m.group(2), m.group(3)
    ecc = gcc[1:]   # gcc = pi[0] + ecc, so ecc = gcc minus first char
    freq_mhz = int(freq5) / 100
    return {
        "freq5": freq5,
        "pi_code": pi,
        "ecc": ecc,
        "gcc": gcc,
        "frequency": f"{freq_mhz:.1f}",
        "band": "FM",
        "bearer_fqdn": fqdn.strip(),
    }


def _lookup_from_db(callsign: str) -> list:
    """Search the local discovery DB for stations matching callsign.

    Searches the `stations` table (short/medium/long name) and joins with
    cname_hits + candidate_domains to recover freq5, pi, ecc. Returns a list
    of candidate dicts in the same shape as _radio_browser_lookup results.
    """
    results = []
    try:
        _ensure_db()
        cs = callsign.strip().upper()
        pattern = f"%{cs}%"
        with connect(_cfg_db()) as conn:
            # First try stations table (populated after parse-si step)
            rows = conn.execute(
                """SELECT s.short_name, s.medium_name, s.long_name,
                          s.radiodns_fqdn, s.service_identifier
                   FROM stations s
                   WHERE UPPER(s.short_name) LIKE ?
                      OR UPPER(s.medium_name) LIKE ?
                      OR UPPER(s.long_name) LIKE ?
                   LIMIT 10""",
                (pattern, pattern, pattern),
            ).fetchall()
            for row in rows:
                row = dict(row)
                entry = {
                    "name": row.get("medium_name") or row.get("short_name") or cs,
                    "callsign": cs,
                    "source": "ztr-db",
                    "service_identifier": row.get("service_identifier") or "",
                }
                # Parse freq/pi/ecc from radiodns_fqdn if available
                fqdn = row.get("radiodns_fqdn") or ""
                parsed = _parse_bearer_fqdn(fqdn) if fqdn else None
                if parsed:
                    entry.update(parsed)
                else:
                    entry.update({"frequency": None, "pi_code": None, "ecc": None, "band": "FM"})
                results.append(entry)

            # Also search cname_hits if no station records
            if not results:
                hits = conn.execute(
                    """SELECT queried_domain, broadcaster_fqdn
                       FROM cname_hits LIMIT 200""",
                ).fetchall()
                for hit in hits:
                    qd = (hit[0] or "").lower()
                    parsed = _parse_bearer_fqdn(qd)
                    if parsed:
                        # cname_hits doesn't have callsign; include as generic discovery hit
                        results.append({
                            "name": qd,
                            "callsign": cs,
                            "broadcaster_fqdn": hit[1] or "",
                            "source": "ztr-cname-scan",
                            **parsed,
                        })
                # Limit generic hits — not a great match without callsign
                results = results[:3]

            # Also try candidate_domains which always has freq/pi/ecc
            if not results:
                cands = conn.execute(
                    "SELECT domain, freq, pi, ecc, gcc FROM candidate_domains LIMIT 5"
                ).fetchall()
                for c in cands:
                    c = dict(c)
                    results.append({
                        "name": c.get("domain", ""),
                        "callsign": cs,
                        "frequency": f"{int(c['freq'])/100:.1f}" if c.get("freq") else None,
                        "freq5": f"{int(c['freq']):05d}" if c.get("freq") else None,
                        "pi_code": c.get("pi"),
                        "ecc": c.get("ecc"),
                        "gcc": c.get("gcc"),
                        "band": "FM",
                        "source": "ztr-candidates",
                    })
    except Exception:
        pass
    return results


def _radio_browser_lookup(callsign: str, band: str = "FM") -> list:
    """Search Radio Browser API by callsign. Returns list of candidate dicts."""
    import requests as _req

    url = f"https://{_RADIO_BROWSER_HOST}/json/stations/search"
    try:
        r = _req.get(url, params={"name": callsign, "limit": 20},
                     headers={"User-Agent": "ZeroTrustRadio/1.0"},
                     timeout=8)
        r.raise_for_status()
        rb_stations = r.json()
    except Exception:
        return []

    cs_upper = callsign.strip().upper()
    results = []
    for s in rb_stations:
        name = (s.get("name") or "").strip()
        if cs_upper not in name.upper():
            continue

        # Try to parse frequency from name like "88.5 KQED" or "KQED 88.5"
        freq_match = _re.search(r'\b(\d{2,3}(?:\.\d{1,2})?)\s*(?:MHz|FM|AM)?\b', name, _re.I)
        frequency = freq_match.group(1) if freq_match else None
        inferred_band = "AM" if "AM" in name.upper() else "FM"

        results.append({
            "name": name,
            "callsign": cs_upper,
            "frequency": frequency,
            "band": inferred_band,
            "homepage": s.get("homepage") or "",
            "favicon": s.get("favicon") or "",
            "countrycode": s.get("countrycode") or "",
            "country": s.get("country") or "",
            "state": s.get("state") or "",
            "tags": s.get("tags") or "",
            "stream_url": s.get("url_resolved") or s.get("url") or "",
            "source": "radio-browser",
        })

    results.sort(key=lambda x: (0 if x["name"].upper().startswith(cs_upper) else 1))
    return results[:5]


@bp.get("/lookup")
def station_lookup():
    """Look up station details by callsign or bearer FQDN.

    Query params:
      callsign  — search by callsign (Radio Browser + ZTR pipeline DB)
      fqdn      — parse a RadioDNS FM bearer FQDN directly (returns freq5/pi/ecc)
      band      — FM (default) or AM

    Returns list of matching station candidates with auto-fillable fields.
    PI code and ECC are included when found in the ZTR discovery DB or
    when parsed directly from a bearer FQDN.
    """
    fqdn = (request.args.get("fqdn") or "").strip()
    if fqdn:
        parsed = _parse_bearer_fqdn(fqdn)
        if not parsed:
            return jsonify({"error": f"could not parse bearer FQDN: {fqdn!r}"}), 400
        return jsonify({"fqdn": fqdn, "results": [{"name": fqdn, "callsign": "", "source": "fqdn-parse", **parsed}]})

    callsign = (request.args.get("callsign") or "").strip()
    band = (request.args.get("band") or "FM").strip().upper()
    if not callsign:
        return jsonify({"error": "callsign or fqdn is required"}), 400
    if len(callsign) > 20:
        return jsonify({"error": "callsign too long"}), 400

    # ZTR pipeline DB first (has PI + ECC when scanned), then Radio Browser
    results = _lookup_from_db(callsign)
    rb_results = _radio_browser_lookup(callsign, band)

    # Merge: enrich DB results with Radio Browser metadata (homepage, favicon, etc.)
    # and append any Radio Browser-only results not already covered
    db_callsigns = {r.get("callsign", "").upper() for r in results}
    for rb in rb_results:
        matched = False
        for db in results:
            if not db.get("homepage") and rb.get("homepage"):
                db["homepage"] = rb["homepage"]
                db["favicon"] = rb.get("favicon", "")
                db["countrycode"] = rb.get("countrycode", "")
                db["country"] = rb.get("country", "")
                db["state"] = rb.get("state", "")
                db["tags"] = rb.get("tags", "")
                db["stream_url"] = rb.get("stream_url", "")
                matched = True
                break
        if not matched:
            results.append(rb)

    return jsonify({"callsign": callsign, "results": results[:8]})


@bp.get("/onboard")
def onboard_ui():
    from flask import render_template
    zone = os.environ.get("PDNS_ZONE", "radiodns.zerotrustradio.org")
    epg = os.environ.get("EPG_HOST", "epg.zerotrustradio.org")
    return render_template(
        "onboard.html",
        pdns_zone=zone,
        epg_default=epg,
        spi_default=os.environ.get("SPI_HOST", epg),
        provider_default=os.environ.get("PROVIDER_NAME", "Zero Trust Radio"),
        website_default=os.environ.get("PROVIDER_WEBSITE", "https://zerotrustradio.org"),
        contact_default=os.environ.get("CONTACT_EMAIL", "ops@zerotrustradio.org"),
    )


@bp.post("/check")
def check_bearer():
    """Check whether a public RadioDNS bearer FQDN already exists in DNS.

    Body: { band, frequency, pi_code, ecc }
    Returns: { bearer_fqdn, exists, target, conflict, message }
    """
    body = request.get_json(silent=True) or {}
    band = (body.get("band") or "FM").strip().upper()
    frequency = (body.get("frequency") or "").strip()
    pi_code = (body.get("pi_code") or "").strip().lower()
    ecc = (body.get("ecc") or "").strip().lower()

    freq5, freq_int, freq_err = _parse_freq_for_band(band, frequency)
    if freq_err:
        return jsonify({"error": freq_err}), 400

    if band != "FM":
        return jsonify({
            "bearer_fqdn": None,
            "exists": False,
            "target": None,
            "conflict": False,
            "message": f"public RadioDNS bearer check only applies to FM (got {band})",
        })

    if not pi_code:
        return jsonify({"error": "pi_code is required for FM bearer check"}), 400
    if not ecc:
        return jsonify({"error": "ecc is required for FM bearer check"}), 400

    try:
        from radiodns_mapper.generator import build_gcc, normalize_pi, normalize_ecc
        pi_norm = normalize_pi(pi_code)
        ecc_norm = normalize_ecc(ecc)
        gcc = build_gcc(pi_norm, ecc_norm)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    bearer_fqdn = f"{freq5}.{pi_norm}.{gcc}.{PUBLIC_RADIODNS_SUFFIX}"
    zone = os.environ.get("PDNS_ZONE", "radiodns.zerotrustradio.org")
    result = _check_bearer_dns(bearer_fqdn, zone)
    return jsonify({"bearer_fqdn": bearer_fqdn, **result})


@bp.post("/stations")
def create_station():
    ok, err = _check_admin(request)
    if not ok:
        return err

    body = request.get_json(silent=True) or {}
    callsign = (body.get("callsign") or "").strip()
    band = (body.get("band") or "FM").strip().upper()
    frequency = (body.get("frequency") or "").strip()

    if not callsign:
        return jsonify({"error": "callsign is required"}), 400
    if band not in ("FM", "AM", "HD", "STREAMING"):
        return jsonify({"error": f"unsupported band: {band}"}), 400

    import re as _re
    callsign_clean = _re.sub(r"[^a-z0-9\-]", "",
                             callsign.lower().replace(" ", "-"))
    if not callsign_clean:
        return jsonify({"error": "callsign produces empty DNS label after cleaning"}), 400

    pi_code = (body.get("pi_code") or "").strip().lower()
    ecc = (body.get("ecc") or "").strip().lower()
    epg_host = (body.get("epg_host") or os.environ.get("EPG_HOST", "epg.zerotrustradio.org")).strip()
    spi_host = (body.get("spi_host") or os.environ.get("SPI_HOST", epg_host)).strip()
    website = (body.get("website") or "").strip()
    contact_email = (body.get("contact_email") or "").strip()
    provider_name = (body.get("provider_name") or "").strip()

    zone = os.environ.get("PDNS_ZONE", "radiodns.zerotrustradio.org")

    # Validate frequency for band
    freq5, freq_int, freq_err = _parse_freq_for_band(band, frequency or "")
    if freq_err:
        return jsonify({"error": freq_err}), 400

    freq5_str = None
    gcc = None
    managed_fqdn = None   # CNAME source in our zone
    bearer_fqdn = None    # public radiodns.org bearer
    svc_fqdn = f"{callsign_clean}.svc.{zone}"
    records = []

    if band == "FM":
        if not pi_code:
            return jsonify({"error": "pi_code is required for FM band"}), 400
        if not ecc:
            return jsonify({"error": "ecc is required for FM band"}), 400
        try:
            from radiodns_mapper.generator import (
                build_gcc, normalize_pi, normalize_ecc,
            )
            pi_norm = normalize_pi(pi_code)
            ecc_norm = normalize_ecc(ecc)
            gcc = build_gcc(pi_norm, ecc_norm)
            freq5_str = freq5
            managed_fqdn = f"{freq5_str}.{pi_norm}.{gcc}.fm.{zone}"
            bearer_fqdn = f"{freq5_str}.{pi_norm}.{gcc}.{PUBLIC_RADIODNS_SUFFIX}"
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        if not _validate_zone(managed_fqdn, zone):
            return jsonify({"error": f"generated FQDN is outside zone {zone}"}), 400

        records.append({
            "fqdn": managed_fqdn,
            "record_type": "CNAME",
            "record_value": _abs_dot(svc_fqdn),
            "ttl": 300,
        })
        records.append({
            "fqdn": f"_radioepg._tcp.{svc_fqdn}",
            "record_type": "SRV",
            "record_value": f"0 100 80 {_abs_dot(epg_host)}",
            "ttl": 300,
        })
        records.append({
            "fqdn": f"_radiospi._tcp.{svc_fqdn}",
            "record_type": "SRV",
            "record_value": f"0 100 80 {_abs_dot(spi_host)}",
            "ttl": 300,
        })
    else:
        # Non-FM: SRV records only under svc_fqdn
        records.append({
            "fqdn": f"_radioepg._tcp.{svc_fqdn}",
            "record_type": "SRV",
            "record_value": f"0 100 80 {_abs_dot(epg_host)}",
            "ttl": 300,
        })
        records.append({
            "fqdn": f"_radiospi._tcp.{svc_fqdn}",
            "record_type": "SRV",
            "record_value": f"0 100 80 {_abs_dot(spi_host)}",
            "ttl": 300,
        })

    _ensure_db()
    with connect(_cfg_db()) as conn:
        cur = conn.execute(
            """INSERT INTO registered_stations
               (callsign, band, frequency, freq5, pi_code, ecc, gcc, fqdn, svc_fqdn,
                epg_host, spi_host, website, contact_email, provider_name)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (callsign, band, frequency, freq5_str, pi_code or None, ecc or None,
             gcc, managed_fqdn, svc_fqdn, epg_host, spi_host, website or None,
             contact_email or None, provider_name or None),
        )
        station_id = cur.lastrowid
        rec_rows = []
        for rec in records:
            rc = conn.execute(
                """INSERT INTO radiodns_records
                   (station_id, fqdn, record_type, record_value, ttl, status)
                   VALUES (?,?,?,?,?,?)""",
                (station_id, rec["fqdn"], rec["record_type"],
                 rec["record_value"], rec["ttl"], "pending"),
            )
            rec["id"] = rc.lastrowid
            rec["station_id"] = station_id
            rec["status"] = "pending"
            rec_rows.append(rec)
        station = dict(conn.execute(
            "SELECT * FROM registered_stations WHERE id=?", (station_id,)
        ).fetchone())

    station["records"] = rec_rows
    station["bearer_fqdn"] = bearer_fqdn
    station["managed_fqdn"] = managed_fqdn
    station["svc_fqdn"] = svc_fqdn
    station["epg_srv_fqdn"] = f"_radioepg._tcp.{svc_fqdn}"
    station["spi_srv_fqdn"] = f"_radiospi._tcp.{svc_fqdn}"
    station["freq5"] = freq5_str
    station["gcc"] = gcc
    return jsonify(station), 201


@bp.get("/stations")
def list_stations():
    _ensure_db()
    with connect(_cfg_db()) as conn:
        rows = conn.execute(
            """SELECT s.*,
                      COUNT(r.id) AS record_count,
                      SUM(CASE WHEN r.status='applied' THEN 1 ELSE 0 END) AS applied_count
               FROM registered_stations s
               LEFT JOIN radiodns_records r ON r.station_id = s.id
               GROUP BY s.id
               ORDER BY s.created_at DESC"""
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.get("/stations/<int:station_id>")
def get_station(station_id):
    _ensure_db()
    with connect(_cfg_db()) as conn:
        row = conn.execute(
            "SELECT * FROM registered_stations WHERE id=?", (station_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "station not found"}), 404
        records = conn.execute(
            "SELECT * FROM radiodns_records WHERE station_id=? ORDER BY id",
            (station_id,)
        ).fetchall()
    station = dict(row)
    station["records"] = [dict(r) for r in records]
    return jsonify(station)


@bp.post("/stations/<int:station_id>/pdns/apply")
def station_pdns_apply(station_id):
    ok, err = _check_admin(request)
    if not ok:
        return err

    _ensure_db()
    with connect(_cfg_db()) as conn:
        station = conn.execute(
            "SELECT * FROM registered_stations WHERE id=?", (station_id,)
        ).fetchone()
        if not station:
            return jsonify({"error": "station not found"}), 404
        records = conn.execute(
            "SELECT * FROM radiodns_records WHERE station_id=? AND status!='deleted'",
            (station_id,)
        ).fetchall()

    results = []
    for rec in records:
        rec = dict(rec)
        try:
            _pdns.upsert_record(
                name=rec["fqdn"],
                rtype=rec["record_type"],
                records=[rec["record_value"]],
                ttl=rec["ttl"],
            )
            status = "applied"
            pdns_resp = "ok"
        except Exception as e:
            status = "error"
            pdns_resp = str(e)

        with connect(_cfg_db()) as conn:
            conn.execute(
                "UPDATE radiodns_records SET status=?, updated_at=datetime('now') WHERE id=?",
                (status, rec["id"]),
            )
            conn.execute(
                """INSERT INTO dns_change_log
                   (station_id, action, fqdn, record_type, new_value, pdns_response)
                   VALUES (?,?,?,?,?,?)""",
                (station_id, "apply", rec["fqdn"], rec["record_type"],
                 rec["record_value"], pdns_resp),
            )
        results.append({
            "record_id": rec["id"],
            "fqdn": rec["fqdn"],
            "record_type": rec["record_type"],
            "status": status,
            "pdns_response": pdns_resp,
        })

    # Mark station as applied if all records succeeded
    all_ok = all(r["status"] == "applied" for r in results)
    if all_ok:
        with connect(_cfg_db()) as conn:
            conn.execute(
                "UPDATE registered_stations SET pdns_applied=1, updated_at=datetime('now') WHERE id=?",
                (station_id,),
            )

    return jsonify({"station_id": station_id, "results": results, "all_applied": all_ok})


@bp.post("/stations/<int:station_id>/pdns/verify")
def station_pdns_verify(station_id):
    _ensure_db()
    with connect(_cfg_db()) as conn:
        station = conn.execute(
            "SELECT * FROM registered_stations WHERE id=?", (station_id,)
        ).fetchone()
        if not station:
            return jsonify({"error": "station not found"}), 404
        records = conn.execute(
            "SELECT * FROM radiodns_records WHERE station_id=? AND status!='deleted'",
            (station_id,)
        ).fetchall()

    try:
        rrsets = _pdns.zone_rrsets()
    except Exception as e:
        return jsonify({"error": f"could not fetch zone rrsets: {e}"}), 502

    # Index rrsets by (name, type)
    rrset_index = {}
    for rs in rrsets:
        key = (rs.get("name", "").rstrip(".").lower(), rs.get("type", "").upper())
        rrset_index[key] = rs

    results = []
    for rec in records:
        rec = dict(rec)
        key = (rec["fqdn"].rstrip(".").lower(), rec["record_type"].upper())
        rs = rrset_index.get(key)
        if rs:
            contents = [r["content"] for r in rs.get("records", [])]
            found = rec["record_value"].rstrip(".") in [c.rstrip(".") for c in contents]
            results.append({
                "record_id": rec["id"],
                "fqdn": rec["fqdn"],
                "record_type": rec["record_type"],
                "expected": rec["record_value"],
                "found_in_pdns": found,
                "pdns_values": contents,
            })
        else:
            results.append({
                "record_id": rec["id"],
                "fqdn": rec["fqdn"],
                "record_type": rec["record_type"],
                "expected": rec["record_value"],
                "found_in_pdns": False,
                "pdns_values": [],
            })

    all_ok = all(r["found_in_pdns"] for r in results)
    return jsonify({"station_id": station_id, "results": results, "all_verified": all_ok})


@bp.delete("/stations/<int:station_id>/records/<int:record_id>")
def delete_station_record(station_id, record_id):
    ok, err = _check_admin(request)
    if not ok:
        return err

    _ensure_db()
    with connect(_cfg_db()) as conn:
        rec = conn.execute(
            "SELECT * FROM radiodns_records WHERE id=? AND station_id=?",
            (record_id, station_id)
        ).fetchone()
        if not rec:
            return jsonify({"error": "record not found"}), 404
        rec = dict(rec)

    pdns_resp = None
    pdns_ok = None
    try:
        _pdns.delete_rrset(rec["fqdn"], rec["record_type"])
        pdns_ok = True
        pdns_resp = "deleted"
    except Exception as e:
        pdns_ok = False
        pdns_resp = str(e)

    with connect(_cfg_db()) as conn:
        conn.execute(
            "UPDATE radiodns_records SET status='deleted', updated_at=datetime('now') WHERE id=?",
            (record_id,),
        )
        conn.execute(
            """INSERT INTO dns_change_log
               (station_id, action, fqdn, record_type, old_value, pdns_response)
               VALUES (?,?,?,?,?,?)""",
            (station_id, "delete", rec["fqdn"], rec["record_type"],
             rec["record_value"], pdns_resp),
        )

    return jsonify({
        "record_id": record_id,
        "station_id": station_id,
        "status": "deleted",
        "pdns_deleted": pdns_ok,
        "pdns_response": pdns_resp,
    })


@bp.get("/stations/<int:station_id>/zonefile")
def station_zonefile(station_id):
    _ensure_db()
    with connect(_cfg_db()) as conn:
        station = conn.execute(
            "SELECT * FROM registered_stations WHERE id=?", (station_id,)
        ).fetchone()
        if not station:
            return jsonify({"error": "station not found"}), 404
        records = conn.execute(
            "SELECT * FROM radiodns_records WHERE station_id=? AND status!='deleted' ORDER BY id",
            (station_id,)
        ).fetchall()

    station = dict(station)
    lines = [
        f"; RadioDNS zonefile snippet for {station['callsign']} ({station['band']})",
        f"; Generated by Zero Trust Radio onboarding · station_id={station_id}",
        f"; Zone: {os.environ.get('PDNS_ZONE', 'radiodns.zerotrustradio.org')}",
        "",
    ]
    for rec in records:
        rec = dict(rec)
        fqdn = _abs_dot(rec["fqdn"])
        ttl = rec["ttl"]
        rtype = rec["record_type"]
        rvalue = rec["record_value"]
        lines.append(f"{fqdn}\t{ttl}\tIN\t{rtype}\t{rvalue}")

    zonefile_text = "\n".join(lines) + "\n"
    return Response(
        zonefile_text,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="station_{station_id}.zone"'
        },
    )


# --- info -----------------------------------------------------------------

@bp.get("/info")
def info():
    return jsonify({
        "service": "radiodns_mapper",
        "db": _cfg_db(),
        "workdir": _cfg_workdir(),
        "si_dir": _cfg_si_dir(),
        "endpoints": {
            "POST /rdns/generate":             "generate FM bearer FQDN candidates",
            "POST /rdns/scan-cname":           "massdns CNAME sweep",
            "POST /rdns/extract-broadcasters": "unique broadcaster FQDNs from cname_hits",
            "POST /rdns/generate-srv":         "make _radioepg/_radiovis lookup names",
            "POST /rdns/scan-srv":             "massdns SRV sweep",
            "POST /rdns/fetch-si":             "fetch SI.xml from radioepg targets",
            "POST /rdns/parse-si":             "parse stored SI.xml into stations",
            "POST /rdns/expand-hits":              "PI/freq sweep around confirmed hits",
            "GET  /rdns/onboard":                  "station onboarding UI",
            "POST /rdns/check":                    "check public RadioDNS bearer DNS (pre-save)",
            "POST /rdns/stations":                 "register a new station",
            "GET  /rdns/stations":                 "list all registered stations",
            "GET  /rdns/stations/<id>":            "get station with records",
            "POST /rdns/stations/<id>/pdns/apply": "apply records to PowerDNS",
            "POST /rdns/stations/<id>/pdns/verify":"verify records in PowerDNS",
            "DELETE /rdns/stations/<id>/records/<rid>": "delete a DNS record",
            "GET  /rdns/stations/<id>/zonefile":   "RFC 1035 zonefile snippet",
            "GET  /rdns/db/summary":           "row counts per table",
            "GET  /rdns/db/<table>":           "rows from a table",
            "GET  /rdns/db/download":          "download the SQLite database",
            "GET  /rdns/db/export-stations":   "download stations.jsonl",
            "POST /rdns/db/reset":             "delete and re-init the DB",
        },
    })
