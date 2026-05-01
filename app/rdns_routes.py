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


bp = Blueprint("rdns", __name__, url_prefix="/rdns")


SRV_DEFAULT_SERVICES = ("_radioepg._tcp", "_radiovis._tcp")
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
    db = _cfg_db()
    os.makedirs(os.path.dirname(os.path.abspath(db)) or ".", exist_ok=True)
    with connect(db) as conn:
        init_schema(conn)


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
            "POST /rdns/expand-hits":          "PI/freq sweep around confirmed hits",
            "GET  /rdns/db/summary":           "row counts per table",
            "GET  /rdns/db/<table>":           "rows from a table",
            "GET  /rdns/db/download":          "download the SQLite database",
            "GET  /rdns/db/export-stations":   "download stations.jsonl",
            "POST /rdns/db/reset":             "delete and re-init the DB",
        },
    })
