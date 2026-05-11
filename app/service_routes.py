"""Flask Blueprint: RadioDNS-as-a-Service.

Stations register their call sign, frequency, PI, and ECC. The service
creates a CNAME record in the PowerDNS zone and optionally SRV records for
_radioepg._tcp and _radiovis._tcp.

Env vars:
  ADMIN_KEY              secret required to register/delete (empty = open)
  RADIODNS_SERVICE_DB    path to SQLite file for registration records
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from flask import Blueprint, current_app, jsonify, render_template, request

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from radiodns_mapper.generator import (
    build_gcc, normalize_ecc, normalize_pi, parse_freq,
)
import pdns

bp = Blueprint("svc", __name__, url_prefix="/service")

ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOST_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def _service_db() -> str:
    v = current_app.config.get("RADIODNS_SERVICE_DB")
    if not v:
        work = current_app.config.get("RADIODNS_WORK", "/tmp/radiodns")
        v = os.path.join(work, "service.sqlite")
    return v


@contextmanager
def _db():
    path = _service_db()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        _init_schema(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            callsign        TEXT    NOT NULL,
            freq_mhz        TEXT    NOT NULL,
            pi              TEXT    NOT NULL,
            ecc             TEXT    NOT NULL,
            gcc             TEXT    NOT NULL,
            freq5           TEXT    NOT NULL,
            radiodns_fqdn   TEXT    NOT NULL UNIQUE,
            cname_target    TEXT    NOT NULL,
            has_srv         INTEGER NOT NULL DEFAULT 0,
            epg_host        TEXT,
            epg_port        INTEGER,
            vis_host        TEXT,
            vis_port        INTEGER,
            contact_email   TEXT,
            notes           TEXT,
            created_at      TEXT    NOT NULL,
            updated_at      TEXT    NOT NULL
        )
    """)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_admin(body: dict) -> Optional[str]:
    if not ADMIN_KEY:
        return None
    key = (body.get("admin_key") or request.headers.get("X-Admin-Key") or "").strip()
    if key != ADMIN_KEY:
        return "invalid admin key"
    return None


def _freq5(freq_raw: str) -> str:
    freq_int = parse_freq(freq_raw)
    return f"{freq_int:05d}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@bp.get("/")
def page():
    return render_template(
        "service.html",
        pdns_zone=pdns.PDNS_ZONE,
        admin_key_required=bool(ADMIN_KEY),
    )


@bp.get("/status")
def status():
    return jsonify(pdns.pdns_status())


@bp.get("/stations")
def list_stations():
    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = max(0, int(request.args.get("offset", 0)))
    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM registrations").fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            "SELECT id, callsign, freq_mhz, pi, ecc, gcc, freq5, "
            "radiodns_fqdn, cname_target, has_srv, epg_host, epg_port, "
            "vis_host, vis_port, contact_email, notes, created_at "
            "FROM registrations ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )]
    return jsonify({"total": total, "limit": limit, "offset": offset, "stations": rows})


@bp.post("/register")
def register():
    body = request.get_json(silent=True) or {}

    err = _check_admin(body)
    if err:
        return jsonify({"error": err}), 403

    callsign = (body.get("callsign") or "").strip()
    if not callsign:
        return jsonify({"error": "callsign is required"}), 400

    freq_raw = (body.get("frequency") or "").strip()
    if not freq_raw:
        return jsonify({"error": "frequency is required"}), 400

    pi_raw = (body.get("pi") or "").strip()
    ecc_raw = (body.get("ecc") or "").strip()
    cname_target = (body.get("cname_target") or "").strip().rstrip(".")
    if not cname_target:
        return jsonify({"error": "cname_target is required"}), 400

    try:
        f5 = _freq5(freq_raw)
        pi = normalize_pi(pi_raw)
        ecc = normalize_ecc(ecc_raw)
        gcc = build_gcc(pi, ecc)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    zone = pdns.PDNS_ZONE
    radiodns_fqdn = f"{f5}.{pi}.{gcc}.fm.{zone}"

    epg_host = (body.get("epg_host") or "").strip().rstrip(".")
    epg_port = body.get("epg_port")
    vis_host = (body.get("vis_host") or "").strip().rstrip(".")
    vis_port = body.get("vis_port")
    has_srv = bool(epg_host and epg_port)

    if epg_host and not _HOST_RE.match(epg_host):
        return jsonify({"error": "invalid epg_host"}), 400
    if vis_host and not _HOST_RE.match(vis_host):
        return jsonify({"error": "invalid vis_host"}), 400

    contact_email = (body.get("contact_email") or "").strip()
    if contact_email and not _EMAIL_RE.match(contact_email):
        return jsonify({"error": "invalid contact_email"}), 400

    notes = (body.get("notes") or "").strip()
    now = _now()

    # Create CNAME record
    created_records = []
    try:
        pdns.upsert_cname(radiodns_fqdn, cname_target)
        created_records.append({
            "type": "CNAME",
            "name": radiodns_fqdn,
            "target": cname_target,
        })
    except Exception as e:
        return jsonify({"error": f"PowerDNS CNAME failed: {e}"}), 502

    # Optionally create SRV records under {callsign}.svc.{zone}
    svc_base = f"{callsign.lower()}.svc.{zone}"
    if has_srv:
        try:
            epg_port_int = int(epg_port)
            epg_name = f"_radioepg._tcp.{svc_base}"
            pdns.upsert_srv(epg_name, 10, 0, epg_port_int, epg_host)
            created_records.append({
                "type": "SRV",
                "name": epg_name,
                "target": f"{epg_host}:{epg_port_int}",
            })
        except Exception as e:
            created_records.append({
                "type": "SRV",
                "name": f"_radioepg._tcp.{svc_base}",
                "error": str(e),
            })

        if vis_host and vis_port:
            try:
                vis_port_int = int(vis_port)
                vis_name = f"_radiovis._tcp.{svc_base}"
                pdns.upsert_srv(vis_name, 10, 0, vis_port_int, vis_host)
                created_records.append({
                    "type": "SRV",
                    "name": vis_name,
                    "target": f"{vis_host}:{vis_port_int}",
                })
            except Exception as e:
                created_records.append({
                    "type": "SRV",
                    "name": f"_radiovis._tcp.{svc_base}",
                    "error": str(e),
                })

    # Persist registration
    with _db() as conn:
        existing = conn.execute(
            "SELECT id FROM registrations WHERE radiodns_fqdn=?",
            (radiodns_fqdn,),
        ).fetchone()
        if existing:
            conn.execute("""
                UPDATE registrations
                SET callsign=?, freq_mhz=?, cname_target=?, has_srv=?,
                    epg_host=?, epg_port=?, vis_host=?, vis_port=?,
                    contact_email=?, notes=?, updated_at=?
                WHERE radiodns_fqdn=?
            """, (
                callsign, freq_raw, cname_target, int(has_srv),
                epg_host or None,
                int(epg_port) if epg_port else None,
                vis_host or None,
                int(vis_port) if vis_port else None,
                contact_email or None, notes or None, now,
                radiodns_fqdn,
            ))
            reg_id = existing["id"]
        else:
            conn.execute("""
                INSERT INTO registrations
                (callsign, freq_mhz, pi, ecc, gcc, freq5, radiodns_fqdn,
                 cname_target, has_srv, epg_host, epg_port, vis_host, vis_port,
                 contact_email, notes, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                callsign, freq_raw, pi, ecc, gcc, f5, radiodns_fqdn,
                cname_target, int(has_srv),
                epg_host or None,
                int(epg_port) if epg_port else None,
                vis_host or None,
                int(vis_port) if vis_port else None,
                contact_email or None, notes or None, now, now,
            ))
            reg_id = conn.execute(
                "SELECT id FROM registrations WHERE radiodns_fqdn=?",
                (radiodns_fqdn,),
            ).fetchone()[0]

    return jsonify({
        "ok": True,
        "id": reg_id,
        "callsign": callsign,
        "radiodns_fqdn": radiodns_fqdn,
        "cname_target": cname_target,
        "has_srv": has_srv,
        "svc_base": svc_base if has_srv else None,
        "dns_records": created_records,
        "freq5": f5,
        "pi": pi,
        "ecc": ecc,
        "gcc": gcc,
        "zone": zone,
    })


@bp.delete("/stations/<int:reg_id>")
def delete_station(reg_id: int):
    body = request.get_json(silent=True) or {}
    err = _check_admin(body)
    if err:
        return jsonify({"error": err}), 403

    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM registrations WHERE id=?", (reg_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404
        row = dict(row)

    warnings = []
    zone = pdns.PDNS_ZONE

    try:
        pdns.delete_rrset(row["radiodns_fqdn"], "CNAME")
    except Exception as e:
        warnings.append(f"CNAME delete: {e}")

    if row.get("has_srv") and row.get("epg_host"):
        svc_base = f"{row['callsign'].lower()}.svc.{zone}"
        for svc_type in ("_radioepg._tcp", "_radiovis._tcp"):
            try:
                pdns.delete_rrset(f"{svc_type}.{svc_base}", "SRV")
            except Exception as e:
                warnings.append(f"{svc_type} SRV delete: {e}")

    with _db() as conn:
        conn.execute("DELETE FROM registrations WHERE id=?", (reg_id,))

    result: dict = {"ok": True, "deleted_id": reg_id, "fqdn": row["radiodns_fqdn"]}
    if warnings:
        result["warnings"] = warnings
    return jsonify(result)


@bp.get("/info")
def info():
    return jsonify({
        "service": "radiodns_service",
        "zone": pdns.PDNS_ZONE,
        "admin_key_required": bool(ADMIN_KEY),
        "endpoints": {
            "GET  /service/":                  "service web UI",
            "GET  /service/status":            "PowerDNS connectivity",
            "GET  /service/stations":          "list registered stations",
            "POST /service/register":          "register a station",
            "DELETE /service/stations/<id>":   "delete a registration",
        },
    })
