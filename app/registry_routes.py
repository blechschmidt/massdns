"""ZTR Broadcast Identity Registry — Flask Blueprint.

URL prefix: /rdns/registry

Architecture:
  ZTR manages its own broadcast identity namespace (broadcast.zerotrustradio.org,
  *.band.zerotrustradio.org) which is SEPARATE from official RadioDNS bearers.
  Official bearers (*.radiodns.org) are only created when a station supplies
  verified RDS parameters (PI + ECC). Analog AM gets ZTR extended identities only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, jsonify, render_template, request

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fcc_ingest import (
    fetch_fcc_cdbs,
    get_registry_stats,
    ingest_facilities,
    init_registry_schema,
    parse_csv_data,
    provision_identities,
)

try:
    from radiodns_mapper.db_compat import connect as _db_connect
except ImportError:
    import sqlite3
    def _db_connect(dsn: str):  # type: ignore
        return sqlite3.connect(dsn)

bp = Blueprint("registry", __name__, url_prefix="/rdns/registry")

RADIODNS_DB   = os.environ.get("DATABASE_URL") or os.environ.get("RADIODNS_DB") or "/tmp/radiodns/radiodns.sqlite"
ADMIN_KEY     = os.environ.get("ADMIN_KEY", "")
PDNS_ZONE     = os.environ.get("PDNS_ZONE", "radiodns.zerotrustradio.org")


# ── DB helpers ─────────────────────────────────────────────────────────────

def _get_conn():
    conn = _db_connect(RADIODNS_DB)
    init_registry_schema(conn)
    return conn


def _require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        key = (
            request.headers.get("X-Admin-Key")
            or (request.get_json(silent=True) or {}).get("admin_key")
            or request.args.get("admin_key")
            or ""
        )
        if ADMIN_KEY and key != ADMIN_KEY:
            return jsonify({"error": "unauthorized — admin key required"}), 403
        return f(*args, **kwargs)
    return wrapper


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_identity(row, col_names: list[str]) -> dict:
    d = dict(zip(col_names, row))
    # Parse fcc_json blob back to dict for rich fields
    try:
        d["fcc_data"] = json.loads(d.pop("fcc_json") or "{}")
    except Exception:
        d["fcc_data"] = {}
    return d


# ── Registry UI ───────────────────────────────────────────────────────────

@bp.get("/")
def registry_ui():
    return render_template("registry.html", pdns_zone=PDNS_ZONE)


# ── Stats ─────────────────────────────────────────────────────────────────

@bp.get("/api/stats")
def api_stats():
    try:
        with _get_conn() as conn:
            stats = get_registry_stats(conn)
        return jsonify({"ok": True, "stats": stats})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── FCC Ingest ────────────────────────────────────────────────────────────

@bp.post("/api/ingest")
@_require_admin
def api_ingest():
    """Ingest FCC facility data.

    Options (priority order):
      1. Uploaded file (multipart 'file' field or raw body text)
      2. ?source=cdbs — fetch from FCC CDBS URL
      3. ?source=lms  — fetch from FCC LMS URL (same handler)
    """
    source = request.args.get("source", "upload").lower()
    records: list[dict] = []
    fetch_source = ""

    # File upload takes priority
    if "file" in (request.files or {}):
        f = request.files["file"]
        text = f.read().decode("latin-1", errors="replace")
        if "," in text[:200]:
            records = parse_csv_data(text)
            fetch_source = f"upload:{f.filename}:csv"
        else:
            from fcc_ingest import parse_cdbs_dat
            records = parse_cdbs_dat(text)
            fetch_source = f"upload:{f.filename}:dat"
    elif source in ("cdbs", "lms", "fcc"):
        records, fetch_source = fetch_fcc_cdbs(timeout=90)
    else:
        # Try raw body as CSV / DAT
        body = request.get_data(as_text=True)
        if body and len(body) > 20:
            if "," in body[:200]:
                records = parse_csv_data(body)
                fetch_source = "body:csv"
            else:
                from fcc_ingest import parse_cdbs_dat
                records = parse_cdbs_dat(body)
                fetch_source = "body:dat"

    if not records:
        return jsonify({
            "ok": False,
            "error": "No facility records parsed. Use ?source=cdbs to fetch from FCC, "
                     "or upload a facility.dat / facility.csv file.",
            "tip": "FCC CDBS: https://transition.fcc.gov/ftp/Bureaus/MB/Databases/cdbs/facility.zip",
        }), 400

    with _get_conn() as conn:
        ingested = ingest_facilities(conn, records)
        provisioned = provision_identities(conn, pdns_zone=PDNS_ZONE)
        stats = get_registry_stats(conn)

    return jsonify({
        "ok": True,
        "parsed":      len(records),
        "ingested":    ingested,
        "provisioned": provisioned,
        "source":      fetch_source,
        "stats":       stats,
    })


@bp.post("/api/provision")
@_require_admin
def api_provision():
    """(Re-)provision station_identities from already-ingested fcc_facilities."""
    with _get_conn() as conn:
        provisioned = provision_identities(conn, pdns_zone=PDNS_ZONE)
        stats = get_registry_stats(conn)
    return jsonify({"ok": True, "provisioned": provisioned, "stats": stats})


# ── Identity search / list ────────────────────────────────────────────────

@bp.get("/api/search")
def api_search():
    q          = (request.args.get("q") or "").strip()
    band       = (request.args.get("band") or "").upper()
    state      = (request.args.get("state") or "").upper()
    status_flt = (request.args.get("status") or "").lower()
    limit      = min(int(request.args.get("limit", "50")), 200)
    offset     = int(request.args.get("offset", "0"))

    conditions = []
    params: list = []

    if q:
        conditions.append("(si.callsign LIKE ? OR si.city LIKE ? OR si.licensee LIKE ? OR ff.facility_id = ?)")
        pct = f"%{q}%"
        params += [pct, pct, pct, q]
    if band:
        conditions.append("si.band = ?")
        params.append(band)
    if state:
        conditions.append("si.state = ?")
        params.append(state)
    if status_flt:
        conditions.append("si.claim_status = ?")
        params.append(status_flt)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    sql = f"""
        SELECT si.*,
               ff.lat, ff.lon, ff.ingested_at AS fcc_ingested_at
        FROM station_identities si
        LEFT JOIN fcc_facilities ff ON ff.facility_id = si.facility_id
        {where}
        ORDER BY
          CASE si.claim_status
            WHEN 'active'           THEN 0
            WHEN 'verified'         THEN 1
            WHEN 'claim_requested'  THEN 2
            WHEN 'unclaimed'        THEN 3
            ELSE 4
          END,
          si.callsign
        LIMIT ? OFFSET ?
    """
    params += [limit, offset]

    try:
        with _get_conn() as conn:
            cur = conn.execute(sql, params)
            col_names = [d[0] for d in cur.description]
            rows = cur.fetchall()
            total = (conn.execute(
                f"SELECT COUNT(*) FROM station_identities si LEFT JOIN fcc_facilities ff ON ff.facility_id = si.facility_id {where}",
                params[:-2],
            ).fetchone() or (0,))[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    results = []
    for row in rows:
        d = dict(zip(col_names, row))
        try:
            d["fcc_data"] = json.loads(d.pop("fcc_json") or "{}")
        except Exception:
            d.pop("fcc_json", None)
            d["fcc_data"] = {}
        results.append(d)

    return jsonify({"results": results, "total": total, "limit": limit, "offset": offset})


@bp.get("/api/identities")
def api_identities():
    return api_search()


@bp.get("/api/identities/<int:identity_id>")
def api_identity_detail(identity_id: int):
    try:
        with _get_conn() as conn:
            cur = conn.execute(
                "SELECT si.*, ff.lat, ff.lon FROM station_identities si "
                "LEFT JOIN fcc_facilities ff ON ff.facility_id = si.facility_id "
                "WHERE si.id = ?",
                (identity_id,),
            )
            row = cur.fetchone()
            if row is None:
                return jsonify({"error": "identity not found"}), 404
            col_names = [d[0] for d in cur.description]
            d = dict(zip(col_names, row))
            try:
                d["fcc_data"] = json.loads(d.pop("fcc_json") or "{}")
            except Exception:
                d.pop("fcc_json", None)
                d["fcc_data"] = {}

            # Attach claims
            claims_cur = conn.execute(
                "SELECT id, claimant_name, claimant_email, claimant_title, status, created_at, reviewed_at "
                "FROM station_claims WHERE identity_id = ? ORDER BY created_at DESC",
                (identity_id,),
            )
            claim_cols = [dd[0] for dd in claims_cur.description]
            d["claims"] = [dict(zip(claim_cols, c)) for c in claims_cur.fetchall()]

            # Attach records
            rec_cur = conn.execute(
                "SELECT fqdn, record_type, record_value, ttl, namespace, pdns_applied "
                "FROM identity_records WHERE identity_id = ? ORDER BY namespace, fqdn",
                (identity_id,),
            )
            rec_cols = [dd[0] for dd in rec_cur.description]
            d["identity_records"] = [dict(zip(rec_cols, r)) for r in rec_cur.fetchall()]

            # Attach recent events
            ev_cur = conn.execute(
                "SELECT event_type, actor, details, created_at FROM verification_events "
                "WHERE identity_id = ? ORDER BY created_at DESC LIMIT 20",
                (identity_id,),
            )
            ev_cols = [dd[0] for dd in ev_cur.description]
            d["events"] = [dict(zip(ev_cols, e)) for e in ev_cur.fetchall()]

        return jsonify(d)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Claim workflow ────────────────────────────────────────────────────────

@bp.post("/api/identities/<int:identity_id>/claim")
def api_submit_claim(identity_id: int):
    body = request.get_json(silent=True) or {}

    claimant_name  = (body.get("claimant_name") or "").strip()
    claimant_email = (body.get("claimant_email") or "").strip()
    claimant_title = (body.get("claimant_title") or "").strip()
    claim_reason   = (body.get("claim_reason") or "").strip()
    evidence_type  = (body.get("evidence_type") or "").strip()
    evidence_data  = body.get("evidence_data")
    pi_code        = (body.get("pi_code") or "").strip().lower()
    ecc            = (body.get("ecc") or "").strip().lower()
    country_code   = (body.get("country_code") or "").strip().upper()

    if not claimant_name or not claimant_email:
        return jsonify({"error": "claimant_name and claimant_email are required"}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", claimant_email):
        return jsonify({"error": "invalid claimant_email"}), 400

    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT id, callsign, claim_status, facility_id FROM station_identities WHERE id = ?",
                (identity_id,),
            ).fetchone()
            if row is None:
                return jsonify({"error": "identity not found"}), 404
            _, callsign, claim_status, facility_id = row

            if claim_status in ("active", "suspended"):
                return jsonify({
                    "error": f"identity is {claim_status} — contact ops@zerotrustradio.org to dispute"
                }), 409

            # Allow re-claim if previously rejected, otherwise block duplicate
            existing = conn.execute(
                "SELECT id, status FROM station_claims WHERE identity_id = ? AND status = 'pending'",
                (identity_id,),
            ).fetchone()
            if existing:
                return jsonify({
                    "error": "a pending claim already exists for this identity",
                    "claim_id": existing[0],
                }), 409

            now = _now()
            cur = conn.execute("""
                INSERT INTO station_claims
                    (identity_id, facility_id, callsign, claimant_name, claimant_email,
                     claimant_title, claim_reason, evidence_type, evidence_data,
                     pi_code, ecc, country_code, status, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                identity_id, facility_id, callsign, claimant_name, claimant_email,
                claimant_title, claim_reason, evidence_type,
                json.dumps(evidence_data) if evidence_data else None,
                pi_code or None, ecc or None, country_code or None,
                "pending", now,
            ))
            claim_id = cur.lastrowid

            conn.execute(
                "UPDATE station_identities SET claim_status='claim_requested', updated_at=? WHERE id=?",
                (now, identity_id),
            )
            conn.execute("""
                INSERT INTO verification_events (identity_id, claim_id, event_type, actor, details, created_at)
                VALUES (?,?,?,?,?,?)
            """, (identity_id, claim_id, "claim_submitted", claimant_email,
                  json.dumps({"claimant": claimant_name, "email": claimant_email}), now))
            conn.commit()

        return jsonify({
            "ok": True,
            "claim_id": claim_id,
            "identity_id": identity_id,
            "callsign": callsign,
            "status": "pending",
            "message": f"Claim submitted for {callsign}. ZTR ops will review within 48 hours.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.get("/api/claims")
@_require_admin
def api_list_claims():
    status = (request.args.get("status") or "").lower()
    limit  = min(int(request.args.get("limit", "50")), 200)
    offset = int(request.args.get("offset", "0"))
    where  = "WHERE sc.status = ?" if status else ""
    params: list = ([status] if status else []) + [limit, offset]

    try:
        with _get_conn() as conn:
            cur = conn.execute(f"""
                SELECT sc.*, si.callsign, si.band, si.frequency, si.city, si.state
                FROM station_claims sc
                JOIN station_identities si ON si.id = sc.identity_id
                {where}
                ORDER BY sc.created_at DESC
                LIMIT ? OFFSET ?
            """, params)
            col_names = [d[0] for d in cur.description]
            rows = [dict(zip(col_names, r)) for r in cur.fetchall()]
        return jsonify({"results": rows, "limit": limit, "offset": offset})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.post("/api/claims/<int:claim_id>/approve")
@_require_admin
def api_approve_claim(claim_id: int):
    body = request.get_json(silent=True) or {}
    notes = (body.get("notes") or "").strip()
    activate = body.get("activate", True)

    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM station_claims WHERE id = ?", (claim_id,)
            ).fetchone()
            if row is None:
                return jsonify({"error": "claim not found"}), 404
            cur2 = conn.execute("SELECT * FROM station_claims LIMIT 0")
            ccols = [d[0] for d in cur2.description]
            claim = dict(zip(ccols, row))

            now = _now()
            new_status = "active" if activate else "verified"

            conn.execute(
                "UPDATE station_claims SET status='approved', reviewer_notes=?, reviewed_at=? WHERE id=?",
                (notes, now, claim_id),
            )
            conn.execute(
                "UPDATE station_identities SET claim_status=?, claimed_by=?, claimed_at=?, "
                "pi_code=COALESCE(?,pi_code), ecc=COALESCE(?,ecc), "
                "country_code=COALESCE(?,country_code), "
                "activated_at=?, updated_at=? WHERE id=?",
                (
                    new_status,
                    claim["claimant_email"],
                    now,
                    claim.get("pi_code"),
                    claim.get("ecc"),
                    claim.get("country_code"),
                    now if activate else None,
                    now,
                    claim["identity_id"],
                ),
            )
            conn.execute("""
                INSERT INTO verification_events (identity_id, claim_id, event_type, actor, details, created_at)
                VALUES (?,?,?,?,?,?)
            """, (
                claim["identity_id"], claim_id, "claim_approved",
                "admin",
                json.dumps({"new_status": new_status, "notes": notes}),
                now,
            ))
            conn.commit()
        return jsonify({"ok": True, "claim_id": claim_id, "identity_status": new_status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.post("/api/claims/<int:claim_id>/reject")
@_require_admin
def api_reject_claim(claim_id: int):
    body = request.get_json(silent=True) or {}
    notes = (body.get("notes") or "").strip()

    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT identity_id FROM station_claims WHERE id = ?", (claim_id,)
            ).fetchone()
            if row is None:
                return jsonify({"error": "claim not found"}), 404
            identity_id = row[0]
            now = _now()

            conn.execute(
                "UPDATE station_claims SET status='rejected', reviewer_notes=?, reviewed_at=? WHERE id=?",
                (notes, now, claim_id),
            )
            # Only revert to unclaimed if no other pending claims exist
            pending = conn.execute(
                "SELECT COUNT(*) FROM station_claims WHERE identity_id=? AND status='pending'",
                (identity_id,),
            ).fetchone()[0]
            if pending == 0:
                conn.execute(
                    "UPDATE station_identities SET claim_status='unclaimed', updated_at=? WHERE id=?",
                    (now, identity_id),
                )
            conn.execute("""
                INSERT INTO verification_events (identity_id, claim_id, event_type, actor, details, created_at)
                VALUES (?,?,?,?,?,?)
            """, (identity_id, claim_id, "claim_rejected", "admin",
                  json.dumps({"notes": notes}), now))
            conn.commit()
        return jsonify({"ok": True, "claim_id": claim_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Conflicts ─────────────────────────────────────────────────────────────

@bp.get("/api/conflicts")
def api_conflicts():
    """Find identities where multiple claims exist, or same callsign has multiple active identities."""
    try:
        with _get_conn() as conn:
            # Multiple pending claims on same identity
            multi_claims = conn.execute("""
                SELECT si.id, si.callsign, si.band, si.frequency, si.state, si.claim_status,
                       COUNT(sc.id) AS claim_count
                FROM station_identities si
                JOIN station_claims sc ON sc.identity_id = si.id AND sc.status = 'pending'
                GROUP BY si.id
                HAVING COUNT(sc.id) > 1
                ORDER BY claim_count DESC
            """).fetchall()

            # Same callsign, multiple active identities (e.g. different bands)
            dup_callsigns = conn.execute("""
                SELECT callsign, COUNT(*) AS cnt, GROUP_CONCAT(band || '@' || COALESCE(frequency,'?')) AS bands
                FROM station_identities
                WHERE claim_status = 'active'
                GROUP BY callsign
                HAVING COUNT(*) > 1
                ORDER BY cnt DESC
            """).fetchall()

        return jsonify({
            "multi_claim_identities": [
                {"id": r[0], "callsign": r[1], "band": r[2], "frequency": r[3],
                 "state": r[4], "claim_status": r[5], "pending_claims": r[6]}
                for r in multi_claims
            ],
            "duplicate_active_callsigns": [
                {"callsign": r[0], "active_count": r[1], "bands": r[2]}
                for r in dup_callsigns
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── FCC facility lookup (for lookup enrichment) ───────────────────────────

def lookup_fcc_facility(conn, callsign: str) -> dict | None:
    """Look up a facility by callsign. Returns first licensed FM match, then any."""
    callsign = callsign.upper().strip()
    rows = conn.execute("""
        SELECT facility_id, callsign, service, band, frequency,
               city, state, country, licensee, fac_status
        FROM fcc_facilities
        WHERE callsign = ?
        ORDER BY
          CASE WHEN fac_status IN ('Licensed','LICEN') THEN 0 ELSE 1 END,
          CASE band WHEN 'FM' THEN 0 WHEN 'AM' THEN 1 ELSE 2 END
        LIMIT 1
    """, (callsign,)).fetchone()
    if rows:
        return {
            "facility_id": rows[0],
            "callsign":    rows[1],
            "service":     rows[2],
            "band":        rows[3],
            "frequency":   rows[4],
            "city":        rows[5],
            "state":       rows[6],
            "country":     rows[7],
            "licensee":    rows[8],
            "fcc_status":  rows[9],
        }
    return None
