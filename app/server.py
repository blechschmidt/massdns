import os
import shlex
import signal
import subprocess
import sys
import tempfile
import traceback

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

# Make the radiodns_mapper package importable when this app is run from /app
# in the container (where the package lives at /app/radiodns_mapper) or from
# the repo root in development.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.dirname(_HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

app = Flask(__name__, template_folder="templates", static_folder="static")

MASSDNS_BIN = os.environ.get("MASSDNS_BIN", "/massdns/bin/massdns")
RESOLVERS = os.environ.get("RESOLVERS", "/massdns/lists/resolvers.txt")
MAX_DOMAINS = int(os.environ.get("MAX_DOMAINS", "10000"))
RADIODNS_WORK = os.environ.get("RADIODNS_WORK", "/tmp/radiodns")
# DATABASE_URL takes precedence over RADIODNS_DB so the DO-injected
# managed-MySQL DSN works automatically. Falls back to a local SQLite
# file at RADIODNS_DB (default /tmp/radiodns/radiodns.sqlite).
RADIODNS_DB = os.environ.get("DATABASE_URL") \
    or os.environ.get("RADIODNS_DB") \
    or os.path.join(RADIODNS_WORK, "radiodns.sqlite")
ALLOWED_TYPES = {
    "A", "AAAA", "ANY", "CNAME", "DNSKEY", "DS", "MX", "NS",
    "NSEC", "PTR", "RRSIG", "SOA", "TXT", "CAA", "TLSA", "SRV",
}

app.config.update(
    MASSDNS_BIN=MASSDNS_BIN,
    RESOLVERS=RESOLVERS,
    RADIODNS_WORK=RADIODNS_WORK,
    RADIODNS_DB=RADIODNS_DB,
)

# Register the radiodns pipeline blueprint, but never let an import error in
# that subsystem prevent the basic resolver UI from booting. The traceback is
# sent to stderr so DigitalOcean / gunicorn captures it.
RDNS_IMPORT_ERROR = None
try:
    try:
        os.makedirs(RADIODNS_WORK, exist_ok=True)
    except OSError as _e:
        print(f"[startup] WARNING: cannot create RADIODNS_WORK={RADIODNS_WORK}: {_e}",
              file=sys.stderr, flush=True)
    from rdns_routes import bp as rdns_bp, seed_db_if_empty  # noqa: E402
    app.register_blueprint(rdns_bp)

    # ZTR Broadcast Identity Registry blueprint (non-fatal if import fails)
    try:
        from registry_routes import bp as registry_bp  # noqa: E402
        app.register_blueprint(registry_bp)
        print("[startup] registry blueprint registered", file=sys.stderr, flush=True)
    except Exception as _re:
        print(f"[startup] WARNING: registry blueprint failed to load: {_re}",
              file=sys.stderr, flush=True)
    print(f"[startup] radiodns blueprint registered (db={RADIODNS_DB})",
          file=sys.stderr, flush=True)
    # Seed the SQLite DB with example stations on first boot so the
    # Database tab and pipeline have something to operate on out of the
    # box. Idempotent — skipped if candidate_domains already has rows.
    try:
        with app.app_context():
            _seed_summary = seed_db_if_empty(RADIODNS_DB)
        print(f"[startup] db seed: {_seed_summary}", file=sys.stderr, flush=True)
    except Exception as _se:
        print(f"[startup] db seed failed (non-fatal): {_se}",
              file=sys.stderr, flush=True)
except Exception as _e:
    RDNS_IMPORT_ERROR = "".join(traceback.format_exception(type(_e), _e, _e.__traceback__))
    print("[startup] FAILED to load radiodns blueprint:", file=sys.stderr, flush=True)
    print(RDNS_IMPORT_ERROR, file=sys.stderr, flush=True)

    # Return 200 (not 5xx) so DO App Platform's edge doesn't substitute a
    # generic 'upstream broken' page. We surface the full traceback in the
    # response body so the failure is debuggable from the browser even
    # when runtime logs aren't available.
    @app.get("/rdns/info")
    def _rdns_disabled_info():
        return jsonify({
            "service": "radiodns_mapper",
            "status": "disabled",
            "reason": "rdns_routes blueprint failed to import",
            "traceback": RDNS_IMPORT_ERROR,
            "env": {
                "RADIODNS_WORK": RADIODNS_WORK,
                "RADIODNS_DB": RADIODNS_DB,
                "sys_path": sys.path,
                "cwd": os.getcwd(),
                "files_in_cwd": sorted(os.listdir(os.getcwd())),
            },
        })

    @app.get("/rdns/<path:_rest>")
    def _rdns_disabled_catchall(_rest):
        return jsonify({
            "service": "radiodns_mapper",
            "status": "disabled",
            "reason": "rdns_routes blueprint failed to import; see /rdns/info",
        })


@app.get("/__diag")
def diag():
    """Top-level diagnostic — probes each radiodns_mapper import individually
    and reports the result. Always available regardless of blueprint state."""
    probes = [
        "radiodns_mapper",
        "radiodns_mapper.utils",
        "radiodns_mapper.models",
        "radiodns_mapper.generator",
        "radiodns_mapper.storage",
        "radiodns_mapper.parsers",
        "radiodns_mapper.massdns_runner",
        "radiodns_mapper.si_fetcher",
        "rdns_routes",
        "requests",
        "flask",
        "sqlite3",
    ]
    results = []
    for name in probes:
        entry = {"module": name}
        try:
            __import__(name)
            entry["ok"] = True
        except Exception as ex:
            entry["ok"] = False
            entry["error"] = f"{type(ex).__name__}: {ex}"
            entry["traceback"] = "".join(
                traceback.format_exception(type(ex), ex, ex.__traceback__)
            )
        results.append(entry)

    fs = {}
    for p in ("/app", "/app/radiodns_mapper", "/app/radiodns",
              RADIODNS_WORK, "/data", "/tmp"):
        try:
            fs[p] = sorted(os.listdir(p))
        except Exception as ex:
            fs[p] = f"<{type(ex).__name__}: {ex}>"

    return jsonify({
        "python_version": sys.version,
        "platform": sys.platform,
        "cwd": os.getcwd(),
        "sys_path": sys.path,
        "rdns_import_error": RDNS_IMPORT_ERROR,
        "imports": results,
        "filesystem": fs,
        "env": {k: os.environ.get(k) for k in (
            "PORT", "MASSDNS_BIN", "RESOLVERS", "RADIODNS_WORK",
            "RADIODNS_DB", "MAX_DOMAINS", "PATH", "PYTHONPATH",
        )},
    })


@app.get("/")
def index():
    accept = (request.headers.get("Accept") or "").lower()
    wants_json = "application/json" in accept and "text/html" not in accept
    if wants_json:
        return _api_info()

    # Build live status for the homepage panel
    status = _live_status()
    return render_template(
        "index.html",
        max_domains=MAX_DOMAINS,
        allowed_types=sorted(ALLOWED_TYPES),
        status=status,
    )


def _live_status():
    """Collect lightweight platform status for the homepage panel."""
    db_ok = False
    candidate_count = 0
    try:
        # Use the same db_compat layer as rdns_routes so MySQL/PostgreSQL DSNs work.
        from radiodns_mapper.db_compat import connect
        with connect(RADIODNS_DB) as conn:
            row = conn.execute("SELECT COUNT(*) FROM candidate_domains").fetchone()
            candidate_count = row[0] if row else 0
        db_ok = True
    except Exception:
        pass
    return {
        "api": True,
        "massdns": os.path.exists(MASSDNS_BIN),
        "db": db_ok,
        "candidate_count": candidate_count,
        "rdns_namespace": "radiodns.zerotrustradio.org",
        "spi_endpoint": "https://epg.zerotrustradio.org/radiodns/spi/3.1/SI.xml",
    }


@app.get("/api")
def api_info():
    return _api_info()


def _api_info():
    return jsonify({
        "service": "radiodns",
        "endpoints": {
            "GET /": "web UI",
            "GET /api": "this info",
            "GET /health": "liveness (alias)",
            "GET /healthz": "liveness",
            "GET /health": "liveness (Genoa identity-sidecar alias)",
            "POST /resolve": "resolve domains, streams ndjson",
            "POST /v1/identity/resolve": "Genoa identity-resolve adapter (stub)",
            "GET /rdns/info": "radiodns_mapper pipeline endpoints",
        },
        "usage": {
            "content_types": ["application/json", "text/plain"],
            "json_body": {"domains": ["example.com", "..."], "type": "A"},
            "plain_body": "one domain per line; ?type=A query string",
            "max_domains": MAX_DOMAINS,
            "allowed_types": sorted(ALLOWED_TYPES),
        },
    })


@app.get("/healthz")
def healthz():
    if not os.path.exists(MASSDNS_BIN):
        return jsonify({"status": "down", "reason": "massdns binary missing"}), 503
    if not os.path.exists(RESOLVERS):
        return jsonify({"status": "down", "reason": "resolvers file missing"}), 503
    return jsonify({"status": "ok"})


# Genoa-compatible aliases.  Genoa's identity client probes GET /health
# (not /healthz) and POSTs to /v1/identity/resolve.  Both are thin
# adapters over the existing radiodns_mapper pipeline so massdns can
# serve double-duty as the Identity sidecar without forking.
@app.get("/health")
def health():
    return healthz()


@app.post("/v1/identity/resolve")
def v1_identity_resolve():
    """Genoa identity-resolve adapter.

    Body: { call, facility_id, frequency, frequency_unit, gcc, pi }
    Returns: { available, sources: [...], confirmations: [...] }

    Currently a stub that returns "no confirmations yet" so the Genoa
    engine surfaces RADIODNS_VALIDATION_UNAVAILABLE cleanly instead of
    erroring on a 404.  The real RadioDNS resolve will be wired into
    the existing /rdns/scan-cname + /rdns/scan-srv pipeline in a
    follow-up — those routes already do the lookup; we just need to
    project their output into Genoa's { available, sources, confirmations }
    shape.
    """
    payload = request.get_json(silent=True) or {}
    return jsonify({
        "available": False,
        "sources": [
            {
                "kind": "radiodns-cname",
                "status": "unavailable",
                "reason": "v1/identity/resolve adapter is a stub; the real "
                          "lookup wraps /rdns/scan-cname + /rdns/scan-srv and "
                          "is wired in a follow-up.",
            }
        ],
        "confirmations": [],
        "echo": {
            "call": payload.get("call"),
            "facility_id": payload.get("facility_id"),
            "frequency": payload.get("frequency"),
            "frequency_unit": payload.get("frequency_unit"),
            "gcc": payload.get("gcc"),
            "pi": payload.get("pi"),
        },
        "provenance": {
            "sidecar": "chelstein/massdns",
            "module": "app/server.py /v1/identity/resolve",
            "pipeline": "radiodns_mapper (CNAME + SRV)",
        },
    })


# ---------------------------------------------------------------------------
# /routes — debug endpoint listing every registered route
# ---------------------------------------------------------------------------
@app.get("/routes")
def list_routes():
    routes = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        routes.append({
            "path": rule.rule,
            "methods": sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS")),
            "endpoint": rule.endpoint,
        })
    return jsonify(routes)


# ---------------------------------------------------------------------------
# /service/* aliases — work regardless of Node.js radio-service component
# ---------------------------------------------------------------------------
@app.get("/service")
@app.get("/service/")
def service_root():
    return redirect("/rdns/info")


@app.get("/service/info")
def service_info():
    return redirect("/rdns/info")


@app.get("/service/stations")
def service_stations():
    limit = request.args.get("limit", "200")
    return redirect(f"/rdns/db/candidate_domains?limit={limit}")


@app.get("/service/status")
def service_status():
    return redirect("/rdns/db/summary")


@app.post("/service/register")
def service_register():
    return jsonify({
        "error": "not_implemented",
        "message": "Station registration requires the radio-service component. "
                   "Use POST /rdns/generate to seed candidate domains instead.",
        "alternatives": {
            "seed_pipeline": "POST /rdns/generate",
            "info": "GET /rdns/info",
        },
    }), 501


def _parse_domains():
    record_type = "A"
    domains = []
    if request.is_json:
        data = request.get_json(silent=True) or {}
        domains = data.get("domains") or []
        record_type = (data.get("type") or request.args.get("type") or "A").upper()
    else:
        record_type = (request.args.get("type") or "A").upper()
        body = request.get_data(as_text=True) or ""
        domains = body.splitlines()

    domains = [d.strip() for d in domains if d and d.strip()]
    return domains, record_type


@app.post("/resolve")
def resolve():
    domains, record_type = _parse_domains()

    if not domains:
        return jsonify({"error": "no domains provided"}), 400
    if len(domains) > MAX_DOMAINS:
        return jsonify({
            "error": f"too many domains (max {MAX_DOMAINS})",
            "received": len(domains),
        }), 413
    if record_type not in ALLOWED_TYPES:
        return jsonify({
            "error": f"unsupported record type: {record_type}",
            "allowed": sorted(ALLOWED_TYPES),
        }), 400

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="massdns-", delete=False
    )
    try:
        tmp.write("\n".join(domains))
        tmp.write("\n")
        tmp.flush()
        tmp.close()
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise

    cmd = [
        MASSDNS_BIN,
        "-r", RESOLVERS,
        "-t", record_type,
        "-o", "Je",
        "--root",
        "-q",
        tmp.name,
    ]

    def generate():
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=1,
            preexec_fn=os.setsid,
        )
        try:
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, b""):
                yield line
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
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    headers = {
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
        "X-Massdns-Cmd": shlex.join(cmd),
    }
    return Response(generate(), mimetype="application/x-ndjson", headers=headers)


def _log_routes():
    print("[startup] registered routes:", file=sys.stderr, flush=True)
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        methods = ",".join(sorted(m for m in rule.methods if m not in ("HEAD", "OPTIONS")))
        print(f"[startup]   {methods:20s}  {rule.rule}", file=sys.stderr, flush=True)


with app.app_context():
    _log_routes()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
