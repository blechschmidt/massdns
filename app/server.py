import os
import shlex
import signal
import subprocess
import sys
import tempfile
import traceback

from flask import Flask, Response, jsonify, render_template, request

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
RADIODNS_DB = os.environ.get("RADIODNS_DB", os.path.join(RADIODNS_WORK, "radiodns.sqlite"))
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
    from rdns_routes import bp as rdns_bp  # noqa: E402
    app.register_blueprint(rdns_bp)
    print(f"[startup] radiodns blueprint registered (db={RADIODNS_DB})",
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


@app.get("/")
def index():
    accept = (request.headers.get("Accept") or "").lower()
    wants_json = "application/json" in accept and "text/html" not in accept
    if wants_json:
        return _api_info()
    return render_template(
        "index.html",
        max_domains=MAX_DOMAINS,
        allowed_types=sorted(ALLOWED_TYPES),
    )


@app.get("/api")
def api_info():
    return _api_info()


def _api_info():
    return jsonify({
        "service": "radiodns",
        "endpoints": {
            "GET /": "web UI",
            "GET /api": "this info",
            "GET /healthz": "liveness",
            "POST /resolve": "resolve domains, streams ndjson",
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
