# massdns-api

A small HTTP wrapper around `massdns` for deployment on platforms like
DigitalOcean App Platform. It accepts a list of domains over HTTP and
streams ndjson resolution results back to the client.

## Endpoints

- `GET /` — usage information.
- `GET /healthz` — liveness probe (verifies the binary and resolvers file exist).
- `POST /resolve` — resolve domains. Streams `application/x-ndjson` as massdns produces output.

### POST /resolve

JSON:

```bash
curl -N -H 'content-type: application/json' \
  -d '{"domains":["example.com","cloudflare.com"],"type":"A"}' \
  https://your-app.ondigitalocean.app/resolve
```

Plain text (one domain per line):

```bash
printf 'example.com\ncloudflare.com\n' | \
  curl -N --data-binary @- \
    -H 'content-type: text/plain' \
    'https://your-app.ondigitalocean.app/resolve?type=AAAA'
```

Each output line is a JSON record from massdns (`-o J`). The connection
stays open until massdns finishes; `-N` (curl no-buffer) is recommended.

## Configuration (env vars)

| Var | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port |
| `MASSDNS_BIN` | `/massdns/bin/massdns` | Path to the massdns binary |
| `RESOLVERS` | `/massdns/lists/resolvers.txt` | Resolvers file |
| `MAX_DOMAINS` | `10000` | Reject requests larger than this |

## Local development

```bash
docker build -t massdns-api .
docker run --rm -p 8080:8080 massdns-api
```

The original CLI image (entrypoint = the `massdns` binary) is still
available at `Dockerfile.cli`:

```bash
docker build -f Dockerfile.cli -t massdns-cli .
docker run --rm massdns-cli -r lists/resolvers.txt -t A domains.txt
```

## Deploy to DigitalOcean App Platform

The repo ships a `.do/app.yaml` app spec that builds from `Dockerfile`.

1. Edit `.do/app.yaml` if your fork lives at a different `github.repo` or
   `branch` (default: `chelstein/massdns` on `main`).
2. Create the app:
   ```bash
   doctl apps create --spec .do/app.yaml
   ```
   Or in the UI: **Create App → GitHub → select repo → Edit Plan → Edit
   App Spec** and paste `.do/app.yaml`.
3. App Platform will build the Docker image, run health checks against
   `/healthz`, and assign a public URL.

## Notes / caveats

- The endpoint is unauthenticated by design (per request). Put it behind
  a Cloudflare/DO firewall or add an API key check before exposing it
  broadly.
- Streaming responses require `--timeout 0` on gunicorn (set in the
  Dockerfile); some proxies still buffer ndjson — `X-Accel-Buffering: no`
  is set on the response to discourage that.
- The container runs as root so massdns can open raw sockets; `--root`
  is passed to massdns to skip its drop-privileges step.
