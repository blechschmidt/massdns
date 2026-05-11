# radiodns-mapper

A production-leaning Python pipeline that **discovers global FM RadioDNS
deployments end-to-end** by combining bulk DNS resolution (massdns) with
SPI 3.1 metadata fetching.

The tool generates RadioDNS FM bearer FQDNs, resolves them with massdns,
extracts authoritative broadcaster targets from CNAME answers, expands
to RadioEPG/RadioVIS SRV lookups, fetches each station's `SI.xml`, and
parses the result into a structured SQLite database (with optional
JSONL export).

## What is RadioDNS?

[RadioDNS](https://radiodns.org/) is an open IETF/ETSI-aligned mechanism
that connects broadcast radio services with IP-delivered metadata. For
FM/RDS the mapping uses a deterministic FQDN of the form:

    <freq5>.<pi>.<gcc>.fm.radiodns.org

where:

| field   | meaning                                                | example |
| ------- | ------------------------------------------------------ | ------- |
| `freq5` | FM frequency in 10 kHz units, zero-padded to 5 digits | `10620` for 106.2 MHz |
| `pi`    | 4-character RDS PI code, lowercase hex                 | `c460`  |
| `gcc`   | first hex char of PI + ECC                             | `ce1`   |

Worked example — Heart UK, 106.2 MHz, PI `C460`, ECC `E1` (United Kingdom):

    10620.c460.ce1.fm.radiodns.org

The first DNS lookup is **always a CNAME**, not an A record. The CNAME
target (e.g. `rdns.musicradio.com`) is the broadcaster's RadioDNS root.
SRV lookups against that root reveal the application endpoints
(`_radioepg._tcp`, `_radiovis._tcp`, …); a `GET` to
`http://<radioepg target>/radiodns/spi/3.1/SI.xml` returns the SPI 3.1
service-information document.

## Why massdns?

There are 65,536 PI values × ~205 frequencies × *N* ECCs of candidate
FQDNs per region. Real-world surveys want millions of QPS. massdns is
ideal because (a) FM RadioDNS responses are tiny CNAMEs, (b) massdns
streams ndjson, and (c) we can hand the broadcaster targets straight
back to massdns for the SRV phase.

## Install

```bash
# 1. Build massdns (top of repo)
make

# 2. Python deps for radiodns-mapper
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.11+ is recommended; 3.9+ works.

## End-to-end pipeline

### 1. Generate candidates

```bash
python -m radiodns_mapper.cli generate \
    --ecc e0,e1,d0,f0,a0 \
    --pi-start c000 \
    --pi-end cfff \
    --freq-start 8750 \
    --freq-end 10800 \
    --freq-step 10 \
    --output domains.txt \
    --limit 100000 \
    --db radiodns.sqlite
```

`--db` is optional; with it, every emitted candidate is also recorded
in `candidate_domains` for later joining.

### 2. CNAME scan

```bash
python -m radiodns_mapper.cli scan-cname \
    --massdns ./bin/massdns \
    --resolvers lists/resolvers.txt \
    --input domains.txt \
    --output cname.jsonl \
    --rate 50000 \
    --db radiodns.sqlite
```

Internally runs:

    massdns -r lists/resolvers.txt -t CNAME -o J -w cname.jsonl -s 50000 domains.txt

Then parses the ndjson, keeps only `NOERROR` answers that contain a
CNAME record, normalises the target FQDN, and stores hits in
`cname_hits`.

### 3. Extract broadcaster FQDNs

```bash
python -m radiodns_mapper.cli extract-broadcasters \
    --input cname.jsonl \
    --output broadcasters.txt \
    --db radiodns.sqlite
```

Either source works (`--input` reparses the ndjson, `--db` reads from
SQLite). Output is one unique broadcaster per line.

### 4. Generate SRV targets

```bash
python -m radiodns_mapper.cli generate-srv \
    --input broadcasters.txt \
    --output srv_targets.txt
```

Produces:

    _radioepg._tcp.rdns.musicradio.com
    _radiovis._tcp.rdns.musicradio.com
    _radioepg._tcp.<next>...

### 5. SRV scan

```bash
python -m radiodns_mapper.cli scan-srv \
    --massdns ./bin/massdns \
    --resolvers lists/resolvers.txt \
    --input srv_targets.txt \
    --output srv.jsonl \
    --db radiodns.sqlite
```

Stores each `(service_domain, service_type, priority, weight, port,
target)` row, deduplicated.

### 6. Fetch SI.xml

```bash
python -m radiodns_mapper.cli fetch-si \
    --db radiodns.sqlite \
    --output-dir si_xml \
    --timeout 8
```

For every distinct `_radioepg._tcp` SRV target, GETs
`http://<target>[:port]/radiodns/spi/3.1/SI.xml`. If port 80 is in the
SRV record we use it directly; otherwise we use the host. We optionally
fall back to `https://` (disable with `--http-only`). Each successful
response is saved to `si_xml/<safe-target>.xml` with sha256, and a row
written to `si_documents`.

### 7. Parse SI.xml

```bash
python -m radiodns_mapper.cli parse-si \
    --input-dir si_xml \
    --db radiodns.sqlite \
    --export stations.jsonl
```

Walks the SPI 3.1 namespace tolerantly and pulls out:

- `shortName`, `mediumName`, `longName`
- `<radiodns fqdn="…" serviceIdentifier="…"/>`
- `<bearer id="…" cost="…" mimeValue="…" offset="…"/>`
- `<mediaDescription><multimedia url="…" width="…" height="…" mimeValue="…"/></…>`

Stations land in `stations`, plus `bearers` and `media` keyed by
station id. Pass `--export` to additionally write a JSONL file with one
station object per line.

### 8. Expand confirmed hits

```bash
python -m radiodns_mapper.cli expand-hits \
    --db radiodns.sqlite \
    --window 32 \
    --output expanded_domains.txt
```

For each entry in `cname_hits`, sweeps PI ± `--window` at the same
frequency/ECC. Pass `--freq-window N` to also sweep ± N steps in
frequency. Useful when you find a single hit and want to discover the
rest of an operator's allocation cheaply. Pipe `expanded_domains.txt`
back into the `scan-cname` step.

## First-run demo

Even without running massdns yourself, you can verify the candidate
generator and SI parser against the worked example:

```bash
# Sanity check the helper output
python -m radiodns_mapper.cli generate \
    --ecc e1 --pi-start c460 --pi-end c460 \
    --freq-start 10620 --freq-end 10620 \
    --output -
# -> 10620.c460.ce1.fm.radiodns.org

# Resolve it manually (any DNS client) — expect a CNAME pointing at
# rdns.musicradio.com. Then SRV-resolve _radioepg._tcp.rdns.musicradio.com
# and GET http://<target>/radiodns/spi/3.1/SI.xml.
```

## Database schema

```
candidate_domains (domain PK, freq, pi, ecc, gcc, source, created_at)
cname_hits        (queried_domain PK, broadcaster_fqdn, resolver, raw_json, created_at)
srv_records       (service_domain, target, port → composite PK; service_type, priority, weight, raw_json, created_at)
si_documents      (target PK, url, status_code, filepath, sha256, fetched_at)
stations          (id PK, source_target, short/medium/long_name, radiodns_fqdn, service_identifier, raw_xml_fragment)
bearers           (station_id, bearer_id UNIQUE per station; cost, mime, offset)
media             (station_id, url UNIQUE per station + size; width, height, mime_value)
```

`PRAGMA foreign_keys = ON` and `journal_mode = WAL` are set per
connection. Inserts use `INSERT OR IGNORE` so every command is
idempotent.

## Data normalisation

- Domain names are always lowercased and trailing dots are stripped.
- PI/ECC/GCC are validated as fixed-length lowercase hex.
- Frequency is stored as integer 10 kHz (e.g. `10620`).
- Comment (`#…`) and blank input lines are skipped.
- `iter_candidates` deduplicates as it streams.

## Legal & ethical

- This tool issues **only DNS lookups** (and one HTTP GET per target
  during `fetch-si`). It does not probe the broadcast hardware nor
  scrape audio.
- Use a resolver list you control or have explicit permission to use.
  Hammering public resolvers (1.1.1.1, 8.8.8.8) at hundreds of
  thousands of QPS will get you blocked and is rude. Run your own
  recursive resolver (Knot Resolver, Unbound) and point massdns at
  127.0.0.1.
- Respect `robots.txt` / typical rate-limits when fetching `SI.xml`.
  The tool waits politely between targets by default (sequential
  requests, single connection).
- The data returned by RadioDNS is published metadata; the broadcasters
  intend it to be discoverable. Be a good citizen.

## Testing locally without massdns

You can stub massdns ndjson and exercise the SQLite + parser pipeline:

```python
import json, tempfile, os
from radiodns_mapper.parsers import parse_cname_jsonl
sample = {
    "name": "10620.c460.ce1.fm.radiodns.org.",
    "type": "CNAME", "status": "NOERROR",
    "data": {"answers": [{"type": "CNAME",
                          "data": "rdns.musicradio.com."}]},
}
p = tempfile.mktemp(suffix=".jsonl")
open(p, "w").write(json.dumps(sample) + "\n")
print(list(parse_cname_jsonl(p)))
```

## Troubleshooting

| symptom | likely cause |
| ------- | ------------ |
| `massdns binary not found` | wrong `--massdns` path, run `make` |
| empty `cname.jsonl` | resolvers file unreachable, or rate too high (drops) |
| `0 _radioepg._tcp targets` before `fetch-si` | run `scan-srv` first, or your SRV scan didn't return any hits |
| SI.xml fetch 404s | many broadcasters host `SI.xml` only on the SRV target's port; that's already used |
| empty stations after `parse-si` | SPI namespace mismatch — file an issue with the offending XML |

## Repository layout

```
radiodns_mapper/
  __init__.py
  cli.py             — argparse glue / pipeline orchestration
  generator.py       — FM bearer FQDN generator + expansion
  massdns_runner.py  — subprocess wrapper around the massdns binary
  parsers.py         — massdns JSONL + SPI 3.1 SI.xml parsers
  si_fetcher.py      — fetch SI.xml over HTTP(S)
  storage.py         — sqlite schema + idempotent inserts
  models.py          — typed records used across the pipeline
  utils.py           — logging, normalisation, hashing helpers
examples/
  ecc.csv            — country / ECC reference table
  seeds.txt          — known FM bearer FQDNs for `expand-hits`
requirements.txt
```
