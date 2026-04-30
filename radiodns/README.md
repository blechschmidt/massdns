# radiodns_generator.py

Generate **RadioDNS FM bearer FQDNs** for bulk DNS resolution with
[massdns](../README.md). Produces a streaming list of names of the form

```
<freq5>.<pi>.<gcc>.fm.radiodns.org
```

where:

| field   | format                                                  | example          |
| ------- | ------------------------------------------------------- | ---------------- |
| `freq5` | FM frequency in 10 kHz units, zero-padded to 5 digits   | `09580` (95.8 MHz) |
| `pi`    | 4-character RDS PI code, lowercase hex                  | `c479`           |
| `gcc`   | first hex char of PI + ECC, lowercase                   | `ce1`            |

Worked example — PI `c479`, ECC `e1`, frequency 95.8 MHz:

```
09580.c479.ce1.fm.radiodns.org
```

## Install

No dependencies beyond Python 3.8+. The script is self-contained.

```bash
chmod +x radiodns/radiodns_generator.py
```

## Quick verify

```bash
python3 radiodns/radiodns_generator.py self-test
```

## Modes

### `from-csv`

Read a CSV with columns `frequency,pi,ecc` and emit one FQDN per row. The
frequency column accepts `95.8`, `95.80`, `95.80 MHz`, or `09580`
(already-normalized 10 kHz units).

```bash
python3 radiodns/radiodns_generator.py from-csv \
    --input radiodns/example_stations.csv \
    --output domains.txt
```

`example_stations.csv`:

```csv
frequency,pi,ecc
95.8,c479,e1
101.9,c123,e1
88.7,c201,e1
```

Rows that fail validation are logged to stderr and skipped — the rest of
the file still streams to disk.

### `brute`

Sweep the FM band against a PI range and an ECC list. Defaults: 87.5 MHz
through 108.0 MHz inclusive in 0.1 MHz steps, full PI range
`0000`–`ffff`, ECCs `e1,e0,d0,a0,c0`.

```bash
python3 radiodns/radiodns_generator.py brute \
    --ecc e1,e0,d0 \
    --pi-start c000 \
    --pi-end cfff \
    --output domains.txt \
    --limit 100000
```

Output is streamed; stderr reports progress every 100,000 records. With
no `--limit`, the full default sweep is roughly 206 freqs × 65,536 PIs ×
5 ECCs ≈ 67.5M records.

## Helper functions

The script also exposes the building blocks for use as a library:

| function | summary |
| -------- | ------- |
| `parse_frequency_to_freq5(value)` | normalize "95.8" / "10190" / "101.90 MHz" to 5-digit 10 kHz string |
| `normalize_pi(value)`             | lowercase, validate 4 hex chars |
| `normalize_ecc(value)`            | lowercase, validate 2 hex chars |
| `build_gcc(pi, ecc)`              | `pi[0] + ecc` (3 chars) |
| `build_fm_radiodns_fqdn(freq5, pi, ecc)` | full FQDN string |
| `iter_fm_frequencies(start, end, step)` | yields MHz floats over an inclusive range |
| `iter_pi_range(pi_start, pi_end)` | yields zero-padded 4-char hex PI strings |
| `generate_from_csv(path)`         | streaming generator of FQDNs |
| `generate_brute(...)`             | streaming generator of FQDNs |

## Resolving with massdns

Once you have `domains.txt`, point massdns at a resolvers list and ask
for CNAMEs (the standard RadioDNS lookup is a CNAME pointing at the
authoritative bearer host) and A records. With this repo built (`make`)
you'll have `bin/massdns`:

```bash
./bin/massdns -r lists/resolvers.txt -t CNAME -o S domains.txt > cname_results.txt
./bin/massdns -r lists/resolvers.txt -t A     -o S domains.txt > a_results.txt
```

`-o S` gives a simple text format. To get JSON for downstream tooling:

```bash
./bin/massdns -r lists/resolvers.txt -t CNAME -o J domains.txt > cname_results.ndjson
```

## Following up: SRV expansion

A *valid* RadioDNS hit is an FQDN that returns an authoritative CNAME
target. Each authoritative target should then be probed for the
RadioDNS service SRV records:

```
_radioepg._tcp.<authoritative-fqdn>
_radiovis._tcp.<authoritative-fqdn>
```

(Other applications include `_radiotag._tcp` and `_radiospi._tcp`.) A
small awk/grep pass over the CNAME results is the easiest way to build
that second-stage list:

```bash
# pick out unique CNAME targets
awk '$2=="CNAME" {print $3}' cname_results.txt \
  | sed 's/\.$//' \
  | sort -u > targets.txt

# generate the SRV candidate names for stage 2
awk '{
        print "_radioepg._tcp." $0;
        print "_radiovis._tcp." $0;
        print "_radiotag._tcp." $0;
        print "_radiospi._tcp." $0;
     }' targets.txt > srv_candidates.txt

# resolve the SRVs
./bin/massdns -r lists/resolvers.txt -t SRV -o S srv_candidates.txt > srv_results.txt
```

The SRV target/port pairs returned in stage 2 are the actual RadioDNS
service endpoints (RadioEPG XML feeds, RadioVIS slideshow channels,
etc.).

## Notes

- The generator uses integer 10 kHz arithmetic internally, so the
  classic `0.1` floating-point drift across the FM band cannot affect
  the output.
- `from-csv` is forgiving about column case and whitespace; brute mode
  validates `--pi-start`, `--pi-end`, and every `--ecc` value before
  starting.
- The full default brute sweep is *large* — pipe to gzip
  (`--output -` and pipe to `gzip > domains.txt.gz`) if disk is tight.
