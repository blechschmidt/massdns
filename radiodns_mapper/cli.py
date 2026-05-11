"""argparse CLI for the radiodns_mapper pipeline."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .generator import (
    DEFAULT_STEP, FREQ_MAX, FREQ_MIN, build_fqdn,
    iter_candidates, iter_expansion, parse_ecc_list, write_candidates,
)
from .massdns_runner import run_cname_scan, run_srv_scan, MassdnsError
from .parsers import parse_cname_jsonl, parse_si_xml, parse_srv_jsonl
from .si_fetcher import fetch_targets
from .storage import (
    connect, export_stations_jsonl, init_schema,
    insert_candidates, insert_cname_hit, insert_srv_record, insert_station,
    iter_radioepg_targets, iter_unique_broadcasters, upsert_si_document,
)
from .utils import iter_nonblank_lines, log, normalize_domain, setup_logging


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------

def cmd_generate(args: argparse.Namespace) -> int:
    eccs = parse_ecc_list(args.ecc)
    if args.freq_step <= 0:
        log.error("--freq-step must be positive")
        return 2
    log.info(
        "generate: freq=%d..%d step=%d pi=%s..%s ecc=%s limit=%s output=%s",
        args.freq_start, args.freq_end, args.freq_step,
        args.pi_start, args.pi_end, ",".join(eccs), args.limit, args.output,
    )
    candidates = iter_candidates(
        freq_start=args.freq_start, freq_end=args.freq_end,
        freq_step=args.freq_step,
        pi_start=args.pi_start, pi_end=args.pi_end,
        eccs=eccs, limit=args.limit,
    )
    if args.db:
        with connect(args.db) as conn:
            init_schema(conn)
            buf = []
            count = 0
            seen = set()
            out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
            try:
                for c in candidates:
                    if c.domain in seen:
                        continue
                    seen.add(c.domain)
                    buf.append(c)
                    out.write(c.domain + "\n")
                    count += 1
                    if len(buf) >= 5000:
                        insert_candidates(conn, buf)
                        buf.clear()
                    if count % 100_000 == 0:
                        log.info("... wrote %d", count)
                        out.flush()
                if buf:
                    insert_candidates(conn, buf)
            finally:
                if out is not sys.stdout:
                    out.close()
        log.info("done: %d candidates -> %s (and db)", count, args.output)
    else:
        count = write_candidates(candidates, args.output)
        log.info("done: %d candidates -> %s", count, args.output)
    return 0


# ---------------------------------------------------------------------------
# scan-cname
# ---------------------------------------------------------------------------

def cmd_scan_cname(args: argparse.Namespace) -> int:
    try:
        run_cname_scan(
            args.massdns, args.resolvers, args.input,
            args.output, rate=args.rate, dry_run=args.dry_run,
        )
    except MassdnsError as e:
        log.error("massdns failed: %s", e)
        return 1
    if args.dry_run:
        return 0

    inserted = 0
    parsed = 0
    if args.db:
        with connect(args.db) as conn:
            init_schema(conn)
            for hit in parse_cname_jsonl(args.output):
                parsed += 1
                if insert_cname_hit(conn, hit):
                    inserted += 1
                if parsed % 5000 == 0:
                    log.info("... parsed %d (new %d)", parsed, inserted)
        log.info("done: parsed %d cname records, %d new -> %s", parsed, inserted, args.db)
    else:
        for _ in parse_cname_jsonl(args.output):
            parsed += 1
        log.info("done: parsed %d cname records (no db)", parsed)
    return 0


# ---------------------------------------------------------------------------
# extract-broadcasters
# ---------------------------------------------------------------------------

def cmd_extract_broadcasters(args: argparse.Namespace) -> int:
    if not args.input and not args.db:
        log.error("provide --input <jsonl> and/or --db <sqlite>")
        return 2

    seen = set()
    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    try:
        if args.input:
            ctx = connect(args.db) if args.db else _null_ctx()
            with ctx as conn:
                if conn is not None:
                    init_schema(conn)
                for hit in parse_cname_jsonl(args.input):
                    if conn is not None:
                        insert_cname_hit(conn, hit)
                    if hit.broadcaster_fqdn in seen:
                        continue
                    seen.add(hit.broadcaster_fqdn)
                    out.write(hit.broadcaster_fqdn + "\n")
        else:
            with connect(args.db) as conn:
                init_schema(conn)
                for fqdn in iter_unique_broadcasters(conn):
                    if fqdn in seen:
                        continue
                    seen.add(fqdn)
                    out.write(fqdn + "\n")
    finally:
        if out is not sys.stdout:
            out.close()
    log.info("done: %d unique broadcasters -> %s", len(seen), args.output)
    return 0


import contextlib

@contextlib.contextmanager
def _null_ctx():
    yield None


# ---------------------------------------------------------------------------
# generate-srv
# ---------------------------------------------------------------------------

SRV_SERVICES = ("_radioepg._tcp", "_radiovis._tcp")


def cmd_generate_srv(args: argparse.Namespace) -> int:
    services = tuple(s.strip().lower() for s in args.services.split(",") if s.strip())
    if not services:
        services = SRV_SERVICES

    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    seen = set()
    count = 0
    try:
        for line in iter_nonblank_lines(args.input):
            host = normalize_domain(line)
            if not host:
                continue
            for svc in services:
                d = f"{svc}.{host}"
                if d in seen:
                    continue
                seen.add(d)
                out.write(d + "\n")
                count += 1
    finally:
        if out is not sys.stdout:
            out.close()
    log.info("done: %d srv targets -> %s", count, args.output)
    return 0


# ---------------------------------------------------------------------------
# scan-srv
# ---------------------------------------------------------------------------

def cmd_scan_srv(args: argparse.Namespace) -> int:
    try:
        run_srv_scan(
            args.massdns, args.resolvers, args.input,
            args.output, rate=args.rate, dry_run=args.dry_run,
        )
    except MassdnsError as e:
        log.error("massdns failed: %s", e)
        return 1
    if args.dry_run:
        return 0

    parsed = 0
    inserted = 0
    if args.db:
        with connect(args.db) as conn:
            init_schema(conn)
            for rec in parse_srv_jsonl(args.output):
                parsed += 1
                if insert_srv_record(conn, rec):
                    inserted += 1
                if parsed % 5000 == 0:
                    log.info("... parsed %d (new %d)", parsed, inserted)
        log.info("done: parsed %d srv records, %d new -> %s", parsed, inserted, args.db)
    else:
        for _ in parse_srv_jsonl(args.output):
            parsed += 1
        log.info("done: parsed %d srv records (no db)", parsed)
    return 0


# ---------------------------------------------------------------------------
# fetch-si
# ---------------------------------------------------------------------------

def cmd_fetch_si(args: argparse.Namespace) -> int:
    if not args.db:
        log.error("--db is required for fetch-si")
        return 2
    os.makedirs(args.output_dir, exist_ok=True)

    with connect(args.db) as conn:
        init_schema(conn)
        targets = list(iter_radioepg_targets(conn))

    if not targets:
        log.warning("no _radioepg._tcp SRV targets in %s", args.db)
        return 0

    log.info("fetching SI.xml for %d targets", len(targets))
    ok = bad = 0
    with connect(args.db) as conn:
        init_schema(conn)
        for doc in fetch_targets(
            targets, args.output_dir,
            timeout=args.timeout, try_https=not args.http_only,
        ):
            upsert_si_document(conn, doc)
            if doc.filepath:
                ok += 1
            else:
                bad += 1
    log.info("done: %d ok, %d failed", ok, bad)
    return 0


# ---------------------------------------------------------------------------
# parse-si
# ---------------------------------------------------------------------------

def cmd_parse_si(args: argparse.Namespace) -> int:
    if not args.db:
        log.error("--db is required for parse-si")
        return 2

    files: List[str] = []
    if args.input_dir:
        for entry in sorted(os.listdir(args.input_dir)):
            full = os.path.join(args.input_dir, entry)
            if os.path.isfile(full) and entry.lower().endswith(".xml"):
                files.append(full)
    elif args.input_file:
        files = [args.input_file]
    else:
        log.error("provide --input-dir or --input-file")
        return 2

    inserted = 0
    with connect(args.db) as conn:
        init_schema(conn)
        for fp in files:
            base = os.path.splitext(os.path.basename(fp))[0]
            stations = parse_si_xml(fp, source_target=base)
            for st in stations:
                if insert_station(conn, st) is not None:
                    inserted += 1
            log.info("%s -> %d stations", fp, len(stations))

    if args.export:
        with connect(args.db) as conn:
            n = export_stations_jsonl(conn, args.export)
        log.info("exported %d stations -> %s", n, args.export)

    log.info("done: %d station rows inserted/updated", inserted)
    return 0


# ---------------------------------------------------------------------------
# expand-hits
# ---------------------------------------------------------------------------

def cmd_expand_hits(args: argparse.Namespace) -> int:
    if not args.db:
        log.error("--db is required for expand-hits")
        return 2

    with connect(args.db) as conn:
        init_schema(conn)
        seeds = [row[0] for row in conn.execute(
            "SELECT queried_domain FROM cname_hits"
        )]

    log.info("expanding around %d hits with pi window=%d freq window=%d",
             len(seeds), args.window, args.freq_window)

    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")
    seen = set()
    count = 0
    try:
        for seed in seeds:
            try:
                for cand in iter_expansion(
                    seed,
                    pi_window=args.window,
                    freq_window=args.freq_window,
                    freq_step=args.freq_step,
                ):
                    if cand.domain in seen:
                        continue
                    seen.add(cand.domain)
                    out.write(cand.domain + "\n")
                    count += 1
            except ValueError as e:
                log.debug("skip seed %s: %s", seed, e)
    finally:
        if out is not sys.stdout:
            out.close()
    log.info("done: %d expanded candidates -> %s", count, args.output)
    return 0


# ---------------------------------------------------------------------------
# argparse glue
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="radiodns_mapper",
        description="Global RadioDNS discovery + mapping pipeline.",
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"radiodns-mapper {__version__}")
    p.add_argument("--verbose", action="store_true", help="enable debug logging")
    sub = p.add_subparsers(dest="cmd", required=True)

    # generate
    pg = sub.add_parser("generate", help="generate candidate FM RadioDNS FQDNs")
    pg.add_argument("--ecc", default="e0,e1,d0,f0,a0,c0",
                    help="comma-separated ECCs")
    pg.add_argument("--pi-start", default="0000")
    pg.add_argument("--pi-end", default="ffff")
    pg.add_argument("--freq-start", type=int, default=FREQ_MIN,
                    help="freq in 10 kHz units (87.5 MHz = 8750)")
    pg.add_argument("--freq-end", type=int, default=FREQ_MAX)
    pg.add_argument("--freq-step", type=int, default=DEFAULT_STEP)
    pg.add_argument("--limit", type=int, default=None)
    pg.add_argument("--output", "-o", required=True)
    pg.add_argument("--db", help="optional sqlite path; rows inserted into candidate_domains")
    pg.set_defaults(func=cmd_generate)

    # scan-cname
    pc = sub.add_parser("scan-cname", help="run massdns CNAME scan")
    pc.add_argument("--massdns", default="./bin/massdns")
    pc.add_argument("--resolvers", required=True)
    pc.add_argument("--input", required=True)
    pc.add_argument("--output", required=True, help="ndjson path written by massdns")
    pc.add_argument("--rate", type=int, default=None,
                    help="passed as -s <rate> to massdns (hashmap size / concurrency)")
    pc.add_argument("--db", help="sqlite path to store hits")
    pc.add_argument("--dry-run", action="store_true",
                    help="print the massdns command and exit")
    pc.set_defaults(func=cmd_scan_cname)

    # extract-broadcasters
    pe = sub.add_parser("extract-broadcasters",
                        help="emit unique broadcaster FQDNs from CNAME hits")
    pe.add_argument("--input", help="cname.jsonl from scan-cname")
    pe.add_argument("--db", help="optional sqlite path")
    pe.add_argument("--output", required=True)
    pe.set_defaults(func=cmd_extract_broadcasters)

    # generate-srv
    pgs = sub.add_parser("generate-srv",
                         help="emit _radioepg/_radiovis SRV lookup names")
    pgs.add_argument("--input", required=True,
                     help="broadcasters.txt (one host per line)")
    pgs.add_argument("--output", required=True)
    pgs.add_argument("--services", default=",".join(SRV_SERVICES),
                     help="comma-separated SRV service prefixes")
    pgs.set_defaults(func=cmd_generate_srv)

    # scan-srv
    ps = sub.add_parser("scan-srv", help="run massdns SRV scan")
    ps.add_argument("--massdns", default="./bin/massdns")
    ps.add_argument("--resolvers", required=True)
    ps.add_argument("--input", required=True)
    ps.add_argument("--output", required=True)
    ps.add_argument("--rate", type=int, default=None)
    ps.add_argument("--db", help="sqlite path to store records")
    ps.add_argument("--dry-run", action="store_true")
    ps.set_defaults(func=cmd_scan_srv)

    # fetch-si
    pf = sub.add_parser("fetch-si", help="fetch SI.xml from radioepg targets")
    pf.add_argument("--db", required=True)
    pf.add_argument("--output-dir", default="si_xml")
    pf.add_argument("--timeout", type=float, default=8.0)
    pf.add_argument("--http-only", action="store_true",
                    help="don't fall back to https")
    pf.set_defaults(func=cmd_fetch_si)

    # parse-si
    pp = sub.add_parser("parse-si", help="parse stored SI.xml files")
    pp.add_argument("--input-dir", help="directory containing *.xml files")
    pp.add_argument("--input-file", help="single SI.xml file")
    pp.add_argument("--db", required=True)
    pp.add_argument("--export", help="optional path to write stations.jsonl")
    pp.set_defaults(func=cmd_parse_si)

    # expand-hits
    px = sub.add_parser("expand-hits", help="generate nearby candidates around CNAME hits")
    px.add_argument("--db", required=True)
    px.add_argument("--window", type=int, default=32, help="PI window (+/-)")
    px.add_argument("--freq-window", type=int, default=0,
                    help="freq window in steps (+/-); 0 disables")
    px.add_argument("--freq-step", type=int, default=DEFAULT_STEP)
    px.add_argument("--output", required=True)
    px.set_defaults(func=cmd_expand_hits)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(getattr(args, "verbose", False))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
