#!/usr/bin/env python3
"""Generate RadioDNS FM bearer FQDNs for bulk resolution with massdns.

FM/RDS bearer FQDN format:
    <freq5>.<pi>.<gcc>.fm.radiodns.org

where:
    freq5 = FM frequency in 10 kHz units, zero-padded to 5 digits
            (95.8 MHz -> 09580, 101.9 MHz -> 10190, 88.7 MHz -> 08870)
    pi    = 4-character RDS PI code, lowercase hex
    gcc   = first hex char of PI + ECC (lowercase)
    e.g. PI c479 + ECC e1  ->  gcc ce1
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import re
import sys
from typing import Iterator, Iterable, List, Optional

SUFFIX = "fm.radiodns.org"
FM_BAND_MIN_MHZ = 87.5
FM_BAND_MAX_MHZ = 108.0

_PI_RE = re.compile(r"^[0-9a-f]{4}$")
_ECC_RE = re.compile(r"^[0-9a-f]{2}$")
_FREQ5_RE = re.compile(r"^\d{5}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_frequency_to_freq5(value: str) -> str:
    """Normalize a frequency to the 5-digit, 10 kHz format used in RadioDNS.

    Accepts:
      "95.8", "101.9", "88.70 MHz"  -> MHz value
      "10190", "09580"              -> already in 10 kHz units
    """
    if value is None:
        raise ValueError("frequency is required")
    s = str(value).strip().lower()
    s = s.replace("mhz", "").strip()
    if not s:
        raise ValueError("empty frequency")
    if "." in s:
        try:
            mhz = float(s)
        except ValueError as e:
            raise ValueError(f"invalid frequency: {value!r}") from e
        khz10 = round(mhz * 100)
    else:
        try:
            khz10 = int(s)
        except ValueError as e:
            raise ValueError(f"invalid frequency: {value!r}") from e
    if khz10 < 0 or khz10 > 99999:
        raise ValueError(f"frequency out of 5-digit range: {value!r}")
    return f"{khz10:05d}"


def normalize_pi(value: str) -> str:
    if value is None:
        raise ValueError("pi is required")
    s = str(value).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not _PI_RE.match(s):
        raise ValueError(f"invalid PI {value!r}: must be 4 hex characters")
    return s


def normalize_ecc(value: str) -> str:
    if value is None:
        raise ValueError("ecc is required")
    s = str(value).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not _ECC_RE.match(s):
        raise ValueError(f"invalid ECC {value!r}: must be 2 hex characters")
    return s


def build_gcc(pi: str, ecc: str) -> str:
    """gcc = first hex char of PI + ECC (lowercase, 3 chars total)."""
    return normalize_pi(pi)[0] + normalize_ecc(ecc)


def build_fm_radiodns_fqdn(freq5: str, pi: str, ecc: str) -> str:
    if freq5 is None or not _FREQ5_RE.match(str(freq5)):
        raise ValueError(f"freq5 must be 5 digits, got {freq5!r}")
    pi_n = normalize_pi(pi)
    ecc_n = normalize_ecc(ecc)
    gcc = pi_n[0] + ecc_n
    return f"{freq5}.{pi_n}.{gcc}.{SUFFIX}"


def iter_fm_frequencies(
    start_mhz: float = FM_BAND_MIN_MHZ,
    end_mhz: float = FM_BAND_MAX_MHZ,
    step_mhz: float = 0.1,
) -> Iterator[float]:
    """Yield MHz values across an inclusive range using integer 10 kHz steps."""
    start = round(start_mhz * 100)
    end = round(end_mhz * 100)
    step = round(step_mhz * 100)
    if step <= 0:
        raise ValueError("step must be positive")
    if end < start:
        return
    for v in range(start, end + 1, step):
        yield v / 100.0


def iter_pi_range(pi_start: str, pi_end: str) -> Iterator[str]:
    a = int(normalize_pi(pi_start), 16)
    b = int(normalize_pi(pi_end), 16)
    if b < a:
        return
    for n in range(a, b + 1):
        yield f"{n:04x}"


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _open_for_read(path: str):
    if path == "-":
        yield sys.stdin
    else:
        fh = open(path, newline="")
        try:
            yield fh
        finally:
            fh.close()


def generate_from_csv(input_path: str) -> Iterator[str]:
    """Stream FQDNs from a CSV with columns: frequency, pi, ecc.

    Rows that fail validation are skipped with a warning on stderr; valid
    rows continue to be yielded.
    """
    with _open_for_read(input_path) as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ValueError("CSV has no header row")
        normalized_headers = {h.strip().lower(): h for h in reader.fieldnames if h}
        for col in ("frequency", "pi", "ecc"):
            if col not in normalized_headers:
                raise ValueError(
                    f"CSV missing required column {col!r}; "
                    f"got {reader.fieldnames!r}"
                )
        freq_col = normalized_headers["frequency"]
        pi_col = normalized_headers["pi"]
        ecc_col = normalized_headers["ecc"]

        for row_num, row in enumerate(reader, start=2):
            try:
                freq5 = parse_frequency_to_freq5(row[freq_col])
                yield build_fm_radiodns_fqdn(freq5, row[pi_col], row[ecc_col])
            except ValueError as e:
                print(f"row {row_num}: skipping ({e})", file=sys.stderr)


def generate_brute(
    start_mhz: float = FM_BAND_MIN_MHZ,
    end_mhz: float = FM_BAND_MAX_MHZ,
    step_mhz: float = 0.1,
    pi_start: str = "0000",
    pi_end: str = "ffff",
    eccs: Iterable[str] = ("e1", "e0", "d0", "a0", "c0"),
    limit: Optional[int] = None,
) -> Iterator[str]:
    eccs_norm = [normalize_ecc(e) for e in eccs]
    if not eccs_norm:
        raise ValueError("at least one ECC required")

    count = 0
    for mhz in iter_fm_frequencies(start_mhz, end_mhz, step_mhz):
        # Format with enough precision before re-parsing back to freq5 — the
        # iter helper already advances in integer 10 kHz steps so this never
        # rounds badly.
        freq5 = parse_frequency_to_freq5(f"{mhz:.2f}")
        for pi in iter_pi_range(pi_start, pi_end):
            for ecc in eccs_norm:
                yield build_fm_radiodns_fqdn(freq5, pi, ecc)
                count += 1
                if limit is not None and count >= limit:
                    return


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PROGRESS_EVERY = 100_000


def _write_stream(gen: Iterator[str], out_path: str) -> int:
    count = 0
    if out_path == "-":
        out = sys.stdout
        close_after = False
    else:
        out = open(out_path, "w")
        close_after = True
    try:
        for fqdn in gen:
            out.write(fqdn)
            out.write("\n")
            count += 1
            if count % PROGRESS_EVERY == 0:
                print(f"... wrote {count:,} records", file=sys.stderr)
                out.flush()
    finally:
        if close_after:
            out.close()
    print(
        f"done: wrote {count:,} records"
        + (f" to {out_path}" if out_path != "-" else " to stdout"),
        file=sys.stderr,
    )
    return count


def _cmd_from_csv(args: argparse.Namespace) -> int:
    gen = generate_from_csv(args.input)
    _write_stream(gen, args.output)
    return 0


def _cmd_brute(args: argparse.Namespace) -> int:
    eccs = [e.strip() for e in args.ecc.split(",") if e.strip()]
    if not eccs:
        print("at least one --ecc value is required", file=sys.stderr)
        return 2
    gen = generate_brute(
        start_mhz=args.start_mhz,
        end_mhz=args.end_mhz,
        step_mhz=args.step_mhz,
        pi_start=args.pi_start,
        pi_end=args.pi_end,
        eccs=eccs,
        limit=args.limit,
    )
    _write_stream(gen, args.output)
    return 0


def _cmd_self_test(_args: argparse.Namespace) -> int:
    return run_self_test()


def run_self_test() -> int:
    failures = 0

    def check(label, got, expected):
        nonlocal failures
        if got == expected:
            print(f"  ok  {label} -> {got!r}", file=sys.stderr)
        else:
            print(
                f"FAIL {label}: got {got!r} expected {expected!r}",
                file=sys.stderr,
            )
            failures += 1

    def expect_raises(label, fn, *args):
        nonlocal failures
        try:
            fn(*args)
        except ValueError:
            print(f"  ok  {label} raised ValueError", file=sys.stderr)
            return
        print(f"FAIL {label}: did not raise", file=sys.stderr)
        failures += 1

    check("freq 95.8", parse_frequency_to_freq5("95.8"), "09580")
    check("freq 101.9", parse_frequency_to_freq5("101.9"), "10190")
    check("freq 88.7", parse_frequency_to_freq5("88.7"), "08870")
    check("freq 101.90 MHz", parse_frequency_to_freq5("101.90 MHz"), "10190")
    check("freq 10190", parse_frequency_to_freq5("10190"), "10190")
    check("freq 09580", parse_frequency_to_freq5("09580"), "09580")

    check("normalize_pi C479", normalize_pi("C479"), "c479")
    check("normalize_pi 0xC479", normalize_pi("0xC479"), "c479")
    check("normalize_ecc E1", normalize_ecc("E1"), "e1")

    check("gcc(c479,e1)", build_gcc("c479", "e1"), "ce1")
    check("gcc(C123,E1)", build_gcc("C123", "E1"), "ce1")

    check(
        "fqdn 95.8 c479 e1",
        build_fm_radiodns_fqdn("09580", "c479", "e1"),
        "09580.c479.ce1.fm.radiodns.org",
    )
    check(
        "fqdn 101.9 C123 E1",
        build_fm_radiodns_fqdn("10190", "C123", "E1"),
        "10190.c123.ce1.fm.radiodns.org",
    )

    expect_raises("normalize_pi('zzzz')", normalize_pi, "zzzz")
    expect_raises("normalize_pi('abc')", normalize_pi, "abc")
    expect_raises("normalize_pi('12345')", normalize_pi, "12345")
    expect_raises("normalize_ecc('zz')", normalize_ecc, "zz")
    expect_raises("normalize_ecc('e')", normalize_ecc, "e")
    expect_raises("normalize_ecc('e10')", normalize_ecc, "e10")
    expect_raises("parse_frequency('abc')", parse_frequency_to_freq5, "abc")
    expect_raises("build_fqdn bad freq5", build_fm_radiodns_fqdn, "9580", "c479", "e1")

    # Iterators behave sanely
    freqs = list(iter_fm_frequencies(87.5, 88.0, 0.1))
    check("iter_fm len 87.5-88.0/0.1", len(freqs), 6)
    check("iter_fm[0]", round(freqs[0], 2), 87.5)
    check("iter_fm[-1]", round(freqs[-1], 2), 88.0)

    pis = list(iter_pi_range("c000", "c003"))
    check("iter_pi c000-c003", pis, ["c000", "c001", "c002", "c003"])

    if failures:
        print(f"\n{failures} self-test failure(s)", file=sys.stderr)
        return 1
    print("\nall self-tests passed", file=sys.stderr)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="radiodns_generator",
        description="Generate RadioDNS FM bearer FQDNs for bulk resolution.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser(
        "from-csv",
        help="generate from a CSV with columns: frequency, pi, ecc",
    )
    pc.add_argument("--input", "-i", required=True,
                    help="path to CSV file (use '-' for stdin)")
    pc.add_argument("--output", "-o", required=True,
                    help="path to write FQDNs (use '-' for stdout)")
    pc.set_defaults(func=_cmd_from_csv)

    pb = sub.add_parser(
        "brute",
        help="generate FM band x PI range x ECC list",
    )
    pb.add_argument("--start-mhz", type=float, default=FM_BAND_MIN_MHZ)
    pb.add_argument("--end-mhz", type=float, default=FM_BAND_MAX_MHZ)
    pb.add_argument("--step-mhz", type=float, default=0.1)
    pb.add_argument("--pi-start", default="0000")
    pb.add_argument("--pi-end", default="ffff")
    pb.add_argument(
        "--ecc",
        default="e1,e0,d0,a0,c0",
        help="comma-separated list of ECCs (default: e1,e0,d0,a0,c0)",
    )
    pb.add_argument("--limit", type=int, default=None,
                    help="stop after N records")
    pb.add_argument("--output", "-o", required=True,
                    help="path to write FQDNs (use '-' for stdout)")
    pb.set_defaults(func=_cmd_brute)

    ps = sub.add_parser("self-test", help="run internal sanity checks")
    ps.set_defaults(func=_cmd_self_test)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
