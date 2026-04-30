"""Candidate FM RadioDNS FQDN generation."""
from __future__ import annotations

import re
from typing import Iterable, Iterator, List, Optional

from .models import CandidateDomain
from .utils import is_hex

SUFFIX = "fm.radiodns.org"
FREQ_MIN = 8750     # 87.5 MHz
FREQ_MAX = 10800    # 108.0 MHz
DEFAULT_STEP = 10   # 0.1 MHz

_PI_RE = re.compile(r"^[0-9a-f]{4}$")
_ECC_RE = re.compile(r"^[0-9a-f]{2}$")


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


def parse_freq(value) -> int:
    """Accept int, '10620', '106.2', or '106.20 MHz'. Return integer 10 kHz."""
    if isinstance(value, int):
        return value
    s = str(value).strip().lower().replace("mhz", "").strip()
    if not s:
        raise ValueError("empty frequency")
    if "." in s:
        return round(float(s) * 100)
    return int(s)


def build_gcc(pi: str, ecc: str) -> str:
    return normalize_pi(pi)[0] + normalize_ecc(ecc)


def build_fqdn(freq: int, pi: str, ecc: str) -> str:
    if not isinstance(freq, int):
        raise ValueError(f"freq must be int, got {type(freq).__name__}")
    if freq < 0 or freq > 99999:
        raise ValueError(f"frequency out of 5-digit range: {freq}")
    pi_n = normalize_pi(pi)
    ecc_n = normalize_ecc(ecc)
    gcc = pi_n[0] + ecc_n
    return f"{freq:05d}.{pi_n}.{gcc}.{SUFFIX}"


def iter_candidates(
    freq_start: int = FREQ_MIN,
    freq_end: int = FREQ_MAX,
    freq_step: int = DEFAULT_STEP,
    pi_start: str = "0000",
    pi_end: str = "ffff",
    eccs: Iterable[str] = ("e0", "e1", "d0", "f0", "a0", "c0"),
    limit: Optional[int] = None,
    source: str = "brute",
) -> Iterator[CandidateDomain]:
    if freq_step <= 0:
        raise ValueError("freq_step must be positive")
    eccs_norm = [normalize_ecc(e) for e in eccs]
    if not eccs_norm:
        raise ValueError("at least one ECC required")
    pi_a = int(normalize_pi(pi_start), 16)
    pi_b = int(normalize_pi(pi_end), 16)
    if pi_b < pi_a:
        return

    count = 0
    for freq in range(freq_start, freq_end + 1, freq_step):
        for n in range(pi_a, pi_b + 1):
            pi = f"{n:04x}"
            for ecc in eccs_norm:
                domain = build_fqdn(freq, pi, ecc)
                yield CandidateDomain(
                    domain=domain, freq=freq, pi=pi, ecc=ecc,
                    gcc=pi[0] + ecc, source=source,
                )
                count += 1
                if limit is not None and count >= limit:
                    return


def iter_expansion(
    seed_fqdn: str,
    pi_window: int = 32,
    freq_window: int = 0,
    freq_step: int = DEFAULT_STEP,
) -> Iterator[CandidateDomain]:
    """Generate nearby candidates around a confirmed RadioDNS hit.

    Hits look like ``10620.c460.ce1.fm.radiodns.org``. We sweep PI ± pi_window
    at the same (freq, ecc), and (optionally) ± freq_window steps at the same
    (pi, ecc).
    """
    parts = seed_fqdn.strip().lower().rstrip(".").split(".")
    if len(parts) < 6 or ".".join(parts[-3:]) != SUFFIX:
        raise ValueError(f"not a RadioDNS FM FQDN: {seed_fqdn!r}")
    freq_str, pi, gcc = parts[0], parts[1], parts[2]
    if not (freq_str.isdigit() and len(freq_str) == 5):
        raise ValueError(f"bad freq component: {freq_str!r}")
    if not is_hex(pi, 4):
        raise ValueError(f"bad pi component: {pi!r}")
    if not is_hex(gcc, 3):
        raise ValueError(f"bad gcc component: {gcc!r}")
    freq = int(freq_str)
    ecc = gcc[1:]

    seen = set()

    pi_int = int(pi, 16)
    pi_lo = max(0x0000, pi_int - pi_window)
    pi_hi = min(0xFFFF, pi_int + pi_window)

    if freq_window > 0:
        f_lo = max(FREQ_MIN, freq - freq_window * freq_step)
        f_hi = min(FREQ_MAX, freq + freq_window * freq_step)
    else:
        f_lo, f_hi = freq, freq

    for f in range(f_lo, f_hi + 1, freq_step):
        for n in range(pi_lo, pi_hi + 1):
            new_pi = f"{n:04x}"
            domain = build_fqdn(f, new_pi, ecc)
            if domain in seen or domain == seed_fqdn:
                continue
            seen.add(domain)
            yield CandidateDomain(
                domain=domain, freq=f, pi=new_pi, ecc=ecc,
                gcc=new_pi[0] + ecc, source="expand",
            )


def write_candidates(stream: Iterable[CandidateDomain], out_path: str,
                     progress_every: int = 100_000) -> int:
    import sys
    count = 0
    seen = set()
    if out_path == "-":
        out = sys.stdout
        close_after = False
    else:
        out = open(out_path, "w", encoding="utf-8")
        close_after = True
    try:
        for c in stream:
            if c.domain in seen:
                continue
            seen.add(c.domain)
            out.write(c.domain + "\n")
            count += 1
            if count % progress_every == 0:
                print(f"... wrote {count:,}", file=sys.stderr)
                out.flush()
    finally:
        if close_after:
            out.close()
    return count


def parse_ecc_list(raw: str) -> List[str]:
    return [normalize_ecc(p) for p in raw.split(",") if p.strip()]
