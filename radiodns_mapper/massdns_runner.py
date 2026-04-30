"""Subprocess wrapper around the massdns binary."""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional

from .utils import log


class MassdnsError(RuntimeError):
    pass


def _ensure_binary(path: str) -> str:
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    found = shutil.which(path)
    if found:
        return found
    raise MassdnsError(f"massdns binary not found / not executable: {path}")


def _ensure_file(path: str, label: str) -> None:
    if not os.path.isfile(path):
        raise MassdnsError(f"{label} file does not exist: {path}")


def _build_cmd(
    massdns_bin: str,
    resolvers: str,
    record_type: str,
    input_path: str,
    output_path: str,
    rate: Optional[int],
    extra: Optional[List[str]] = None,
) -> List[str]:
    cmd = [
        massdns_bin,
        "-r", resolvers,
        "-t", record_type,
        "-o", "J",
        "-w", output_path,
    ]
    if rate is not None:
        cmd += ["-s", str(rate)]
    if extra:
        cmd += list(extra)
    cmd.append(input_path)
    return cmd


def run_scan(
    massdns_bin: str,
    resolvers: str,
    record_type: str,
    input_path: str,
    output_path: str,
    rate: Optional[int] = None,
    extra: Optional[List[str]] = None,
    dry_run: bool = False,
) -> int:
    """Run a massdns scan synchronously, streaming stderr to our logger."""
    massdns_bin = _ensure_binary(massdns_bin)
    _ensure_file(resolvers, "resolvers")
    _ensure_file(input_path, "input")
    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

    cmd = _build_cmd(
        massdns_bin, resolvers, record_type,
        input_path, output_path, rate, extra,
    )
    log.info("massdns: %s", " ".join(cmd))
    if dry_run:
        log.info("dry-run: not executing")
        return 0

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        assert proc.stderr is not None
        for line in proc.stderr:
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                log.info("massdns> %s", text)
        rc = proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    if rc != 0:
        raise MassdnsError(f"massdns exited with code {rc}")
    return rc


def run_cname_scan(massdns_bin, resolvers, input_path, output_path,
                   rate=None, dry_run=False) -> int:
    return run_scan(
        massdns_bin, resolvers, "CNAME", input_path, output_path,
        rate=rate, dry_run=dry_run,
    )


def run_srv_scan(massdns_bin, resolvers, input_path, output_path,
                 rate=None, dry_run=False) -> int:
    return run_scan(
        massdns_bin, resolvers, "SRV", input_path, output_path,
        rate=rate, dry_run=dry_run,
    )
