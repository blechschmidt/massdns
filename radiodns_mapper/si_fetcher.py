"""Fetch SI.xml documents from RadioEPG SRV targets."""
from __future__ import annotations

import os
from typing import Iterable, Optional, Tuple

import requests

from .models import SiDocument
from .utils import log, safe_filename, sha256_file

SI_PATH = "/radiodns/spi/3.1/SI.xml"
USER_AGENT = "radiodns-mapper/0.1 (+https://github.com/chelstein/massdns)"


def candidate_urls(target: str, port: Optional[int], try_https: bool) -> Iterable[str]:
    target = target.rstrip(".")
    schemes = ["http"]
    if try_https:
        schemes.append("https")
    for scheme in schemes:
        if port and port not in (80, 443):
            host = f"{target}:{port}"
        else:
            host = target
        yield f"{scheme}://{host}{SI_PATH}"


def fetch_one(
    target: str,
    port: Optional[int],
    output_dir: str,
    timeout: float = 8.0,
    try_https: bool = True,
    session: Optional[requests.Session] = None,
) -> SiDocument:
    sess = session or requests.Session()
    headers = {"User-Agent": USER_AGENT, "Accept": "application/xml,text/xml,*/*"}
    last_status: Optional[int] = None
    last_url: Optional[str] = None

    for url in candidate_urls(target, port, try_https):
        last_url = url
        try:
            log.debug("GET %s", url)
            resp = sess.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            last_status = resp.status_code
        except requests.RequestException as e:
            log.debug("HTTP error %s: %s", url, e)
            continue

        ctype = (resp.headers.get("content-type") or "").lower()
        body = resp.content
        if resp.status_code == 200 and body and (
            "xml" in ctype or body.lstrip().startswith(b"<")
        ):
            os.makedirs(output_dir, exist_ok=True)
            fname = safe_filename(target) + ".xml"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "wb") as fh:
                fh.write(body)
            digest = sha256_file(fpath)
            log.info("fetched SI.xml: %s -> %s (%d bytes, %s)",
                     target, fpath, len(body), digest[:12])
            return SiDocument(
                target=target, url=url, status_code=resp.status_code,
                filepath=fpath, sha256=digest,
            )

    log.warning("no SI.xml for %s (last url=%s status=%s)",
                target, last_url, last_status)
    return SiDocument(
        target=target, url=last_url or "", status_code=last_status,
        filepath=None, sha256=None,
    )


def fetch_targets(
    targets: Iterable[Tuple[str, Optional[int]]],
    output_dir: str,
    timeout: float = 8.0,
    try_https: bool = True,
) -> Iterable[SiDocument]:
    sess = requests.Session()
    sess.headers.update({"User-Agent": USER_AGENT})
    for target, port in targets:
        yield fetch_one(target, port, output_dir, timeout, try_https, sess)
