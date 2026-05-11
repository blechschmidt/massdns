"""Parsers for massdns JSONL and SPI SI.xml documents."""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from typing import Iterator, List, Optional

from .models import Bearer, CnameHit, MediaItem, SrvRecord, Station
from .utils import is_valid_domain, log, normalize_domain


# ---------------------------------------------------------------------------
# massdns JSONL
# ---------------------------------------------------------------------------

def _iter_answers(rec: dict) -> List[dict]:
    """Tolerate the small variations in massdns ndjson schemas."""
    answers = []
    data = rec.get("data")
    if isinstance(data, dict):
        a = data.get("answers")
        if isinstance(a, list):
            answers.extend(a)
    a2 = rec.get("answers")
    if isinstance(a2, list):
        answers.extend(a2)
    return answers


def _resolver_of(rec: dict) -> Optional[str]:
    r = rec.get("resolver")
    if isinstance(r, str) and r:
        return r
    if isinstance(r, dict):
        return r.get("ip") or r.get("address") or None
    return None


def parse_cname_jsonl(path: str) -> Iterator[CnameHit]:
    """Yield (queried, broadcaster) pairs from massdns CNAME ndjson output."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_num, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                log.debug("cname jsonl line %d: skipping (%s)", line_num, e)
                continue
            if rec.get("status") and rec["status"] != "NOERROR":
                continue
            queried = normalize_domain(rec.get("name") or "")
            if not queried:
                continue
            for ans in _iter_answers(rec):
                if str(ans.get("type", "")).upper() != "CNAME":
                    continue
                target = normalize_domain(ans.get("data") or "")
                if not target or not is_valid_domain(target):
                    continue
                yield CnameHit(
                    queried_domain=queried,
                    broadcaster_fqdn=target,
                    resolver=_resolver_of(rec),
                    raw_json=line,
                )
                break


def parse_srv_jsonl(path: str) -> Iterator[SrvRecord]:
    """Yield SrvRecord rows from massdns SRV ndjson output."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line_num, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                log.debug("srv jsonl line %d: skipping (%s)", line_num, e)
                continue
            if rec.get("status") and rec["status"] != "NOERROR":
                continue
            service_domain = normalize_domain(rec.get("name") or "")
            if not service_domain:
                continue
            service_type = ".".join(service_domain.split(".")[:2])
            for ans in _iter_answers(rec):
                if str(ans.get("type", "")).upper() != "SRV":
                    continue
                data = ans.get("data") or ""
                parts = str(data).split()
                if len(parts) < 4:
                    continue
                try:
                    priority = int(parts[0])
                    weight = int(parts[1])
                    port = int(parts[2])
                except ValueError:
                    continue
                target = normalize_domain(parts[3])
                if not target:
                    continue
                yield SrvRecord(
                    service_domain=service_domain,
                    service_type=service_type,
                    priority=priority, weight=weight, port=port,
                    target=target,
                    raw_json=line,
                )


# ---------------------------------------------------------------------------
# SI.xml (SPI 3.1)
# ---------------------------------------------------------------------------

def _localname(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _findall_local(elem: ET.Element, name: str) -> List[ET.Element]:
    return [e for e in elem.iter() if _localname(e.tag) == name]


def _children_local(elem: ET.Element, name: str) -> List[ET.Element]:
    return [e for e in list(elem) if _localname(e.tag) == name]


def _first_text(elem: ET.Element, name: str) -> Optional[str]:
    for c in _children_local(elem, name):
        if c.text:
            return c.text.strip() or None
    return None


def _int_or_none(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_si_xml(path: str, source_target: Optional[str] = None) -> List[Station]:
    """Parse SI.xml at *path*, returning a list of Station records."""
    src = source_target or os.path.basename(path)
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        log.warning("SI parse error %s: %s", path, e)
        return []
    root = tree.getroot()

    stations: List[Station] = []
    for service in _findall_local(root, "service"):
        st = Station(source_target=src)
        st.short_name = _first_text(service, "shortName")
        st.medium_name = _first_text(service, "mediumName")
        st.long_name = _first_text(service, "longName")

        for rdns in _children_local(service, "radiodns"):
            fq = rdns.attrib.get("fqdn")
            sid = rdns.attrib.get("serviceIdentifier")
            if fq and not st.radiodns_fqdn:
                st.radiodns_fqdn = normalize_domain(fq)
            if sid and not st.service_identifier:
                st.service_identifier = sid.strip().lower()

        for b in _children_local(service, "bearer"):
            bid = b.attrib.get("id")
            if not bid:
                continue
            st.bearers.append(Bearer(
                bearer_id=bid.strip(),
                cost=_int_or_none(b.attrib.get("cost")),
                mime=b.attrib.get("mimeValue") or b.attrib.get("mimeType"),
                offset=_int_or_none(b.attrib.get("offset")),
            ))

        for md in _children_local(service, "mediaDescription"):
            for mm in _findall_local(md, "multimedia"):
                url = mm.attrib.get("url")
                if not url:
                    continue
                st.media.append(MediaItem(
                    url=url.strip(),
                    width=_int_or_none(mm.attrib.get("width")),
                    height=_int_or_none(mm.attrib.get("height")),
                    mime_value=mm.attrib.get("mimeValue") or mm.attrib.get("mimeType"),
                ))

        try:
            st.raw_xml_fragment = ET.tostring(service, encoding="unicode")
        except Exception:
            st.raw_xml_fragment = None

        stations.append(st)
    return stations
