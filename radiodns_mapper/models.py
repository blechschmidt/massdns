"""Typed records used across the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CandidateDomain:
    domain: str
    freq: int           # integer 10 kHz units, e.g. 10620 for 106.2 MHz
    pi: str             # 4-char lowercase hex
    ecc: str            # 2-char lowercase hex
    gcc: str            # 3-char lowercase hex
    source: str = "brute"


@dataclass
class CnameHit:
    queried_domain: str
    broadcaster_fqdn: str
    resolver: Optional[str] = None
    raw_json: Optional[str] = None


@dataclass
class SrvRecord:
    service_domain: str   # e.g. _radioepg._tcp.example.com
    service_type: str     # "_radioepg._tcp" / "_radiovis._tcp" / ...
    priority: int
    weight: int
    port: int
    target: str
    raw_json: Optional[str] = None


@dataclass
class SiDocument:
    target: str
    url: str
    status_code: Optional[int]
    filepath: Optional[str]
    sha256: Optional[str]


@dataclass
class MediaItem:
    url: str
    width: Optional[int] = None
    height: Optional[int] = None
    mime_value: Optional[str] = None


@dataclass
class Bearer:
    bearer_id: str
    cost: Optional[int] = None
    mime: Optional[str] = None
    offset: Optional[int] = None


@dataclass
class Station:
    source_target: str
    short_name: Optional[str] = None
    medium_name: Optional[str] = None
    long_name: Optional[str] = None
    radiodns_fqdn: Optional[str] = None
    service_identifier: Optional[str] = None
    raw_xml_fragment: Optional[str] = None
    bearers: List[Bearer] = field(default_factory=list)
    media: List[MediaItem] = field(default_factory=list)
