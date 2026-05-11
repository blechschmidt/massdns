"""Minimal PowerDNS HTTP API v1 client.

Env vars:
  PDNS_API_URL   e.g. http://147.182.190.208:8081/api/v1
  PDNS_API_KEY   PowerDNS API secret (from pdns.conf api-key=)
  PDNS_ZONE      e.g. radiodns.zerotrustradio.org
  PDNS_SERVER    PowerDNS server id, almost always 'localhost'
  PDNS_TTL       default TTL in seconds (default 300)
"""
from __future__ import annotations

import os

import requests

PDNS_API_URL = os.environ.get("PDNS_API_URL", "http://147.182.190.208:8081/api/v1")
PDNS_API_KEY = os.environ.get("PDNS_API_KEY", "")
PDNS_ZONE = os.environ.get("PDNS_ZONE", "radiodns.zerotrustradio.org")
PDNS_SERVER = os.environ.get("PDNS_SERVER", "localhost")
PDNS_TTL = int(os.environ.get("PDNS_TTL", "300"))


def _abs(name: str) -> str:
    """Return an absolute DNS name (trailing dot)."""
    return name.strip().rstrip(".") + "."


def _headers() -> dict:
    return {"X-API-Key": PDNS_API_KEY, "Content-Type": "application/json"}


def _zone_url() -> str:
    return f"{PDNS_API_URL.rstrip('/')}/servers/{PDNS_SERVER}/zones/{_abs(PDNS_ZONE)}"


def upsert_cname(name: str, target: str, ttl: int = PDNS_TTL) -> None:
    payload = {
        "rrsets": [{
            "name": _abs(name),
            "type": "CNAME",
            "ttl": ttl,
            "changetype": "REPLACE",
            "records": [{"content": _abs(target), "disabled": False}],
        }]
    }
    r = requests.patch(_zone_url(), json=payload, headers=_headers(), timeout=10)
    r.raise_for_status()


def upsert_srv(name: str, priority: int, weight: int, port: int, target: str,
               ttl: int = PDNS_TTL) -> None:
    content = f"{priority} {weight} {port} {_abs(target)}"
    payload = {
        "rrsets": [{
            "name": _abs(name),
            "type": "SRV",
            "ttl": ttl,
            "changetype": "REPLACE",
            "records": [{"content": content, "disabled": False}],
        }]
    }
    r = requests.patch(_zone_url(), json=payload, headers=_headers(), timeout=10)
    r.raise_for_status()


def delete_rrset(name: str, rtype: str) -> None:
    payload = {
        "rrsets": [{
            "name": _abs(name),
            "type": rtype.upper(),
            "changetype": "DELETE",
        }]
    }
    r = requests.patch(_zone_url(), json=payload, headers=_headers(), timeout=10)
    r.raise_for_status()


def zone_rrsets() -> list:
    r = requests.get(_zone_url(), headers=_headers(), timeout=15)
    r.raise_for_status()
    return r.json().get("rrsets", [])


def pdns_status() -> dict:
    try:
        r = requests.get(_zone_url(), headers=_headers(), timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                "ok": True,
                "zone": PDNS_ZONE,
                "api_url": PDNS_API_URL,
                "rrset_count": len(data.get("rrsets", [])),
            }
        return {"ok": False, "zone": PDNS_ZONE, "http_status": r.status_code,
                "detail": r.text[:200]}
    except Exception as e:
        return {"ok": False, "zone": PDNS_ZONE, "error": str(e)}
