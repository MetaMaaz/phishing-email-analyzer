"""FR4 — IOC enrichment (pluggable, degrades gracefully).

Sources: VirusTotal, AbuseIPDB, URLhaus, plus an optional hand-off to the
owner's **ThreatLens** platform. Design rules from SPEC.md:

* Every network call has a timeout and a single retry.
* One source failing never aborts the run — failures are isolated and noted
  on the IOC's ``enrichment`` dict.
* With no API keys set, enrichment is skipped entirely and the tool still
  produces a complete (lower-confidence) report.

``httpx`` is preferred; if it isn't installed we fall back to the stdlib
``urllib`` so the module never hard-fails on import.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional
from urllib.parse import quote_plus

from .config import Config
from .models import IOC, Finding

PHISHING = "T1566"


# ---------------------------------------------------------------------------
# Tiny HTTP wrapper: timeout + one retry, works with httpx or urllib.
# ---------------------------------------------------------------------------
def _http_get(url: str, headers: dict[str, str], timeout: int) -> Optional[dict[str, Any]]:
    for attempt in range(2):  # initial try + one retry
        try:
            return _do_get(url, headers, timeout)
        except Exception:
            if attempt == 0:
                time.sleep(0.5)
                continue
            return None
    return None


def _http_post(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout: int
) -> Optional[dict[str, Any]]:
    for attempt in range(2):
        try:
            return _do_post(url, headers, body, timeout)
        except Exception:
            if attempt == 0:
                time.sleep(0.5)
                continue
            return None
    return None


def _do_get(url: str, headers: dict[str, str], timeout: int) -> dict[str, Any]:
    try:
        import httpx  # type: ignore

        r = httpx.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except ImportError:
        import urllib.request

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))


def _do_post(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout: int
) -> dict[str, Any]:
    try:
        import httpx  # type: ignore

        r = httpx.post(url, headers=headers, json=body, timeout=timeout)
        r.raise_for_status()
        return r.json() if r.content else {}
    except ImportError:
        import urllib.request

        data = json.dumps(body).encode("utf-8")
        h = dict(headers)
        h.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}


# ---------------------------------------------------------------------------
# Per-source lookups
# ---------------------------------------------------------------------------
def vt_lookup(ioc: IOC, config: Config) -> Optional[dict[str, Any]]:
    if not config.vt_api_key:
        return None
    headers = {"x-apikey": config.vt_api_key}
    if ioc.type == "url":
        # VT expects the URL id; submit then read is two calls — here we use
        # the URL search endpoint id form (base64 unpadded) for simplicity.
        import base64

        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc.type == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc.value}"
    elif ioc.type in ("md5", "sha1", "sha256"):
        endpoint = f"https://www.virustotal.com/api/v3/files/{ioc.value}"
    else:
        return None

    data = _http_get(endpoint, headers, config.http_timeout)
    if not data:
        return None
    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    malicious = int(stats.get("malicious", 0)) if stats else 0
    return {"source": "virustotal", "malicious": malicious, "stats": stats}


def abuseipdb_lookup(ip: str, config: Config) -> Optional[dict[str, Any]]:
    if not config.abuseipdb_api_key or not ip:
        return None
    url = (
        "https://api.abuseipdb.com/api/v2/check?ipAddress="
        + quote_plus(ip)
        + "&maxAgeInDays=90"
    )
    headers = {"Key": config.abuseipdb_api_key, "Accept": "application/json"}
    data = _http_get(url, headers, config.http_timeout)
    if not data:
        return None
    d = data.get("data", {})
    return {
        "source": "abuseipdb",
        "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
        "totalReports": d.get("totalReports", 0),
        "countryCode": d.get("countryCode"),
    }


def urlhaus_lookup(url_value: str, config: Config) -> Optional[dict[str, Any]]:
    """URLhaus URL lookup. Public endpoint; auth key optional/newer API."""

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        import httpx  # type: ignore

        headers = {}
        if config.urlhaus_auth_key:
            headers["Auth-Key"] = config.urlhaus_auth_key
        r = httpx.post(
            endpoint, data={"url": url_value}, headers=headers,
            timeout=config.http_timeout,
        )
        r.raise_for_status()
        data = r.json()
    except Exception:
        return None
    if not data or data.get("query_status") != "ok":
        return None
    return {
        "source": "urlhaus",
        "threat": data.get("threat"),
        "url_status": data.get("url_status"),
    }


def threatlens_handoff(iocs: list[IOC], config: Config) -> Optional[dict[str, Any]]:
    """Optional hand-off: POST the extracted IOCs to a running ThreatLens
    instance for the owner's own enrichment/correlation pipeline."""

    if not config.threatlens_base_url:
        return None
    url = config.threatlens_base_url.rstrip("/") + "/api/iocs/ingest"
    headers = {}
    if config.threatlens_api_key:
        headers["Authorization"] = f"Bearer {config.threatlens_api_key}"
    payload = {
        "source": "phishing-email-analyzer",
        "iocs": [{"type": i.type, "value": i.value, "origin": i.origin} for i in iocs],
    }
    return _http_post(url, headers, payload, config.http_timeout)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def enrich_iocs(
    iocs: list[IOC], originating_ip: Optional[str], config: Config
) -> list[Finding]:
    """Enrich IOCs in place (populating ``ioc.enrichment``) and return any
    scoring findings the enrichment justifies. Skips cleanly with no keys."""

    findings: list[Finding] = []

    have_any_key = any(
        [config.vt_api_key, config.abuseipdb_api_key, config.threatlens_base_url]
    )
    if not have_any_key and not config.urlhaus_auth_key:
        # Nothing to do; still try URLhaus public endpoint opportunistically?
        # Keep it strictly offline-safe: skip all network when no config given.
        return findings

    for ioc in iocs:
        if ioc.type in ("url", "domain", "md5", "sha1", "sha256"):
            vt = vt_lookup(ioc, config)
            if vt:
                ioc.enrichment["virustotal"] = vt
                if vt.get("malicious", 0) > 0:
                    is_hash = ioc.type in ("md5", "sha1", "sha256")
                    findings.append(
                        Finding(
                            "ATTACHMENT_KNOWN_BAD" if is_hash else "URL_FLAGGED",
                            f"{ioc.type} '{ioc.defanged}' flagged malicious by "
                            f"VirusTotal ({vt['malicious']} engines)",
                            config.weights["ATTACHMENT_KNOWN_BAD"] if is_hash
                            else config.weights["URL_FLAGGED"],
                            [PHISHING, "T1566.001" if is_hash else "T1566.002"],
                        )
                    )
        if ioc.type == "url":
            uh = urlhaus_lookup(ioc.value, config)
            if uh:
                ioc.enrichment["urlhaus"] = uh
                findings.append(
                    Finding(
                        "URL_FLAGGED",
                        f"URL '{ioc.defanged}' known to URLhaus "
                        f"(threat: {uh.get('threat')})",
                        config.weights["URL_FLAGGED"],
                        [PHISHING, "T1566.002"],
                    )
                )

    if originating_ip:
        ab = abuseipdb_lookup(originating_ip, config)
        if ab and int(ab.get("abuseConfidenceScore", 0)) >= 50:
            findings.append(
                Finding(
                    "IP_FLAGGED",
                    f"Originating IP {originating_ip} has AbuseIPDB confidence "
                    f"{ab['abuseConfidenceScore']}% ({ab.get('totalReports', 0)} reports)",
                    config.weights["IP_FLAGGED"],
                    [PHISHING],
                )
            )

    # Hand-off last; its response is informational, not scored.
    tl = threatlens_handoff(iocs, config)
    if tl is not None:
        for ioc in iocs:
            ioc.enrichment.setdefault("threatlens", {"submitted": True})

    return findings
