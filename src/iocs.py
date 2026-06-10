"""FR3 — IOC extraction, de-duplication and defanging.

Pulls URLs, domains, IPv4/IPv6, sender e-mail and attachment hashes out of an
``EmailObject``, separating *sender infrastructure* IOCs from *body / link*
IOCs, and defangs everything for safe display (``hxxp``, ``[.]``).

Uses the optional ``iocextract`` / ``tldextract`` libraries when present but
falls back to regex so the module works offline with zero extra installs.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import EmailObject, IOC

# ---------------------------------------------------------------------------
# Regexes (fallbacks; iocextract used first when available)
# ---------------------------------------------------------------------------
_URL_RE = re.compile(r"""(?xi)\b((?:https?|ftp)://[^\s<>"'\)\]]+)""")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I
)
_HASH_RES = {
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
}

_PRIVATE_IP_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.")


# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------
def defang(value: str) -> str:
    out = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace("ftp://", "fxp://")
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


def refang(value: str) -> str:
    out = value.replace("[.]", ".").replace("[@]", "@")
    out = out.replace("hxxps://", "https://").replace("hxxp://", "http://")
    out = out.replace("fxp://", "ftp://")
    return out


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------
# Build one offline tldextract instance (no network calls — uses the bundled
# public-suffix snapshot). Keeps the tool fully offline-by-default. Falls back
# to a naive split if tldextract isn't installed.
_TLD_EXTRACT = None
try:  # pragma: no cover - depends on optional dep
    import tldextract as _tldextract  # type: ignore

    _TLD_EXTRACT = _tldextract.TLDExtract(suffix_list_urls=())
except Exception:
    _TLD_EXTRACT = None


def registered_domain(host: str) -> str:
    """Best-effort eTLD+1. Uses an offline tldextract if available, else a
    naive last-two-labels split."""

    host = host.strip().lower().rstrip(".")
    if _TLD_EXTRACT is not None:
        try:
            ext = _TLD_EXTRACT(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _host_from_url(url: str) -> str:
    m = re.match(r"(?:https?|ftp)://([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    try:
        import iocextract  # type: ignore

        urls = list(iocextract.extract_urls(text, refang=True))
    except Exception:
        pass
    urls += _URL_RE.findall(text)
    cleaned = []
    for u in urls:
        # Cut at the first character that can't be part of a URL in HTML/text
        # (handles href="..."> and similar markup leaking into the match).
        for stop in ('"', "'", "<", ">", " "):
            idx = u.find(stop)
            if idx != -1:
                u = u[:idx]
        u = u.rstrip(".,);]")  # trailing sentence punctuation
        if u:
            cleaned.append(u)
    return cleaned


def extract_iocs(email_obj: EmailObject) -> list[IOC]:
    """Return a de-duplicated, defanged list of IOCs, tagged by origin."""

    seen: set[tuple[str, str]] = set()
    out: list[IOC] = []

    def add(ioc_type: str, value: str, origin: str) -> None:
        value = value.strip()
        if not value:
            return
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(IOC(type=ioc_type, value=value, defanged=defang(value), origin=origin))

    # --- Sender infrastructure ---
    if email_obj.from_addr:
        add("email", email_obj.from_addr, "sender")
        dom = email_obj.from_addr.split("@")[-1]
        if dom:
            add("domain", registered_domain(dom), "sender")
    if email_obj.reply_to:
        add("email", email_obj.reply_to, "sender")
    if email_obj.return_path:
        add("email", email_obj.return_path, "sender")

    # Originating IPs from the received chain (sender infra).
    chain_text = "\n".join(email_obj.received_chain)
    for ip in _IPV4_RE.findall(chain_text):
        if not ip.startswith(_PRIVATE_IP_PREFIXES) and _valid_ipv4(ip):
            add("ipv4", ip, "sender")

    # --- Body / links ---
    body = "\n".join(filter(None, [email_obj.body_text, email_obj.body_html]))

    for url in _extract_urls(body):
        add("url", url, "body")
        host = _host_from_url(url)
        if host and not _IPV4_RE.fullmatch(host):
            add("domain", registered_domain(host), "body")
        elif host:
            add("ipv4", host, "body")

    for ip in _IPV4_RE.findall(body):
        if not ip.startswith(_PRIVATE_IP_PREFIXES) and _valid_ipv4(ip):
            add("ipv4", ip, "body")
    for ip in _IPV6_RE.findall(body):
        add("ipv6", ip, "body")

    # Standalone domains in the body (after URLs so URL hosts win the dedupe).
    for dom in _DOMAIN_RE.findall(body):
        rd = registered_domain(dom)
        if rd and "." in rd:
            add("domain", rd, "body")

    # Hashes mentioned in the body (rare, but cheap to catch).
    for htype, rx in _HASH_RES.items():
        for h in rx.findall(body):
            add(htype, h.lower(), "body")

    return out


def _valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Lookalike / typosquat detection
# ---------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_domains(
    domains: Iterable[str], brands: Iterable[str]
) -> list[tuple[str, str]]:
    """Return (suspicious_domain, brand) where the domain is a near-miss of a
    brand domain but not an exact match — classic typosquatting."""

    hits: list[tuple[str, str]] = []
    brand_list = [b.lower() for b in brands]
    for d in {x.lower() for x in domains}:
        for b in brand_list:
            if d == b:
                continue
            d_core = d.split(".")[0]
            b_core = b.split(".")[0]
            dist = levenshtein(d_core, b_core)
            if 0 < dist <= 2 and abs(len(d_core) - len(b_core)) <= 2:
                hits.append((d, b))
                break
    return hits
