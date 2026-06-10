"""FR2 — Header analysis.

Three jobs, all producing ``Finding`` objects the scorer can consume:

1. Authentication results (SPF / DKIM / DMARC) from ``Authentication-Results``.
2. Trace the ``Received:`` chain to the earliest originating IP / host.
3. Spoofing signals: From vs Return-Path vs Reply-To domain mismatches, and
   display-name impersonation of well-known brands.

Pure functions where possible so they are easy to unit-test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .models import EmailObject, Finding

# MITRE technique reused across spoofing findings.
PHISHING = "T1566"

# Brands commonly impersonated in display-name spoofing.
KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "office365": ["microsoft.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "hmrc": ["hmrc.gov.uk", "gov.uk"],
    "dpd": ["dpd.co.uk", "dpd.com"],
    "linkedin": ["linkedin.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "coinbase": ["coinbase.com"],
}

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "169.254.")

# Free webmail providers — legitimate for individuals, a red flag when the
# display name claims to be a company executive (classic BEC).
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "yahoo.co.uk", "aol.com", "icloud.com", "protonmail.com",
    "proton.me", "gmx.com", "mail.com", "yandex.com", "zoho.com",
}

# Authority/executive titles that attackers impersonate in BEC lures.
_EXEC_TITLES = re.compile(
    r"\b(ceo|cfo|coo|cto|president|vice president|vp|director|managing director|"
    r"chair(man|woman|person)?|owner|founder|head of|finance|accounts payable|payroll)\b",
    re.I,
)


@dataclass
class AuthResult:
    spf: str = "none"      # pass | fail | softfail | neutral | none
    dkim: str = "none"     # pass | fail | none
    dmarc: str = "none"    # pass | fail | none

    def to_dict(self) -> dict[str, str]:
        return {"spf": self.spf, "dkim": self.dkim, "dmarc": self.dmarc}


# ---------------------------------------------------------------------------
# 1. Authentication-Results parsing
# ---------------------------------------------------------------------------
def parse_auth_results(raw: str) -> AuthResult:
    """Extract spf/dkim/dmarc verdicts from a raw Authentication-Results blob.

    Tolerant of formatting variations like ``spf=pass`` / ``spf =pass`` and
    multiple header instances joined by newlines.
    """

    res = AuthResult()
    if not raw:
        return res
    text = raw.lower()

    def grab(mech: str) -> Optional[str]:
        m = re.search(mech + r"\s*=\s*([a-z]+)", text)
        return m.group(1) if m else None

    res.spf = grab("spf") or "none"
    res.dkim = grab("dkim") or "none"
    res.dmarc = grab("dmarc") or "none"
    return res


def auth_findings(auth: AuthResult, weights: dict[str, int]) -> list[Finding]:
    out: list[Finding] = []
    if auth.spf in ("fail", "softfail"):
        out.append(
            Finding("SPF_FAIL", f"SPF authentication {auth.spf}",
                    weights["SPF_FAIL"], [PHISHING])
        )
    if auth.dkim == "fail":
        out.append(
            Finding("DKIM_FAIL", "DKIM signature invalid/absent",
                    weights["DKIM_FAIL"], [PHISHING])
        )
    if auth.dmarc == "fail":
        out.append(
            Finding("DMARC_FAIL", "DMARC policy failed",
                    weights["DMARC_FAIL"], [PHISHING])
        )
    return out


# ---------------------------------------------------------------------------
# 2. Received chain -> originating IP
# ---------------------------------------------------------------------------
def originating_ip(received_chain: list[str]) -> Optional[str]:
    """The earliest hop is the last ``Received:`` header. Return the first
    public IPv4 found there, falling back to any public IP in the chain."""

    if not received_chain:
        return None

    def public_ips(line: str) -> list[str]:
        return [ip for ip in _IPV4.findall(line)
                if not ip.startswith(_PRIVATE_PREFIXES)]

    # Earliest hop first.
    for line in reversed(received_chain):
        ips = public_ips(line)
        if ips:
            return ips[0]
    # Fallback: anything public anywhere.
    for line in reversed(received_chain):
        for ip in _IPV4.findall(line):
            if not ip.startswith(_PRIVATE_PREFIXES):
                return ip
    return None


# ---------------------------------------------------------------------------
# 3. Spoofing signals
# ---------------------------------------------------------------------------
def _domain(addr: str) -> str:
    return addr.split("@")[-1].strip().lower() if addr and "@" in addr else ""


def spoof_findings(email_obj: EmailObject, weights: dict[str, int]) -> list[Finding]:
    out: list[Finding] = []

    from_dom = _domain(email_obj.from_addr)
    rp_dom = _domain(email_obj.return_path)
    reply_dom = _domain(email_obj.reply_to)

    # Envelope (Return-Path) vs header From mismatch.
    if from_dom and rp_dom and from_dom != rp_dom:
        out.append(
            Finding(
                "ENVELOPE_MISMATCH",
                f"Envelope sender domain ({rp_dom}) differs from From ({from_dom})",
                weights["ENVELOPE_MISMATCH"],
                [PHISHING],
            )
        )

    # Reply-To pointing somewhere else (classic redirect).
    if from_dom and reply_dom and reply_dom != from_dom:
        out.append(
            Finding(
                "REPLYTO_MISMATCH",
                f"Reply-To domain ({reply_dom}) differs from From ({from_dom})",
                weights["ENVELOPE_MISMATCH"],
                [PHISHING],
            )
        )
    # Same domain but different local-part on Reply-To — answers route to a
    # different mailbox than the apparent sender (BEC payment-redirect tell).
    elif from_dom and reply_dom and reply_dom == from_dom:
        from_local = (email_obj.from_addr.split("@")[0] or "").lower()
        reply_local = (email_obj.reply_to.split("@")[0] or "").lower()
        if from_local and reply_local and from_local != reply_local:
            out.append(
                Finding(
                    "REPLYTO_LOCALPART_MISMATCH",
                    f"Reply-To routes to a different mailbox ({reply_local}@) "
                    f"than the sender ({from_local}@) on the same domain",
                    weights["ENVELOPE_MISMATCH"],
                    [PHISHING],
                )
            )

    # Display-name brand impersonation.
    f = display_name_spoof(email_obj.from_display, from_dom)
    if f:
        out.append(Finding(f[0], f[1], weights["DISPLAY_NAME_SPOOF"], [PHISHING]))

    # Executive impersonation from free webmail (BEC without a payload).
    # Check the display name AND the address local-part, since friendly-name
    # parsers may strip a parenthetical title like "Jane Smith (CEO)".
    from_local = email_obj.from_addr.split("@")[0] if email_obj.from_addr else ""
    exec_text = f"{email_obj.from_display} {from_local}"
    if _EXEC_TITLES.search(exec_text) and from_dom in FREEMAIL_DOMAINS:
        who = email_obj.from_display or email_obj.from_addr
        out.append(
            Finding(
                "FREEMAIL_EXEC_IMPERSONATION",
                f"Sender implies an executive/authority role ('{who}') but is "
                f"sent from free webmail ({from_dom}) — common in business "
                f"email compromise",
                weights["DISPLAY_NAME_SPOOF"] + 5,
                [PHISHING],
            )
        )

    # Brand name embedded in the sending domain but not the brand's real domain
    # (e.g. 'docusign-secure-docs.com', 'paypal.account-verify.com').
    b = brand_in_domain(from_dom)
    if b:
        out.append(
            Finding(
                "BRAND_IN_DOMAIN",
                f"Sending domain '{from_dom}' embeds brand token '{b}' but is "
                f"not an official {b} domain",
                weights["LOOKALIKE_DOMAIN"],
                [PHISHING],
            )
        )

    return out


def brand_in_domain(from_domain: str) -> Optional[str]:
    """If a known brand name appears as a token inside the sending domain but
    the domain isn't one of the brand's legitimate domains, return the brand."""

    if not from_domain:
        return None
    core = from_domain.split(".")[0]  # label before the TLD's registered part
    label_parts = re.split(r"[-_.]", from_domain)
    for brand, legit_domains in KNOWN_BRANDS.items():
        if from_domain in legit_domains or any(
            from_domain.endswith("." + ld) for ld in legit_domains
        ):
            continue
        if brand in label_parts or brand in core:
            return brand
    return None


def display_name_spoof(display: str, from_domain: str) -> Optional[tuple[str, str]]:
    """If the friendly name claims a brand the sending domain doesn't match,
    return (code, reason). Otherwise None."""

    if not display:
        return None
    d = display.lower()
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in d:
            if not any(from_domain == ld or from_domain.endswith("." + ld)
                       for ld in legit_domains):
                return (
                    "DISPLAY_NAME_SPOOF",
                    f"Display name impersonates '{brand}' but sender domain "
                    f"is '{from_domain or 'unknown'}'",
                )
    return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def analyze_headers(
    email_obj: EmailObject, weights: dict[str, int]
) -> tuple[AuthResult, Optional[str], list[Finding]]:
    """Run all header checks. Returns (auth, originating_ip, findings)."""

    auth = parse_auth_results(email_obj.auth_results)
    src_ip = originating_ip(email_obj.received_chain)
    findings = auth_findings(auth, weights) + spoof_findings(email_obj, weights)
    return auth, src_ip, findings
