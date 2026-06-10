"""Core data structures for the Phishing Email Analyzer.

Everything that flows through the pipeline (parse -> headers + iocs +
attachments -> enrich -> score -> report) is one of these dataclasses.
Kept deliberately simple and serialisable so the JSON report is trivial.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------
@dataclass
class Attachment:
    """A single attachment, kept in memory only (never written to disk in a
    location that could auto-open)."""

    filename: str
    content_type: str
    data: bytes = field(repr=False, default=b"")
    size: int = 0
    # Populated later by attachments.py
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    findings: list["Finding"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class EmailObject:
    """Structured, format-agnostic view of a parsed email (.eml or .msg)."""

    source_path: str = ""
    from_addr: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    received_chain: list[str] = field(default_factory=list)
    auth_results: str = ""  # raw Authentication-Results header(s)
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    # Anything we couldn't parse cleanly is recorded, never silently dropped.
    parse_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["attachments"] = [a.to_dict() for a in self.attachments]
        # Drop raw bytes / long bodies from the machine report for readability.
        d.pop("body_html", None)
        d["body_text"] = (self.body_text or "")[:2000]
        return d


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------
@dataclass
class IOC:
    """A single Indicator of Compromise. ``defanged`` is what we print;
    ``value`` is the live original (used for enrichment lookups)."""

    type: str  # url | domain | ipv4 | ipv6 | email | md5 | sha1 | sha256
    value: str
    defanged: str
    origin: str = "body"  # "sender" (infra) or "body" (links/content)
    enrichment: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Findings & scoring
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    """One scored observation. Every point in the final score traces back to
    one of these — that is what makes the verdict explainable."""

    code: str          # machine code, e.g. "SPF_FAIL"
    reason: str        # human-readable explanation
    weight: int        # points contributed
    mitre: list[str] = field(default_factory=list)  # ATT&CK technique IDs

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    """The full analysis result for one email."""

    email: EmailObject
    iocs: list[IOC] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    band: str = "Low"  # Low | Suspicious | Malicious
    mitre: list[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "verdict": {"score": self.score, "band": self.band},
            "email": self.email.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "iocs": [i.to_dict() for i in self.iocs],
            "mitre_attack": self.mitre,
        }
