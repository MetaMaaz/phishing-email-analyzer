"""FR7 — Reporting (Markdown for humans, JSON for machines).

The Markdown report is structured exactly like a SOC triage note so it reads
the way a recruiter or senior analyst expects:
Summary/verdict -> Authentication -> Spoofing -> IOCs -> Attachments ->
Score breakdown -> MITRE ATT&CK.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .headers import AuthResult
from .models import IOC, Report

# ATT&CK technique reference (SPEC.md §8).
MITRE_MAP = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
}

_BAND_EMOJI = {"Low": "🟢", "Suspicious": "🟠", "Malicious": "🔴"}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def render_markdown(
    report: Report,
    auth: Optional[AuthResult] = None,
    originating_ip: Optional[str] = None,
) -> str:
    e = report.email
    band = report.band
    emoji = _BAND_EMOJI.get(band, "")
    lines: list[str] = []

    # --- Summary / verdict ---
    lines.append(f"# Phishing Triage Report — {emoji} {band}")
    lines.append("")
    lines.append(f"**Risk score:** {report.score}/100  ·  **Verdict:** {band}")
    lines.append(f"**Generated:** {report.generated_at}")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| From | `{e.from_display}` <{e.from_addr or 'unknown'}> |")
    lines.append(f"| Reply-To | {e.reply_to or '—'} |")
    lines.append(f"| Return-Path | {e.return_path or '—'} |")
    lines.append(f"| To | {e.to or '—'} |")
    lines.append(f"| Subject | {e.subject or '—'} |")
    lines.append(f"| Date | {e.date or '—'} |")
    lines.append(f"| Attachments | {len(e.attachments)} |")
    if originating_ip:
        lines.append(f"| Originating IP | `{originating_ip}` |")
    lines.append("")

    if e.parse_warnings:
        lines.append("> ⚠️ Parse notes: " + "; ".join(e.parse_warnings))
        lines.append("")

    # --- Authentication ---
    lines.append("## Authentication")
    lines.append("")
    if auth is not None:
        lines.append("| Mechanism | Result |")
        lines.append("|-----------|--------|")
        lines.append(f"| SPF | {_mark(auth.spf)} |")
        lines.append(f"| DKIM | {_mark(auth.dkim)} |")
        lines.append(f"| DMARC | {_mark(auth.dmarc)} |")
    else:
        lines.append("_No Authentication-Results header present._")
    lines.append("")

    # --- Spoofing signals ---
    lines.append("## Spoofing signals")
    lines.append("")
    spoof = [f for f in report.findings
             if f.code in ("ENVELOPE_MISMATCH", "REPLYTO_MISMATCH",
                           "REPLYTO_LOCALPART_MISMATCH", "DISPLAY_NAME_SPOOF",
                           "FREEMAIL_EXEC_IMPERSONATION", "BRAND_IN_DOMAIN",
                           "LOOKALIKE_DOMAIN")]
    if spoof:
        for f in spoof:
            lines.append(f"- **{f.code}** — {f.reason}")
    else:
        lines.append("_None detected._")
    lines.append("")

    # --- IOCs ---
    lines.append("## Indicators of Compromise (defanged)")
    lines.append("")
    lines.extend(_ioc_section("Sender infrastructure",
                              [i for i in report.iocs if i.origin == "sender"]))
    lines.extend(_ioc_section("Body / links",
                              [i for i in report.iocs if i.origin == "body"]))
    att_iocs = [i for i in report.iocs if i.origin == "attachment"]
    if att_iocs:
        lines.extend(_ioc_section("Attachment hashes", att_iocs))

    # --- Attachments ---
    lines.append("## Attachments")
    lines.append("")
    if e.attachments:
        lines.append("| Name | Type | Size | SHA256 |")
        lines.append("|------|------|-----:|--------|")
        for a in e.attachments:
            sha = (a.sha256 or "—")
            sha_short = sha[:16] + "…" if len(sha) > 16 else sha
            lines.append(
                f"| `{a.filename}` | {a.content_type} | {a.size} | `{sha_short}` |"
            )
        lines.append("")
        for a in e.attachments:
            if a.findings:
                lines.append(f"**`{a.filename}` findings:**")
                for f in a.findings:
                    lines.append(f"- {f.reason} (+{f.weight})")
                lines.append("")
    else:
        lines.append("_No attachments._")
        lines.append("")

    # --- Score breakdown ---
    lines.append("## Score breakdown")
    lines.append("")
    if report.findings:
        lines.append("| Signal | Points | Reason |")
        lines.append("|--------|-------:|--------|")
        for f in sorted(report.findings, key=lambda x: -x.weight):
            lines.append(f"| {f.code} | +{f.weight} | {f.reason} |")
        lines.append(f"| **Total (capped at 100)** | **{report.score}** | "
                     f"**{band}** |")
    else:
        lines.append("_No scoring signals fired — nothing suspicious detected._")
    lines.append("")

    # --- MITRE ---
    lines.append("## MITRE ATT&CK mapping")
    lines.append("")
    if report.mitre:
        lines.append("| Technique | ID |")
        lines.append("|-----------|-----|")
        for tid in report.mitre:
            lines.append(f"| {MITRE_MAP.get(tid, 'Unknown')} | {tid} |")
    else:
        lines.append("_No techniques mapped._")
    lines.append("")
    lines.append("---")
    lines.append("_Static analysis only — no attachment was executed or "
                 "detonated. Generated by Phishing Email Analyzer._")
    lines.append("")
    return "\n".join(lines)


def _mark(result: str) -> str:
    r = (result or "none").lower()
    icon = {"pass": "✅", "fail": "❌", "softfail": "⚠️",
            "neutral": "➖", "none": "➖"}.get(r, "➖")
    return f"{icon} {r}"


def _ioc_section(title: str, iocs: list[IOC]) -> list[str]:
    out = [f"### {title}", ""]
    if not iocs:
        out.append("_None._")
        out.append("")
        return out
    out.append("| Type | Indicator |")
    out.append("|------|-----------|")
    for i in iocs:
        out.append(f"| {i.type} | `{i.defanged}` |")
    out.append("")
    return out


# ---------------------------------------------------------------------------
# Writing to disk
# ---------------------------------------------------------------------------
def write_reports(
    report: Report,
    out_dir: str | Path,
    stem: str,
    auth: Optional[AuthResult] = None,
    originating_ip: Optional[str] = None,
) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    md_path = out / f"{stem}.md"
    json_path = out / f"{stem}.json"
    md_path.write_text(render_markdown(report, auth, originating_ip), encoding="utf-8")
    json_path.write_text(render_json(report), encoding="utf-8")
    return md_path, json_path
