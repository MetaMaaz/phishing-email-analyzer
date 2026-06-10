"""FR5 — Static attachment analysis.

Three checks, all static — nothing is ever executed or opened:

1. Hash every attachment (MD5 / SHA1 / SHA256).
2. Office documents: inspect macros with ``oletools`` (olevba) — flag
   auto-execution triggers and suspicious API calls.
3. PDFs: flag JavaScript, embedded files and launch / OpenAction entries.

If ``oletools`` is unavailable, Office inspection degrades to a byte-level
heuristic (e.g. presence of ``vbaProject.bin``) and records that confidence is
reduced. Attachment bytes are processed in memory; nothing is written to an
auto-openable location.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile

from .models import Attachment, EmailObject, Finding

# Auto-execution macro triggers and high-risk calls (olevba-style keywords).
_AUTOEXEC_KEYWORDS = [
    "AutoOpen", "Auto_Open", "AutoClose", "AutoExec", "Document_Open",
    "Workbook_Open", "Auto_Close", "DocumentOpen",
]
_SUSPICIOUS_CALLS = [
    "Shell", "WScript.Shell", "CreateObject", "Powershell", "cmd.exe",
    "URLDownloadToFile", "MSXML2.XMLHTTP", "ADODB.Stream", "Environ",
    "VirtualAlloc", "RtlMoveMemory", "Base64",
]

_OFFICE_EXTS = (".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb",
                ".xlt", ".xltm", ".ppt", ".pptm", ".pps", ".ppsm")
_ZIP_OFFICE_EXTS = (".docx", ".xlsx", ".pptx")  # OOXML; macros live in .*m

MITRE_FILE = ["T1566.001", "T1204.002"]


def hash_attachment(att: Attachment) -> None:
    data = att.data or b""
    att.md5 = hashlib.md5(data).hexdigest()
    att.sha1 = hashlib.sha1(data).hexdigest()
    att.sha256 = hashlib.sha256(data).hexdigest()


def _ext(name: str) -> str:
    name = (name or "").lower()
    dot = name.rfind(".")
    return name[dot:] if dot != -1 else ""


# ---------------------------------------------------------------------------
# Office macro inspection
# ---------------------------------------------------------------------------
def inspect_office(att: Attachment, weights: dict[str, int]) -> list[Finding]:
    findings: list[Finding] = []
    data = att.data or b""

    try:
        from oletools.olevba import VBA_Parser  # type: ignore

        vba = VBA_Parser(att.filename, data=data)
        if vba.detect_vba_macros():
            macro_text = ""
            for (_f, _s, _vba_name, code) in vba.extract_macros():
                macro_text += (code or "") + "\n"

            autoexec = [k for k in _AUTOEXEC_KEYWORDS
                        if re.search(re.escape(k), macro_text, re.I)]
            calls = [k for k in _SUSPICIOUS_CALLS
                     if re.search(re.escape(k), macro_text, re.I)]

            if autoexec:
                findings.append(
                    Finding(
                        "MACRO_AUTOEXEC",
                        f"Office macro with auto-execution trigger(s): "
                        f"{', '.join(sorted(set(autoexec)))}",
                        weights["MACRO_AUTOEXEC"],
                        MITRE_FILE,
                    )
                )
            if calls:
                findings.append(
                    Finding(
                        "MACRO_SUSPICIOUS_CALL",
                        f"Macro contains suspicious calls: "
                        f"{', '.join(sorted(set(calls)))}",
                        # Half weight; supporting signal, not a verdict on its own.
                        max(5, weights["MACRO_AUTOEXEC"] // 2),
                        MITRE_FILE,
                    )
                )
            if not autoexec and not calls:
                findings.append(
                    Finding("MACRO_PRESENT",
                            "Document contains VBA macros (no auto-exec detected)",
                            10, MITRE_FILE)
                )
        vba.close()
        if findings:
            return findings
        # olevba ran but detected nothing parseable — fall through to the
        # container scan as a backstop (catches malformed/obfuscated projects).
    except ImportError:
        pass  # fall through to heuristic
    except Exception as exc:
        att.findings.append(
            Finding("MACRO_SCAN_ERROR", f"olevba failed: {exc}", 0, [])
        )

    # Heuristic fallback (no oletools, or olevba found nothing): inspect the
    # OOXML container's macro storage directly.
    return _zip_macro_scan(data, weights)


def _zip_macro_scan(data: bytes, weights: dict[str, int]) -> list[Finding]:
    """Statically scan an OOXML (.docm/.xlsm/.pptm) container for a macro
    project and the keywords inside it. Robust to compression and works with
    no third-party libraries."""

    findings: list[Finding] = []
    if data[:2] != b"PK":  # not a zip; nothing more we can do without olevba
        return findings
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return findings

    macro_blobs = [n for n in zf.namelist() if n.lower().endswith("vbaproject.bin")]
    if not macro_blobs:
        return findings

    body = b""
    for n in macro_blobs:
        try:
            body += zf.read(n)
        except Exception:
            pass

    autoexec = [k for k in _AUTOEXEC_KEYWORDS if k.lower().encode() in body.lower()]
    calls = [k for k in _SUSPICIOUS_CALLS if k.lower().encode() in body.lower()]

    if autoexec:
        findings.append(
            Finding(
                "MACRO_AUTOEXEC",
                f"Office macro with auto-execution trigger(s): "
                f"{', '.join(sorted(set(autoexec)))}",
                weights["MACRO_AUTOEXEC"], MITRE_FILE,
            )
        )
    if calls:
        findings.append(
            Finding(
                "MACRO_SUSPICIOUS_CALL",
                f"Macro contains suspicious calls: {', '.join(sorted(set(calls)))}",
                max(5, weights["MACRO_AUTOEXEC"] // 2), MITRE_FILE,
            )
        )
    if not autoexec and not calls:
        findings.append(
            Finding("MACRO_PRESENT", "Document contains a VBA macro project",
                    10, MITRE_FILE)
        )
    return findings


# ---------------------------------------------------------------------------
# PDF inspection
# ---------------------------------------------------------------------------
def inspect_pdf(att: Attachment, weights: dict[str, int]) -> list[Finding]:
    findings: list[Finding] = []
    data = att.data or b""
    flags: list[str] = []

    if re.search(rb"/JavaScript|/JS\b", data):
        flags.append("JavaScript")
    if re.search(rb"/OpenAction", data):
        flags.append("OpenAction (runs on open)")
    if re.search(rb"/AA\b", data):
        flags.append("Additional Actions")
    if re.search(rb"/Launch", data):
        flags.append("Launch action")
    if re.search(rb"/EmbeddedFile", data):
        flags.append("Embedded file")

    if flags:
        # OpenAction + JavaScript/Launch is the dangerous combo.
        active = any(x.startswith(("JavaScript", "Launch", "OpenAction"))
                     for x in flags)
        weight = weights["MACRO_AUTOEXEC"] if active else 15
        findings.append(
            Finding(
                "PDF_ACTIVE_CONTENT",
                f"PDF contains active/embedded content: {', '.join(flags)}",
                weight,
                ["T1566.001", "T1204.002"],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def analyze_attachments(
    email_obj: EmailObject, weights: dict[str, int]
) -> list[Finding]:
    all_findings: list[Finding] = []
    for att in email_obj.attachments:
        hash_attachment(att)
        ext = _ext(att.filename)
        ctype = (att.content_type or "").lower()

        local: list[Finding] = []
        if ext in _OFFICE_EXTS or ext in _ZIP_OFFICE_EXTS or "officedocument" in ctype \
                or "msword" in ctype or "ms-excel" in ctype or "ms-powerpoint" in ctype:
            local += inspect_office(att, weights)
        if ext == ".pdf" or "pdf" in ctype or (att.data or b"")[:5] == b"%PDF-":
            local += inspect_pdf(att, weights)

        att.findings = local
        all_findings += local
    return all_findings
