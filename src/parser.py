"""FR1 — Email parsing.

Turn a ``.eml`` or ``.msg`` file into a single, format-agnostic
``EmailObject``. The guiding rule (CONTEXT.md hard rules): never crash on
malformed input — record what is missing in ``parse_warnings`` and carry on.
"""

from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from email.utils import parseaddr, getaddresses
from pathlib import Path

from .models import Attachment, EmailObject


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def parse_email(path: str | Path) -> EmailObject:
    """Auto-detect file type and parse. Falls back from extension to content
    sniffing so a mislabelled file still works."""

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No such file: {p}")

    raw = p.read_bytes()
    suffix = p.suffix.lower()

    is_msg = suffix == ".msg" or raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    if is_msg:
        return _parse_msg(p, raw)
    return _parse_eml(p, raw)


# ---------------------------------------------------------------------------
# .eml
# ---------------------------------------------------------------------------
def _parse_eml(path: Path, raw: bytes) -> EmailObject:
    obj = EmailObject(source_path=str(path))
    try:
        msg: EmailMessage = email.message_from_bytes(raw, policy=policy.default)
    except Exception as exc:  # extremely malformed; degrade to compat policy
        obj.parse_warnings.append(f"strict parse failed ({exc}); retried compat")
        msg = email.message_from_bytes(raw, policy=policy.compat32)

    _fill_headers(obj, msg)
    _fill_bodies_and_attachments(obj, msg)
    return obj


def _fill_headers(obj: EmailObject, msg: EmailMessage) -> None:
    def h(name: str) -> str:
        try:
            v = msg.get(name)
            return str(v) if v is not None else ""
        except Exception:
            return ""

    raw_from = h("From")
    obj.from_display, obj.from_addr = parseaddr(raw_from)
    obj.reply_to = parseaddr(h("Reply-To"))[1]
    obj.return_path = parseaddr(h("Return-Path"))[1]
    obj.to = ", ".join(a for _, a in getaddresses([h("To")]) if a)
    obj.subject = h("Subject")
    obj.date = h("Date")

    # Received chain — preserved top-to-bottom as it appears in the header.
    try:
        obj.received_chain = [str(v) for v in msg.get_all("Received", [])]
    except Exception:
        obj.received_chain = []

    # Authentication-Results may appear multiple times.
    try:
        ar = msg.get_all("Authentication-Results", [])
        obj.auth_results = "\n".join(str(v) for v in ar)
    except Exception:
        obj.auth_results = ""

    for needed in ("From", "Date"):
        if not h(needed):
            obj.parse_warnings.append(f"missing header: {needed}")


def _fill_bodies_and_attachments(obj: EmailObject, msg: EmailMessage) -> None:
    try:
        body = msg.get_body(preferencelist=("plain",))
        if body is not None:
            obj.body_text = body.get_content()
    except Exception as exc:
        obj.parse_warnings.append(f"text body extraction failed: {exc}")

    try:
        html = msg.get_body(preferencelist=("html",))
        if html is not None:
            obj.body_html = html.get_content()
    except Exception:
        pass

    # Attachments — kept in memory only.
    try:
        for part in msg.iter_attachments():
            filename = part.get_filename() or "unnamed"
            try:
                data = part.get_content()
                if isinstance(data, str):
                    data = data.encode("utf-8", errors="replace")
            except Exception:
                data = part.get_payload(decode=True) or b""
            obj.attachments.append(
                Attachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    data=data,
                    size=len(data),
                )
            )
    except Exception as exc:
        obj.parse_warnings.append(f"attachment extraction failed: {exc}")


# ---------------------------------------------------------------------------
# .msg  (Outlook) — normalise into the same EmailObject
# ---------------------------------------------------------------------------
def _parse_msg(path: Path, raw: bytes) -> EmailObject:
    obj = EmailObject(source_path=str(path))
    try:
        import extract_msg  # type: ignore
    except ImportError:
        obj.parse_warnings.append(
            "extract-msg not installed; cannot parse .msg (pip install extract-msg)"
        )
        return obj

    try:
        m = extract_msg.Message(str(path))
    except Exception as exc:
        obj.parse_warnings.append(f".msg parse failed: {exc}")
        return obj

    raw_from = m.sender or ""
    obj.from_display, obj.from_addr = parseaddr(raw_from)
    if not obj.from_addr and "@" in raw_from:
        obj.from_addr = raw_from.strip()
    obj.to = m.to or ""
    obj.subject = m.subject or ""
    obj.date = str(m.date or "")
    obj.body_text = m.body or ""
    try:
        obj.body_html = (m.htmlBody or b"").decode("utf-8", "replace") if isinstance(
            m.htmlBody, bytes
        ) else (m.htmlBody or "")
    except Exception:
        obj.body_html = ""

    # Outlook keeps transport headers as a single blob; reuse the email parser
    # to pull Received / Authentication-Results / Reply-To / Return-Path out.
    headers_blob = getattr(m, "header", None)
    if headers_blob is not None:
        try:
            hdr = email.message_from_string(str(headers_blob), policy=policy.default)
            obj.received_chain = [str(v) for v in hdr.get_all("Received", [])]
            obj.auth_results = "\n".join(
                str(v) for v in hdr.get_all("Authentication-Results", [])
            )
            obj.reply_to = parseaddr(str(hdr.get("Reply-To", "")))[1]
            obj.return_path = parseaddr(str(hdr.get("Return-Path", "")))[1]
            if not obj.from_addr:
                obj.from_display, obj.from_addr = parseaddr(str(hdr.get("From", "")))
        except Exception as exc:
            obj.parse_warnings.append(f".msg header blob parse failed: {exc}")
    else:
        obj.parse_warnings.append(".msg has no transport headers (auth checks limited)")

    try:
        for att in m.attachments:
            data = att.data if isinstance(att.data, bytes) else b""
            name = att.longFilename or att.shortFilename or "unnamed"
            obj.attachments.append(
                Attachment(
                    filename=name,
                    content_type="application/octet-stream",
                    data=data,
                    size=len(data),
                )
            )
    except Exception as exc:
        obj.parse_warnings.append(f".msg attachment extraction failed: {exc}")

    return obj
