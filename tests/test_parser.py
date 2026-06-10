"""Parser tests (FR1): clean .eml, malformed headers, attachments."""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

from src.parser import parse_email


def test_parse_basic_eml(write_eml):
    p = write_eml(
        "clean.eml",
        {
            "From": "Alice <alice@example.com>",
            "To": "bob@example.org",
            "Subject": "Lunch?",
            "Reply-To": "alice@example.com",
        },
        body="See you at noon.",
    )
    obj = parse_email(p)
    assert obj.from_addr == "alice@example.com"
    assert obj.from_display == "Alice"
    assert obj.subject == "Lunch?"
    assert "noon" in obj.body_text
    assert obj.parse_warnings == []  # nothing missing


def test_missing_headers_do_not_crash(write_eml):
    # No From, no Date — must parse and record warnings, not raise.
    p = write_eml("broken.eml", {"Subject": "no sender"})
    obj = parse_email(p)
    assert obj.subject == "no sender"
    assert any("From" in w for w in obj.parse_warnings)


def test_attachment_extracted(tmp_path: Path):
    m = EmailMessage()
    m["From"] = "x@example.com"
    m["Subject"] = "doc"
    m["Date"] = "Wed, 10 Jun 2026 10:00:00 +0000"
    m.set_content("body")
    m.add_attachment(b"%PDF-1.4 fake", maintype="application",
                     subtype="pdf", filename="a.pdf")
    p = tmp_path / "att.eml"
    p.write_bytes(m.as_bytes())

    obj = parse_email(p)
    assert len(obj.attachments) == 1
    assert obj.attachments[0].filename == "a.pdf"
    assert obj.attachments[0].size > 0


def test_received_and_auth_headers_captured(write_eml):
    p = write_eml(
        "auth.eml",
        {
            "From": "x@example.com",
            "Subject": "s",
            "Received": "from a.example (a.example [203.0.113.1]) by mx",
            "Authentication-Results": "mx; spf=pass; dkim=pass; dmarc=pass",
        },
    )
    obj = parse_email(p)
    assert obj.received_chain and "203.0.113.1" in obj.received_chain[0]
    assert "spf=pass" in obj.auth_results
