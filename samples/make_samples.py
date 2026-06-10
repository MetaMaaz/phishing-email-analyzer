"""Generate SAFE, synthetic phishing samples for testing and the case studies.

These are entirely fabricated. No real malware, no live malicious URLs — the
"bad" domains use RFC-2606 / obviously-fake hosts and the macro doc carries an
inert VBA body that is never executed (static analysis only). Run:

    python samples/make_samples.py

It writes .eml files into the same folder. ``samples/`` is gitignored, so
these never reach a public repo; the README describes them instead.
"""

from __future__ import annotations

import zipfile
from email.message import EmailMessage
from email.utils import formatdate
from io import BytesIO
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _base(subject: str, from_hdr: str) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = from_hdr
    m["To"] = "victim@example.com"
    m["Date"] = formatdate(localtime=True)
    return m


def _write(m: EmailMessage, name: str) -> None:
    (HERE / name).write_bytes(m.as_bytes())
    print("wrote", name)


# ---------------------------------------------------------------------------
# 1. Fake invoice (attachment lure) — PDF with OpenAction + JavaScript
# ---------------------------------------------------------------------------
def fake_invoice() -> None:
    m = _base("Invoice INV-90871 overdue - action required",
              "Accounts Payable <billing@acccounts-payable-portal.com>")
    m["Reply-To"] = "billing@acccounts-payable-portal.com"
    m["Return-Path"] = "<bounce@mailer-xyz.ru>"
    m["Authentication-Results"] = (
        "mx.example.com; spf=fail smtp.mailfrom=mailer-xyz.ru; "
        "dkim=none; dmarc=fail header.from=acccounts-payable-portal.com"
    )
    m["Received"] = (
        "from mailer-xyz.ru (mailer-xyz.ru [203.0.113.66]) "
        "by mx.example.com with ESMTP id ABC123; " + formatdate()
    )
    m.set_content(
        "Dear Customer,\n\nYour invoice INV-90871 is overdue. Please review the "
        "attached PDF and pay immediately to avoid a late fee.\n\n"
        "View account: http://acccounts-payable-portal.com/pay?id=90871\n\n"
        "Regards,\nAccounts Payable"
    )
    # Minimal PDF carrying active-content markers (inert, never opened).
    pdf = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj\n"
        b"2 0 obj<</S/JavaScript/JS(app.alert\\('inert sample'\\);)>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF"
    )
    m.add_attachment(pdf, maintype="application", subtype="pdf",
                     filename="Invoice_INV-90871.pdf")
    _write(m, "01_fake_invoice.eml")


# ---------------------------------------------------------------------------
# 2. Credential harvesting — lookalike Microsoft login link
# ---------------------------------------------------------------------------
def credential_harvest() -> None:
    m = _base("Your mailbox is almost full - re-verify now",
              "Microsoft 365 <no-reply@micros0ft-support.com>")
    m["Reply-To"] = "no-reply@micros0ft-support.com"
    m["Return-Path"] = "<no-reply@micros0ft-support.com>"
    m["Authentication-Results"] = (
        "mx.example.com; spf=softfail smtp.mailfrom=micros0ft-support.com; "
        "dkim=none; dmarc=fail"
    )
    m["Received"] = (
        "from vps-cheap-host (unknown [198.51.100.23]) by mx.example.com "
        "with ESMTP; " + formatdate()
    )
    m.set_content(
        "Action required: your Microsoft 365 mailbox is 99% full.\n\n"
        "Re-verify your account within 24 hours or lose access:\n"
        "https://login.micros0ft-support.com/owa/verify?u=victim\n\n"
        "Microsoft 365 Team"
    )
    m.add_alternative(
        "<html><body><p>Your <b>Microsoft 365</b> mailbox is full.</p>"
        "<p><a href=\"https://login.micros0ft-support.com/owa/verify?u=victim\">"
        "Re-verify now</a></p></body></html>",
        subtype="html",
    )
    _write(m, "02_credential_harvest.eml")


# ---------------------------------------------------------------------------
# 3. Malware attachment — macro-enabled Office doc (inert VBA)
# ---------------------------------------------------------------------------
def macro_doc() -> None:
    m = _base("Salary review document - enable content to view",
              "HR Department <hr@company-hr-portal.net>")
    m["Return-Path"] = "<hr@company-hr-portal.net>"
    m["Authentication-Results"] = (
        "mx.example.com; spf=fail; dkim=fail; dmarc=fail")
    m["Received"] = (
        "from smtp.bad-host.tk (smtp.bad-host.tk [192.0.2.155]) "
        "by mx.example.com; " + formatdate()
    )
    m.set_content(
        "Please open the attached document and ENABLE CONTENT to view your "
        "confidential salary review.\n\nHR Department"
    )
    # Build a tiny .docm-like OOXML zip with a vbaProject.bin containing an
    # INERT VBA source string. This is detected statically; nothing runs.
    inert_vba = (
        b"Attribute VB_Name = \"Module1\"\r\n"
        b"Sub AutoOpen()\r\n"
        b"  ' INERT SAMPLE - does nothing, for static-analysis testing only\r\n"
        b"  Dim s As String\r\n"
        b"  s = \"Shell\"  ' suspicious-keyword marker, not a real call\r\n"
        b"End Sub\r\n"
    )
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats'
                   '.org/package/2006/content-types"/>')
        # Store the macro project uncompressed so the static keyword scan can
        # read it without a full OLE parser (mirrors a real vbaProject.bin).
        z.writestr(
            zipfile.ZipInfo("word/vbaProject.bin"), inert_vba,
            compress_type=zipfile.ZIP_STORED,
        )
        z.writestr("word/document.xml",
                   '<?xml version="1.0"?><document>salary</document>')
    m.add_attachment(
        buf.getvalue(),
        maintype="application",
        subtype="vnd.ms-word.document.macroEnabled.12",
        filename="Salary_Review.docm",
    )
    _write(m, "03_macro_attachment.eml")


# ---------------------------------------------------------------------------
# 4. BEC — display-name spoof of the CEO, no payload
# ---------------------------------------------------------------------------
def bec() -> None:
    m = _base("Quick task",
              '"Jane Smith, CEO" <jane.smith.ceo@gmail.com>')
    m["Reply-To"] = "jane.smith.payments@gmail.com"
    m["Return-Path"] = "<jane.smith.ceo@gmail.com>"
    m["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=gmail.com; "
        "dkim=pass header.d=gmail.com; dmarc=pass")
    m["Received"] = (
        "from mail-sor-f41.google.com (mail-sor-f41.google.com "
        "[209.85.220.41]) by mx.example.com; " + formatdate()
    )
    m.set_content(
        "Hi,\n\nAre you at your desk? I need you to process an urgent vendor "
        "payment before 3pm. It's time-sensitive and confidential — reply here "
        "and I'll send the bank details.\n\nSent from my iPhone\nJane"
    )
    _write(m, "04_bec_ceo_fraud.eml")


# ---------------------------------------------------------------------------
# 5. AI-generated phishing — clean grammar, topical lure, lookalike link
# ---------------------------------------------------------------------------
def ai_phish() -> None:
    m = _base("Your recent DocuSign envelope is ready to view",
              "DocuSign <notify@docusign-secure-docs.com>")
    m["Reply-To"] = "notify@docusign-secure-docs.com"
    m["Return-Path"] = "<notify@docusign-secure-docs.com>"
    m["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=docusign-secure-docs.com; "
        "dkim=pass header.d=docusign-secure-docs.com; dmarc=pass")
    m["Received"] = (
        "from sendgrid.net (o1.ptr1234.docusign-secure-docs.com "
        "[167.89.12.34]) by mx.example.com; " + formatdate()
    )
    m.set_content(
        "Hello,\n\nA new document requires your signature. The envelope was "
        "sent to you by your finance team and will expire in 48 hours.\n\n"
        "Review and sign securely:\n"
        "https://app.docusign-secure-docs.com/sign?env=8842\n\n"
        "Thank you for using DocuSign. This message was sent to a monitored "
        "address; please do not reply.\n\nThe DocuSign Team"
    )
    _write(m, "05_ai_generated_phish.eml")


if __name__ == "__main__":
    fake_invoice()
    credential_harvest()
    macro_doc()
    bec()
    ai_phish()
    print("\nDone. 5 synthetic samples in", HERE)
