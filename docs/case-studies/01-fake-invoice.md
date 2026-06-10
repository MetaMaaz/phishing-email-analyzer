# Case study 1 — Fake invoice (attachment lure)

**Sample:** `samples/01_fake_invoice.eml`
**Verdict:** 🔴 Malicious — 85/100

## What I saw

An "overdue invoice" email pressuring the recipient to open an attached PDF and
pay immediately. The display name is "Accounts Payable", the sending domain is
`acccounts-payable-portal.com` (note the triple-c misspelling of "accounts"),
and there's a single PDF attachment named `Invoice_INV-90871.pdf`.

The classic shape of this lure: an unpaid-bill subject line, urgency ("avoid a
late fee"), and a document the victim is expected to open without thinking.

## How I analysed it

Headers first. The `Authentication-Results` header tells the story before I even
look at the body:

```
spf=fail smtp.mailfrom=mailer-xyz.ru
dkim=none
dmarc=fail header.from=acccounts-payable-portal.com
```

SPF failed, there's no DKIM signature, and DMARC failed. On top of that the
envelope sender (`Return-Path: bounce@mailer-xyz.ru`) is a completely different
domain — and a different country's TLD — from the `From` domain. That's an
envelope mismatch: the mail claims to be from the billing portal but was
actually injected from `mailer-xyz.ru`. Tracing the `Received:` chain gives the
originating IP `203.0.113.66`, which matches that `.ru` infrastructure.

Then the attachment. Static inspection of the PDF (no opening it) finds an
`/OpenAction` entry pointing at `/JavaScript` — meaning the PDF is built to run
script the moment it's opened. That's not how a real invoice behaves.

## Score breakdown

| Signal | Points |
|--------|-------:|
| PDF with active content (JavaScript + OpenAction) | +30 |
| SPF fail | +20 |
| DMARC fail | +20 |
| Envelope (Return-Path) mismatch | +15 |
| **Total** | **85 — Malicious** |

## Verdict

Malicious. Authentication failed across the board, the mail was injected from
unrelated foreign infrastructure while impersonating an accounts-payable portal,
and the attachment is rigged to execute on open. This is a payload-delivery
phish. Action: block the sender domain and originating IP, pull the message from
any other mailboxes it reached, and submit the PDF hash to the intel platform.

## MITRE ATT&CK

- T1566.001 — Phishing: Spearphishing Attachment
- T1204.002 — User Execution: Malicious File
