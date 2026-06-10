# Case study 2 — Credential harvesting (lookalike login link)

**Sample:** `samples/02_credential_harvest.eml`
**Verdict:** 🟠 Suspicious — 55/100

## What I saw

A "your mailbox is almost full, re-verify now" email branded as Microsoft 365,
with a 24-hour deadline and a link to "re-verify your account". No attachment —
the payload is the link itself, which points at
`https://login.micros0ft-support.com/owa/verify?u=victim`.

The whole design is built to push the recipient onto a fake Outlook login page
and capture their credentials.

## How I analysed it

The display name says "Microsoft 365" but the sending domain is
`micros0ft-support.com` — that's a zero in place of the "o" in Microsoft, plus a
`-support` suffix that Microsoft doesn't use. The tool flags this as
display-name impersonation: the friendly name claims a brand the sending domain
doesn't back up.

Authentication is weak: SPF is a softfail and DMARC failed. The mail came from
`198.51.100.23`, a host with no relationship to Microsoft.

The link is the real giveaway. The hostname `login.micros0ft-support.com` is
designed to read like a Microsoft login URL at a glance — the word "login" and
"owa" (Outlook Web Access) are there to reassure — but the registered domain is
the attacker's lookalike. The tool defangs it to
`hxxps://login[.]micros0ft-support[.]com/owa/verify?u=victim` so it's safe to
record and share.

## Score breakdown

| Signal | Points |
|--------|-------:|
| SPF softfail | +20 |
| DMARC fail | +20 |
| Display-name brand impersonation (Microsoft) | +15 |
| **Total** | **55 — Suspicious** |

## Analyst note

This one sits in *Suspicious* rather than *Malicious* on signals alone, because
there's no payload to detonate and no confirmed-bad reputation hit without
enrichment. In a real queue I'd run the URL through VirusTotal and URLhaus (the
tool does this automatically when keys are set), and a single malicious verdict
there adds +25 and tips it to Malicious. Even without enrichment, the
homoglyph domain plus auth failures plus a credential-capture URL is more than
enough to action: block the domain, warn the user, and hunt for anyone who
clicked.

## Verdict

Suspicious, treat as malicious credential harvesting. The lookalike domain and
the fake OWA path are the tells.

## MITRE ATT&CK

- T1566.002 — Phishing: Spearphishing Link
- T1204.001 — User Execution: Malicious Link
