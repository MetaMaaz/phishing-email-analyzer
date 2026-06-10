# Case study 4 — Business Email Compromise (display-name spoof, no payload)

**Sample:** `samples/04_bec_ceo_fraud.eml`
**Verdict:** 🟠 Suspicious — 35/100

## What I saw

A short, casual email: subject "Quick task", from "Jane Smith, CEO". The body
asks the recipient if they're at their desk and says there's an urgent,
confidential vendor payment that needs processing before 3pm — reply and the
"CEO" will send bank details. It's signed "Sent from my iPhone".

No link. No attachment. Nothing for a sandbox to detonate. This is the hard
case, and it's the one that costs companies the most money.

## How I analysed it

This is where header authentication *doesn't* save you. Check the results:

```
spf=pass smtp.mailfrom=gmail.com
dkim=pass header.d=gmail.com
dmarc=pass
```

Everything passes — because the mail genuinely was sent from Gmail. The attacker
isn't spoofing a domain; they registered a free Gmail account and put "Jane
Smith, CEO" in the display name. SPF/DKIM/DMARC all validate Gmail, so an
auth-only check would wave this straight through.

So you have to score on behaviour instead, which is exactly what the tool does
here:

- **Executive impersonation from free webmail.** The display name and address
  both imply a CEO (`jane.smith.ceo`), but the sending domain is `gmail.com`. A
  real CEO sends from the corporate domain, not a personal Gmail. This is the
  single strongest BEC tell.
- **Reply-To redirect.** The `From` is `jane.smith.ceo@gmail.com` but the
  `Reply-To` is `jane.smith.payments@gmail.com` — same domain, *different
  mailbox*. When the victim hits reply, their answer (and any bank details)
  routes to a different inbox than the one that appears to have sent the mail.
  That's the payment-redirect mechanism.

The urgency, the secrecy, the "are you at your desk" opener and the off-hours
deadline are all textbook BEC pressure tactics that line up with the technical
signals.

## Score breakdown

| Signal | Points |
|--------|-------:|
| Executive impersonation from free webmail | +20 |
| Reply-To routes to a different mailbox | +15 |
| **Total** | **35 — Suspicious** |

## Analyst note

35/Suspicious is the *right* score for this. BEC has no payload and passes
authentication, so it will never light up like a malware doc — and a tool that
forced it to "Malicious" on these signals alone would scream false-positive on
every legitimate email a real executive sends from their phone. The value here
is that the tool surfaces *why* it's suspicious in plain language, so a Tier-1
analyst escalates it to the finance team for out-of-band verification instead of
ignoring a clean-auth email. Catching BEC is a judgement call supported by
signals, not an automatic verdict.

## Verdict

Suspicious — treat as attempted CEO-fraud BEC. No payment should be processed
without verifying through a known-good channel (phone the actual CEO, not this
thread).

## MITRE ATT&CK

- T1566 — Phishing (BEC is the non-payload branch)
