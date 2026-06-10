# Case study 3 — Malware attachment (macro-enabled Office doc)

**Sample:** `samples/03_macro_attachment.eml`
**Verdict:** 🔴 Malicious — 100/100

## What I saw

An email from "HR Department" with the subject "Salary review document — enable
content to view" and a macro-enabled Word attachment, `Salary_Review.docm`. The
body explicitly tells the recipient to "ENABLE CONTENT" — which is the social
engineering needed to get past Office's macro warning. Anyone curious about
their salary is the target.

> Note: the attachment in this repo is a fully synthetic `.docm` with an **inert**
> VBA body (it does nothing). It exists only to exercise the static macro
> detection. Real samples are never committed.

## How I analysed it

Authentication is a clean sweep of failures — SPF fail, DKIM fail, DMARC fail —
and the mail originated from `192.0.2.155`, unrelated to any real HR system. The
sending domain `company-hr-portal.net` is generic lookalike infrastructure.

The attachment is where this becomes a confirmed payload. Static macro
inspection (no execution — the document is never opened) reads the VBA project
out of the `.docm` container and finds:

- An **`AutoOpen`** subroutine — VBA that runs automatically the moment the
  document is opened. This is the auto-execution trigger.
- A **`Shell`** call — the API used to launch external processes, i.e. to run
  whatever the macro wants to drop or download.

`AutoOpen` + `Shell` together is the signature of a macro dropper: open the doc,
the macro fires, and it shells out to stage the next payload.

## Score breakdown

| Signal | Points |
|--------|-------:|
| Office macro with auto-execution (AutoOpen) | +30 |
| SPF fail | +20 |
| DMARC fail | +20 |
| DKIM fail | +15 |
| Macro contains suspicious call (Shell) | +15 |
| **Total (capped)** | **100 — Malicious** |

## Verdict

Malicious, high confidence. This is a macro-based malware delivery document.
Action: block the sender and IP, quarantine the attachment by hash everywhere it
landed, and if anyone enabled content, treat that host as potentially
compromised and hand it to IR. The macro should only ever be examined statically
or detonated inside an isolated VM — never on a production host.

## MITRE ATT&CK

- T1566.001 — Phishing: Spearphishing Attachment
- T1204.002 — User Execution: Malicious File
