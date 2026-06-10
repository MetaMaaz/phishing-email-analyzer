# Case study 5 — AI-generated phishing (clean grammar, passes auth)

**Sample:** `samples/05_ai_generated_phish.eml`
**Verdict:** 🟠 Suspicious — 30/100

## What I saw

A polished DocuSign notification: "Your recent DocuSign envelope is ready to
view", telling the recipient a document from their finance team needs signing
and will expire in 48 hours, with a "review and sign securely" link. The grammar
is perfect, the tone is exactly right, and it even includes the "this is a
monitored address, please do not reply" boilerplate that real DocuSign mail
uses.

This is the modern problem. The old tells — broken English, obvious urgency,
weird formatting — are gone. Generative AI writes phishing that reads like the
real thing, so you can't lean on "it looks dodgy" any more. You have to lean on
infrastructure.

## How I analysed it

The writing gives nothing away, so I ignore it and go to the headers and the
domain. And here's the catch that makes this case interesting:

```
spf=pass smtp.mailfrom=docusign-secure-docs.com
dkim=pass header.d=docusign-secure-docs.com
dmarc=pass
```

It passes authentication — but read the domain it's passing *for*. SPF, DKIM and
DMARC all validate `docusign-secure-docs.com`, which is the **attacker's** domain.
Authentication only proves the mail really came from whoever owns that domain; it
says nothing about whether that domain is legitimate. An attacker who registers a
domain and sets up SPF/DKIM correctly gets a full pass. This is the most
misunderstood part of email authentication, and AI-written lures exploit it
because they have nothing else to give them away.

So the signal has to come from the domain itself, and the tool catches it two
ways:

- **Display-name impersonation.** The friendly name is "DocuSign" but the
  sending domain is `docusign-secure-docs.com`, not `docusign.com` or
  `docusign.net`.
- **Brand name embedded in the domain.** The domain *contains* the token
  "docusign" but isn't an official DocuSign domain. Burying a real brand name in
  a longer attacker-owned domain (`docusign-secure-docs.com`,
  `paypal-account-verify.com`) is a deliberate trick to make the URL look
  trustworthy in a hurry. The body link `hxxps://app[.]docusign-secure-docs[.]com/sign?env=8842`
  is built the same way.

## Score breakdown

| Signal | Points |
|--------|-------:|
| Display-name brand impersonation (DocuSign) | +15 |
| Brand name embedded in sending domain | +15 |
| **Total** | **30 — Suspicious** |

## Analyst note

The thing I want a recruiter to notice here: the tool reached *Suspicious* on a
message that is grammatically perfect and passes SPF, DKIM and DMARC. It did that
purely on infrastructure analysis — the relationship between the claimed brand
and the actual domain — which is exactly the muscle you need as AI makes the
written content of phishing indistinguishable from legitimate mail. Run the URL
and domain through VirusTotal/URLhaus enrichment and a reputation hit pushes this
firmly into Malicious; even without it, the brand-in-domain pattern is enough to
block and investigate.

## Verdict

Suspicious — DocuSign-themed credential/sign-in phish on attacker-controlled
lookalike infrastructure. Don't trust "it passed DMARC".

## MITRE ATT&CK

- T1566.002 — Phishing: Spearphishing Link
- T1204.001 — User Execution: Malicious Link
