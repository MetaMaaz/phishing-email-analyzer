# Phishing Email Analyzer — Detailed Build Plan

**Project:** A blue-team tool that parses suspicious emails, analyses authentication headers, extracts and enriches IOCs, inspects attachments, and produces a risk-scored analyst report.

**Owner:** Maaz
**Platform:** Mac (fully native — no VM required)
**Language:** Python 3.11+
**Time budget:** ~2–3 hrs/week → 6–8 weeks
**Resume angle:** SOC Tier-1 daily workflow; integrates with ThreatLens IOC enrichment pipeline.

---

## 1. Why this project stands out

- Phishing triage is one of the **most common real SOC Tier-1 tasks** — recruiters recognise it instantly.
- Demonstrates header forensics, IOC extraction, threat-intel enrichment, and report writing in one tool.
- **Integrates with ThreatLens:** parse email → extract IOCs → hand to your existing enrichment pipeline. Two connected tools > two isolated ones.
- Maps cleanly to **MITRE ATT&CK** (Phishing T1566, Spearphishing Attachment T1566.001, Link T1566.002).

---

## 2. What it does (feature scope)

### Core (MVP — must have)
- Parse `.eml` and `.msg` files into structured objects.
- **Header analysis:**
  - SPF / DKIM / DMARC pass/fail extraction.
  - `Received:` chain tracing → identify true originating IP/host.
  - `From` vs `Return-Path` vs `Reply-To` mismatch detection (spoofing signal).
  - Display-name spoofing detection (e.g. "PayPal Support <random@gmail.com>").
- **IOC extraction:** URLs, domains, IPs, sender addresses, attachment hashes.
- **Risk scoring:** weighted score from auth failures, mismatches, suspicious URLs, known-bad IOCs.
- **Report output:** clean Markdown/JSON analyst report per email.

### Enrichment (high value)
- VirusTotal — URL/domain/hash reputation.
- AbuseIPDB — originating IP reputation.
- URLhaus — malicious URL feed lookup.
- (Optional) hand IOCs to **ThreatLens** instead of / in addition to direct API calls.

### Attachment analysis
- Hash all attachments (MD5/SHA1/SHA256) + reputation check.
- Office macro inspection via `oletools` (olevba) — flag auto-exec macros, suspicious calls.
- PDF inspection (JavaScript, embedded files, launch actions) via `peepdf`/`pdfid`.
- **Never detonate.** Static analysis only. Keep samples zipped + password-protected.

### Nice-to-have (stretch)
- URL defanging/refanging (`hxxp://`).
- Lookalike/homoglyph domain detection (typosquatting).
- Simple web UI (Flask/FastAPI) or batch CLI over a folder.
- Export findings as STIX or a ThreatLens-compatible format.

---

## 3. Tech stack & libraries (all install fine on Mac)

| Purpose | Library |
|---------|---------|
| `.eml` parsing | built-in `email`, `email.policy` |
| `.msg` parsing | `extract-msg` |
| Header auth parsing | `authheaders` or manual regex on `Authentication-Results` |
| IOC regex / IPs | `re`, `iocextract`, `tldextract` |
| Hashing | built-in `hashlib` |
| Office macros | `oletools` (`olevba`, `oleid`) |
| PDF analysis | `pdfid`, `peepdf` |
| HTTP / API calls | `requests` or `httpx` |
| CLI | `argparse` or `typer` |
| Report rendering | `jinja2` (HTML) or plain f-strings (Markdown) |
| Web UI (optional) | `fastapi` + `uvicorn` |

```bash
python3 -m venv venv && source venv/bin/activate
pip install extract-msg oletools iocextract tldextract requests typer jinja2 authheaders
```

---

## 4. Suggested architecture

```
phishing-analyzer/
├── README.md
├── requirements.txt
├── samples/                # password-protected test emails (NOT in git, or zipped)
├── reports/                # generated analyst reports
├── src/
│   ├── __init__.py
│   ├── parser.py           # .eml/.msg → EmailObject
│   ├── headers.py          # SPF/DKIM/DMARC, Received chain, spoof checks
│   ├── iocs.py             # extract URLs/domains/IPs/hashes
│   ├── enrich.py           # VT / AbuseIPDB / URLhaus / ThreatLens calls
│   ├── attachments.py      # hashing, oletools, pdf checks
│   ├── score.py            # weighted risk scoring
│   ├── report.py           # Markdown/JSON/HTML output
│   └── cli.py              # entry point
├── tests/
│   └── test_*.py
└── .env.example            # API keys (never commit real keys)
```

**Data flow:**
`parse → extract headers + IOCs + attachments → enrich → score → report`

---

## 5. Risk scoring model (starter design)

| Signal | Weight |
|--------|--------|
| SPF fail | +20 |
| DKIM fail | +15 |
| DMARC fail | +20 |
| From / Return-Path mismatch | +15 |
| Display-name spoofing | +15 |
| URL flagged by VT/URLhaus | +25 each |
| Originating IP flagged by AbuseIPDB | +20 |
| Attachment hash known-malicious | +40 |
| Macro with auto-exec | +30 |
| Lookalike/typosquat domain | +15 |

**Bands:** 0–29 Low · 30–59 Suspicious · 60+ Malicious. Tune against your test corpus and document the tuning — that reasoning is itself a resume signal.

---

## 6. 6–8 week roadmap (~2–3 hrs/week)

| Week | Goal | Deliverable |
|------|------|-------------|
| 1 | Repo + `.eml`/`.msg` parser | Parse a sample email, print structured fields |
| 2 | Header analysis | SPF/DKIM/DMARC + Received chain + spoof detection |
| 3 | IOC extraction + risk scoring v1 | Defanged IOC list + first score |
| 4 | Enrichment (VT, AbuseIPDB, URLhaus) | Live reputation in the report |
| 5 | Attachment analysis (hashes, oletools, PDF) | Macro/PDF flags in the report |
| 6 | Report generation (MD + JSON) | Clean analyst report per email |
| 7 | 5 case studies + tuning | Documented investigations (see below) |
| 8 | Polish: README, ThreatLens integration, screenshots | Portfolio-ready repo |

---

## 7. Case studies to include (the part recruiters read)

Build 5 documented investigations, each a short report (what you saw → how you analysed → verdict → MITRE mapping):

1. **Fake invoice** — attachment-based lure.
2. **Credential harvesting** — lookalike login link.
3. **Malware attachment** — macro-enabled Office doc.
4. **Business Email Compromise (BEC)** — display-name spoof, no payload.
5. **AI-generated phishing** — clean grammar, modern lure (topical talking point in interviews).

Each writeup is worth more than the code — it shows analyst judgement.

---

## 8. Where to get safe test samples

- **PhishTank** — reported phishing URLs.
- **Any.run / MalwareBazaar** — real samples (handle zipped + password-protected).
- **TryHackMe phishing rooms** — pre-packaged emails + walkthroughs.
- Your own spam folder (sanitise before committing).
- **Never commit real malicious samples to a public GitHub repo** — zip + password, or `.gitignore` the `samples/` folder and describe them in the README instead.

---

## 9. Safety hygiene (state this in your README — it's a maturity signal)

- Static analysis only — no detonation on the host Mac.
- Attachments stay zipped + password-protected; never double-click.
- API keys in `.env`, never committed (`.env.example` only).
- If you want dynamic analysis later, detonate inside your **Kali UTM VM**, isolated — out of scope for this tool.

---

## 10. MITRE ATT&CK mapping (put this in the README)

| Technique | ID |
|-----------|-----|
| Phishing | T1566 |
| Spearphishing Attachment | T1566.001 |
| Spearphishing Link | T1566.002 |
| User Execution: Malicious File | T1204.002 |
| User Execution: Malicious Link | T1204.001 |

---

## 11. README checklist (portfolio polish)

- [ ] One-line description + screenshot of a sample report
- [ ] Problem it solves (SOC phishing triage)
- [ ] Features list
- [ ] Architecture diagram (the data-flow above)
- [ ] Install + usage (`python -m src.cli sample.eml`)
- [ ] Risk scoring explanation
- [ ] 5 case studies linked
- [ ] MITRE ATT&CK mapping
- [ ] Safety/handling note
- [ ] ThreatLens integration note (how they connect)
- [ ] Tech stack + what you learned

---

## Notes for future AI assistants

- Owner is Maaz, MSc Cybersecurity (Surrey), targeting SOC Tier-1 → DFIR.
- Already built: Password Generator, ThreatLens (IOC enrichment platform). **This analyzer should feed IOCs into ThreatLens** — that integration is a key resume story.
- Constraints: ~2–3 hrs/week, Mac primary (Kali UTM available but not needed here), Python comfortable at basic-automation level.
- Prefers Markdown working docs, Conventional Commits, documentation-as-you-go.
- Keep scope realistic — MVP first (parse + headers + IOCs + score + report), enrichment and attachments next, web UI last.
