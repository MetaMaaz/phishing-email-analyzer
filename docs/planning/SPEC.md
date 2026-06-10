# Phishing Email Analyzer — Build Specification

> **For Claude Cowork:** This is the authoritative spec for what to build. Read `CONTEXT.md` first for environment and constraints, then work through `TASKS.md` in order. Build the MVP fully before adding enrichment or attachment analysis.

---

## 1. What this is

A blue-team CLI tool (Python) that ingests a suspicious email, analyses its authentication headers, extracts and enriches Indicators of Compromise (IOCs), inspects attachments statically, scores the email's risk, and emits an analyst-ready report.

**It is a SOC Tier-1 phishing-triage tool.** It must never execute or detonate anything — static analysis only.

---

## 2. Goals & non-goals

### Goals
- Parse `.eml` and `.msg` into a structured object.
- Detect spoofing and authentication failures from headers.
- Extract IOCs (URLs, domains, IPs, sender, attachment hashes), defanged.
- Enrich IOCs against threat-intel APIs (and/or the owner's existing ThreatLens platform).
- Statically inspect attachments (hashes, Office macros, PDF anomalies).
- Produce a weighted risk score and a clean Markdown + JSON report.

### Non-goals
- No dynamic execution / sandbox detonation.
- No live mailbox integration (IMAP/Graph) in v1.
- No ML model — scoring is rule-based and explainable by design.

---

## 3. Functional requirements

### FR1 — Email parsing
- Accept a path to a `.eml` or `.msg` file (auto-detect by extension/content).
- Produce an `EmailObject` exposing: `from`, `reply_to`, `return_path`, `to`, `subject`, `date`, `received_chain` (ordered list), `auth_results` (raw `Authentication-Results`), `body_text`, `body_html`, `attachments` (list of name + bytes + content-type).
- Handle malformed/missing headers gracefully (never crash; record what's missing).

### FR2 — Header analysis
- Parse SPF, DKIM, DMARC results from `Authentication-Results` (pass/fail/none/softfail).
- Trace the `Received:` chain and identify the earliest originating IP/host.
- Detect mismatches between `From`, `Return-Path`, and `Reply-To` domains.
- Detect display-name spoofing (friendly name implies a brand the address domain doesn't match).

### FR3 — IOC extraction
- Extract URLs, domains, IPv4/IPv6, sender email, and attachment hashes (MD5/SHA1/SHA256).
- Defang all IOCs in output (`hxxp`, `[.]`).
- De-duplicate. Separate "sender infrastructure" IOCs from "body/link" IOCs.

### FR4 — Enrichment (pluggable; degrade gracefully if no API key)
- VirusTotal: URL/domain/file-hash reputation.
- AbuseIPDB: originating IP reputation.
- URLhaus: malicious-URL lookup.
- Optional ThreatLens hand-off: POST extracted IOCs to the owner's ThreatLens API (config-driven base URL).
- All network calls must time out, retry once, and never block the whole run on one failure.

### FR5 — Attachment analysis (static only)
- Hash every attachment.
- Office docs: run `oletools` (olevba/oleid) — flag auto-exec macros, suspicious keywords (Shell, AutoOpen, etc.).
- PDFs: flag JavaScript, embedded files, launch/OpenAction.
- Never write attachment bytes to a path that could auto-open; keep in memory or a quarantined temp dir.

### FR6 — Risk scoring
- Weighted, rule-based, explainable. Every point added must come with a human-readable reason.
- Output a total score, a band (Low / Suspicious / Malicious), and the contributing reasons.

### FR7 — Reporting
- Emit Markdown (human) and JSON (machine) reports per email.
- Markdown report sections: Summary + verdict, Authentication, Spoofing signals, IOCs (defanged) with enrichment, Attachments, Score breakdown, MITRE ATT&CK mapping.
- Batch mode: accept a folder and produce one report per email plus a summary index.

---

## 4. Non-functional requirements

- **Python 3.11+**, runs natively on macOS, no VM.
- **No secrets in code** — API keys from `.env` / environment only; ship `.env.example`.
- **Safe by default** — static analysis only; document this in the README.
- **Explainable** — no black-box scoring; every verdict is traceable.
- **Testable** — pure functions where possible; unit tests for parser, headers, IOCs, scoring.
- **Offline-capable** — full run must work with enrichment disabled (no keys), just lower confidence.

---

## 5. Suggested architecture

```
phishing-analyzer/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore              # ignores .env and samples/
├── samples/                # test emails (zipped/pw-protected; not committed)
├── reports/                # generated output
├── src/
│   ├── __init__.py
│   ├── parser.py           # FR1  .eml/.msg -> EmailObject
│   ├── headers.py          # FR2  auth + received chain + spoof checks
│   ├── iocs.py             # FR3  extraction + defang
│   ├── enrich.py           # FR4  VT / AbuseIPDB / URLhaus / ThreatLens
│   ├── attachments.py      # FR5  hashing + oletools + pdf
│   ├── score.py            # FR6  weighted scoring
│   ├── report.py           # FR7  markdown + json
│   ├── models.py           # dataclasses: EmailObject, IOC, Finding, Report
│   ├── config.py           # env/config loading
│   └── cli.py              # entry point (typer/argparse)
├── tests/
│   ├── test_parser.py
│   ├── test_headers.py
│   ├── test_iocs.py
│   └── test_score.py
└── docs/
    └── case-studies/       # the 5 investigation writeups
```

**Data flow:** `parse → (headers + iocs + attachments) → enrich → score → report`

---

## 6. Risk scoring model (starter — Cowork should make weights config-driven)

| Signal | Weight | Reason string |
|--------|-------:|---------------|
| SPF fail | +20 | "SPF authentication failed" |
| DKIM fail | +15 | "DKIM signature invalid/absent" |
| DMARC fail | +20 | "DMARC policy failed" |
| From/Return-Path mismatch | +15 | "Envelope sender domain differs from From" |
| Display-name spoofing | +15 | "Display name impersonates a brand" |
| URL flagged (VT/URLhaus) | +25 each | "URL flagged malicious by <source>" |
| Originating IP flagged (AbuseIPDB) | +20 | "Sender IP has abuse reports" |
| Attachment hash known-malicious | +40 | "Attachment matches known malware hash" |
| Macro auto-exec | +30 | "Office macro with auto-execution" |
| Lookalike/typosquat domain | +15 | "Domain resembles a known brand" |

**Bands:** `0–29 Low` · `30–59 Suspicious` · `60+ Malicious`. Cap at 100. Weights live in `config.py` / `.env` so they're tunable.

---

## 7. Tech stack

| Purpose | Library |
|---------|---------|
| `.eml` parsing | built-in `email`, `email.policy` |
| `.msg` parsing | `extract-msg` |
| IOC extraction | `iocextract`, `tldextract`, `re` |
| Hashing | built-in `hashlib` |
| Office macros | `oletools` |
| PDF analysis | `pdfid` (and/or `peepdf`) |
| HTTP | `httpx` (async-capable) or `requests` |
| CLI | `typer` |
| Reports | `jinja2` or f-strings |
| Tests | `pytest` |
| Config | `python-dotenv` |

---

## 8. MITRE ATT&CK mapping (include in every report + README)

| Technique | ID |
|-----------|-----|
| Phishing | T1566 |
| Spearphishing Attachment | T1566.001 |
| Spearphishing Link | T1566.002 |
| User Execution: Malicious File | T1204.002 |
| User Execution: Malicious Link | T1204.001 |

---

## 9. Definition of done

- [ ] `python -m src.cli analyze sample.eml` produces a Markdown + JSON report.
- [ ] Works with **no** API keys (enrichment skipped, run still completes).
- [ ] Works **with** keys (enrichment populated).
- [ ] `.msg` and `.eml` both parse.
- [ ] Macro-enabled doc is correctly flagged.
- [ ] Spoofed `From`/`Return-Path` is correctly flagged.
- [ ] Unit tests pass for parser, headers, IOCs, scoring.
- [ ] README complete (see checklist in `TASKS.md`).
- [ ] 5 case studies written in `docs/case-studies/`.
- [ ] No secrets committed; `.env` gitignored.
