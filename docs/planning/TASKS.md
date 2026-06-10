# Phishing Email Analyzer — Task List (for Claude Cowork)

> Work top to bottom. Each task has a clear **done-when**. Commit after each task using Conventional Commits (`feat:`, `chore:`, `test:`, `docs:`). Don't start enrichment (Phase 3) until the MVP (Phases 0–2) runs end to end.

---

## Phase 0 — Project setup

- [ ] **T0.1** Create the repo structure from `SPEC.md` §5.
  *Done when:* all folders/files exist (empty stubs OK).
- [ ] **T0.2** Add `requirements.txt`, `.env.example`, `.gitignore` (ignore `.env`, `samples/`, `reports/`, `venv/`).
  *Done when:* `pip install -r requirements.txt` succeeds in a fresh venv.
- [ ] **T0.3** Define dataclasses in `models.py`: `EmailObject`, `IOC`, `Finding` (reason + weight), `Report`.
  *Done when:* models import cleanly and have type hints.
  *Commit:* `chore: scaffold project structure and models`

## Phase 1 — Parsing (FR1)

- [ ] **T1.1** Implement `.eml` parsing in `parser.py` using built-in `email` + `email.policy.default`.
- [ ] **T1.2** Implement `.msg` parsing via `extract-msg`; normalise into the same `EmailObject`.
- [ ] **T1.3** Auto-detect file type; handle missing/malformed headers without crashing.
  *Done when:* both a sample `.eml` and `.msg` print structured fields (from, subject, received_chain, attachments count).
  *Commit:* `feat: parse .eml and .msg into EmailObject`

## Phase 2 — Header analysis, IOCs, scoring, report (MVP core)

- [ ] **T2.1** `headers.py`: extract SPF/DKIM/DMARC from `Authentication-Results`.
- [ ] **T2.2** `headers.py`: trace `Received:` chain → earliest originating IP/host.
- [ ] **T2.3** `headers.py`: detect From/Return-Path/Reply-To mismatches + display-name spoofing.
- [ ] **T2.4** `iocs.py`: extract + de-dupe + defang URLs/domains/IPs/sender/hashes.
- [ ] **T2.5** `score.py`: weighted, reason-tagged scoring per `SPEC.md` §6; weights from config.
- [ ] **T2.6** `report.py`: Markdown + JSON output with all MVP sections.
- [ ] **T2.7** `cli.py`: `analyze <path>` command wiring parse→headers→iocs→score→report.
  *Done when:* `python -m src.cli analyze sample.eml` writes a complete report with **no API keys needed**.
  *Commit:* `feat: MVP analysis pipeline (headers, iocs, scoring, report)`

> **Checkpoint: MVP must run end to end before continuing.**

## Phase 3 — Enrichment (FR4)

- [ ] **T3.1** `enrich.py`: VirusTotal lookups (URL/domain/hash), key from env, graceful skip if absent.
- [ ] **T3.2** AbuseIPDB lookup for originating IP.
- [ ] **T3.3** URLhaus lookup for URLs.
- [ ] **T3.4** Optional ThreatLens hand-off: POST IOCs to a config-driven base URL.
- [ ] **T3.5** Timeouts + single retry + per-source failure isolation.
  *Done when:* enrichment populates the report when keys are present and is cleanly skipped when not.
  *Commit:* `feat: IOC enrichment via VT/AbuseIPDB/URLhaus + ThreatLens handoff`

## Phase 4 — Attachment analysis (FR5)

- [ ] **T4.1** Hash all attachments (MD5/SHA1/SHA256).
- [ ] **T4.2** `oletools` macro inspection — flag auto-exec + suspicious keywords.
- [ ] **T4.3** PDF checks — JavaScript, embedded files, launch/OpenAction.
- [ ] **T4.4** Quarantine handling: never write bytes to an auto-openable location.
  *Done when:* a macro-enabled test doc is flagged with specific findings in the report.
  *Commit:* `feat: static attachment analysis (hashes, macros, pdf)`

## Phase 5 — Batch mode + polish

- [ ] **T5.1** `cli.py`: `batch <folder>` → one report per email + a summary index.
- [ ] **T5.2** Tune scoring weights against the test corpus; document the tuning.
  *Commit:* `feat: batch mode and scoring tuning`

## Phase 6 — Tests

- [ ] **T6.1** `test_parser.py` — eml + msg parse correctly.
- [ ] **T6.2** `test_headers.py` — spoof + auth-fail detection.
- [ ] **T6.3** `test_iocs.py` — extraction + defang + dedupe.
- [ ] **T6.4** `test_score.py` — known inputs → expected bands.
  *Done when:* `pytest` is green.
  *Commit:* `test: unit tests for parser, headers, iocs, scoring`

## Phase 7 — Documentation & case studies

- [ ] **T7.1** Write `README.md` (checklist below).
- [ ] **T7.2** Write 5 case studies in `docs/case-studies/`:
  fake invoice · credential harvesting · malware attachment (macro) · BEC · AI-generated phishing.
  Each: what you saw → analysis → verdict → MITRE mapping.
  *Commit:* `docs: README and five investigation case studies`

### README checklist
- [ ] One-liner + screenshot of a sample report
- [ ] Problem solved (SOC phishing triage)
- [ ] Features
- [ ] Architecture diagram (data-flow from `SPEC.md` §5)
- [ ] Install + usage (`python -m src.cli analyze sample.eml`)
- [ ] Risk-scoring explanation
- [ ] Links to the 5 case studies
- [ ] MITRE ATT&CK mapping
- [ ] Safety/handling note (static only, samples zipped+pw)
- [ ] ThreatLens integration note
- [ ] Tech stack + what was learned

---

## Guardrails for Cowork (do not violate)

- **Static analysis only.** Never execute, open, or detonate attachments.
- **No secrets in code or commits.** Keys come from `.env`; commit only `.env.example`.
- **Never commit real malicious samples** to a public repo — keep `samples/` gitignored; describe them in the README instead.
- **Degrade gracefully** — the tool must run fully offline with enrichment disabled.
- **Ask before** adding live-mailbox integration, any execution capability, or any new outbound destination not already in the spec.
