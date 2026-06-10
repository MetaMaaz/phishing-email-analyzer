# CONTEXT — Read this first

> Handoff context for Claude Cowork building the Phishing Email Analyzer. Read this, then `SPEC.md`, then execute `TASKS.md` in order.

---

## Who this is for

Owner is an MSc Cybersecurity student targeting a **SOC Analyst Tier-1** role, specialising long-term in **DFIR** (defensive / blue team). This project is a **portfolio piece** — its job is to demonstrate real SOC phishing-triage workflow to recruiters. The **writeups and explainability matter as much as the code.**

## Environment

- **OS:** macOS (Apple Silicon). Everything must run natively — **no VM required.**
- **Python:** 3.11+ in a venv.
- **Editor/runner:** Claude Cowork.
- **Version control:** Git + GitHub. Use **Conventional Commits** (`feat:`, `chore:`, `test:`, `docs:`). Commit after each task.
- A Kali Linux VM (UTM) exists but is **out of scope** here — this tool does static analysis only and should not depend on it.

## Constraints

- **Time:** owner has ~2–3 hrs/week, so keep changes reviewable and incremental. Prefer small, working commits over big drops.
- **Skill level:** comfortable with basic Python automation. Favour readable, well-commented code over clever abstractions.
- **Format preference:** Markdown for all docs.

## The ThreatLens connection (important resume angle)

The owner already built **ThreatLens**, a threat-intelligence platform that collects, enriches, scores, and correlates IOCs. This analyzer should be able to **hand its extracted IOCs to ThreatLens** (config-driven base URL, see `SPEC.md` FR4 / task T3.4). Two tools that connect tell a stronger story than two isolated ones — keep that integration clean and documented.

## Definition of success (beyond "it runs")

1. A recruiter can read the README and immediately understand what it does and why it's a SOC skill.
2. The 5 case studies show analyst judgement, not just tool output.
3. Everything maps to MITRE ATT&CK.
4. The code is safe-by-default and explainable (no black-box scoring).

## Hard rules (security & safety)

- **Static analysis only** — never execute or detonate samples.
- **No secrets committed** — `.env` is gitignored; ship `.env.example` only.
- **No real malicious samples in a public repo** — `samples/` gitignored; describe them in the README.
- **Graceful offline operation** — must run fully with enrichment disabled.
- **Ask the owner before** adding: live mailbox access, any execution/detonation, or any outbound network destination not in the spec.

## Suggested first move

Start at **T0.1** (scaffold) → **T0.3** (models) → Phase 1 (parsing). Get a single `.eml` parsing and printing structured fields before touching anything else. Stop at the **MVP checkpoint** (end of Phase 2) and confirm the end-to-end run with the owner before building enrichment.

## Files in this pack

| File | Purpose |
|------|---------|
| `CONTEXT.md` | This file — environment, constraints, success criteria |
| `SPEC.md` | Authoritative build specification (requirements, architecture, scoring) |
| `TASKS.md` | Sequenced, checkbox task list with done-when criteria and commit messages |
