"""FR6 — Weighted, rule-based, explainable risk scoring.

There is no black box here: the score is just the sum of ``Finding.weight``
values, capped, mapped to a band. Every point is attributable to a named
finding with a human-readable reason — that traceability is the whole point.
"""

from __future__ import annotations

from .config import Config
from .models import Finding, Report


def score_findings(findings: list[Finding], config: Config) -> tuple[int, str]:
    """Sum finding weights, cap, and map to a band."""

    total = sum(f.weight for f in findings)
    total = max(0, min(total, config.score_cap))
    return total, config.band_for(total)


def collect_mitre(findings: list[Finding]) -> list[str]:
    seen: list[str] = []
    for f in findings:
        for t in f.mitre:
            if t not in seen:
                seen.append(t)
    return sorted(seen)


def finalize_report(report: Report, config: Config) -> Report:
    """Populate score, band and aggregated MITRE list from current findings."""

    report.score, report.band = score_findings(report.findings, config)
    report.mitre = collect_mitre(report.findings)
    return report
