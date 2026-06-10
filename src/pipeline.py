"""End-to-end orchestration: parse -> headers + iocs + attachments ->
enrich -> score -> report.

Kept separate from ``cli.py`` so it can be imported and unit-tested without
touching argument parsing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .config import Config, load_config
from .headers import AuthResult, KNOWN_BRANDS, analyze_headers
from .iocs import extract_iocs, lookalike_domains
from .models import Finding, Report
from .parser import parse_email
from .report import now_iso, write_reports
from .score import finalize_report

# Brand registered-domains used for lookalike comparison.
_BRAND_DOMAINS = sorted({d for ds in KNOWN_BRANDS.values() for d in ds})


class AnalysisResult:
    """Bundle of everything a caller might want after one analysis."""

    def __init__(self, report: Report, auth: AuthResult, src_ip: Optional[str]):
        self.report = report
        self.auth = auth
        self.originating_ip = src_ip


def analyze(
    path: str | Path,
    config: Optional[Config] = None,
    enrich: bool = True,
) -> AnalysisResult:
    """Run the full pipeline on a single email file."""

    config = config or load_config()

    # 1. Parse
    email_obj = parse_email(path)

    # 2. Headers (auth + received chain + spoofing)
    auth, src_ip, header_findings = analyze_headers(email_obj, config.weights)

    # 3. IOCs
    iocs = extract_iocs(email_obj)

    # 3b. Lookalike / typosquat domains among extracted domains
    findings: list[Finding] = list(header_findings)
    body_domains = [i.value for i in iocs if i.type == "domain"]
    for dom, brand in lookalike_domains(body_domains, _BRAND_DOMAINS):
        findings.append(
            Finding(
                "LOOKALIKE_DOMAIN",
                f"Domain '{dom}' closely resembles brand domain '{brand}'",
                config.weights["LOOKALIKE_DOMAIN"],
                ["T1566", "T1566.002"],
            )
        )

    # 4. Attachments (static only) — optional import so the MVP runs even if
    #    oletools isn't installed.
    try:
        from .attachments import analyze_attachments

        findings += analyze_attachments(email_obj, config.weights)
    except Exception as exc:  # pragma: no cover - defensive
        email_obj.parse_warnings.append(f"attachment analysis skipped: {exc}")

    # 5. Enrichment (network; degrades gracefully)
    if enrich:
        try:
            from .enrich import enrich_iocs

            findings += enrich_iocs(iocs, src_ip, config)
        except Exception as exc:  # pragma: no cover - defensive
            email_obj.parse_warnings.append(f"enrichment skipped: {exc}")

    # 6. Score + 7. assemble report
    report = Report(
        email=email_obj,
        iocs=iocs,
        findings=findings,
        generated_at=now_iso(),
    )
    finalize_report(report, config)

    return AnalysisResult(report, auth, src_ip)


def analyze_to_files(
    path: str | Path,
    out_dir: str | Path,
    config: Optional[Config] = None,
    enrich: bool = True,
) -> tuple[Path, Path, AnalysisResult]:
    result = analyze(path, config=config, enrich=enrich)
    stem = Path(path).stem
    md, js = write_reports(
        result.report, out_dir, stem, result.auth, result.originating_ip
    )
    return md, js, result
