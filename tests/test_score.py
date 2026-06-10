"""Scoring tests (FR6): known findings -> expected bands; cap; attachments."""

from __future__ import annotations

from src.attachments import inspect_pdf
from src.config import load_config
from src.models import Attachment, Finding
from src.score import collect_mitre, score_findings


CFG = load_config()


def _f(weight: int) -> Finding:
    return Finding("X", "reason", weight, ["T1566"])


def test_band_thresholds():
    assert score_findings([_f(0)], CFG)[1] == "Low"
    assert score_findings([_f(29)], CFG)[1] == "Low"
    assert score_findings([_f(30)], CFG)[1] == "Suspicious"
    assert score_findings([_f(59)], CFG)[1] == "Suspicious"
    assert score_findings([_f(60)], CFG)[1] == "Malicious"


def test_score_is_capped_at_100():
    score, band = score_findings([_f(80), _f(80)], CFG)
    assert score == 100
    assert band == "Malicious"


def test_collect_mitre_dedupes():
    findings = [
        Finding("A", "", 10, ["T1566", "T1566.002"]),
        Finding("B", "", 10, ["T1566"]),
    ]
    assert collect_mitre(findings) == ["T1566", "T1566.002"]


def test_pdf_active_content_flagged():
    pdf = (b"%PDF-1.4\n1 0 obj<</OpenAction 2 0 R>>endobj\n"
           b"2 0 obj<</S/JavaScript/JS(x)>>endobj\n%%EOF")
    att = Attachment(filename="x.pdf", content_type="application/pdf",
                     data=pdf, size=len(pdf))
    findings = inspect_pdf(att, CFG.weights)
    assert findings and findings[0].code == "PDF_ACTIVE_CONTENT"
    assert "JavaScript" in findings[0].reason


def test_clean_email_scores_low():
    # No findings at all -> Low / 0.
    assert score_findings([], CFG) == (0, "Low")
