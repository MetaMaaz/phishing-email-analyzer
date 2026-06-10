"""Header-analysis tests (FR2): auth parsing, received chain, spoof signals."""

from __future__ import annotations

from src.config import load_config
from src.headers import (
    analyze_headers,
    brand_in_domain,
    display_name_spoof,
    originating_ip,
    parse_auth_results,
)
from src.parser import parse_email


WEIGHTS = load_config().weights


def test_parse_auth_results_all_fail():
    auth = parse_auth_results("mx; spf=fail; dkim=fail; dmarc=fail")
    assert (auth.spf, auth.dkim, auth.dmarc) == ("fail", "fail", "fail")


def test_parse_auth_results_pass_and_missing():
    auth = parse_auth_results("mx; spf=pass smtp.mailfrom=x.com; dkim=pass")
    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "none"  # absent -> none


def test_originating_ip_picks_earliest_public():
    chain = [
        "from internal (10.0.0.5) by mx2",          # latest hop, private
        "from edge (198.51.100.7) by mx1",          # earliest hop, public
    ]
    assert originating_ip(chain) == "198.51.100.7"


def test_display_name_spoof_detects_brand_mismatch():
    hit = display_name_spoof("PayPal Service", "not-paypal.com")
    assert hit is not None and hit[0] == "DISPLAY_NAME_SPOOF"


def test_display_name_spoof_allows_legit_domain():
    assert display_name_spoof("PayPal", "paypal.com") is None


def test_brand_in_domain():
    assert brand_in_domain("docusign-secure-docs.com") == "docusign"
    assert brand_in_domain("docusign.com") is None
    assert brand_in_domain("example.com") is None


def test_spoof_findings_on_envelope_mismatch(write_eml):
    p = write_eml(
        "spoof.eml",
        {
            "From": "Billing <billing@brand.com>",
            "Return-Path": "<bounce@evil.ru>",
            "Subject": "pay",
            "Authentication-Results": "mx; spf=fail; dkim=none; dmarc=fail",
        },
    )
    obj = parse_email(p)
    _auth, _ip, findings = analyze_headers(obj, WEIGHTS)
    codes = {f.code for f in findings}
    assert "SPF_FAIL" in codes
    assert "DMARC_FAIL" in codes
    assert "ENVELOPE_MISMATCH" in codes
