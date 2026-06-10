"""IOC tests (FR3): extraction, dedupe, defang, lookalike detection."""

from __future__ import annotations

from src.iocs import (
    defang,
    extract_iocs,
    levenshtein,
    lookalike_domains,
    refang,
    registered_domain,
)
from src.models import EmailObject


def test_defang_and_refang_roundtrip():
    url = "https://evil.example.com/path"
    d = defang(url)
    assert d == "hxxps://evil[.]example[.]com/path"
    assert refang(d) == url


def test_registered_domain():
    assert registered_domain("login.micros0ft-support.com") == "micros0ft-support.com"
    assert registered_domain("a.b.example.co.uk").endswith("example.co.uk")


def test_extract_dedupes_and_tags_origin():
    obj = EmailObject(
        from_addr="sender@evil.com",
        received_chain=["from x (x [203.0.113.9]) by mx"],
        body_text="Click http://evil.com/a and http://evil.com/a again. "
                  "Also visit http://other.net/login",
    )
    iocs = extract_iocs(obj)
    urls = [i.value for i in iocs if i.type == "url"]
    # Duplicate URL collapses to one.
    assert urls.count("http://evil.com/a") == 1
    # Sender infra is tagged separately from body.
    assert any(i.origin == "sender" and i.type == "ipv4" for i in iocs)
    assert any(i.origin == "body" and i.type == "url" for i in iocs)
    # Everything is defanged.
    assert all("[.]" in i.defanged or i.type in ("md5", "sha1", "sha256")
               for i in iocs if "." in i.value)


def test_levenshtein():
    assert levenshtein("microsoft", "micr0soft") == 1
    assert levenshtein("paypal", "paypal") == 0


def test_lookalike_domains():
    hits = lookalike_domains(
        ["paypa1.com", "paypal.com", "example.org"], ["paypal.com"]
    )
    flagged = {d for d, _ in hits}
    assert "paypa1.com" in flagged       # typosquat caught
    assert "paypal.com" not in flagged   # exact match ignored
    assert "example.org" not in flagged  # unrelated ignored
