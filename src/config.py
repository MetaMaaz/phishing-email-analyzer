"""Configuration: scoring weights, bands, API keys, network behaviour.

All values are environment-driven (via ``.env`` / process env) so nothing
secret lives in code and weights are tunable without touching the logic.
``python-dotenv`` is used if installed, but the module degrades gracefully
if it (or any key) is absent.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()  # loads a local .env if present; no-op otherwise
except Exception:  # pragma: no cover - dotenv is optional
    pass


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Default scoring weights (SPEC.md §6). Each is overridable via env.
DEFAULT_WEIGHTS: dict[str, int] = {
    "SPF_FAIL": _int_env("WEIGHT_SPF_FAIL", 20),
    "DKIM_FAIL": _int_env("WEIGHT_DKIM_FAIL", 15),
    "DMARC_FAIL": _int_env("WEIGHT_DMARC_FAIL", 20),
    "ENVELOPE_MISMATCH": _int_env("WEIGHT_ENVELOPE_MISMATCH", 15),
    "DISPLAY_NAME_SPOOF": _int_env("WEIGHT_DISPLAY_NAME_SPOOF", 15),
    "URL_FLAGGED": _int_env("WEIGHT_URL_FLAGGED", 25),
    "IP_FLAGGED": _int_env("WEIGHT_IP_FLAGGED", 20),
    "ATTACHMENT_KNOWN_BAD": _int_env("WEIGHT_ATTACHMENT_KNOWN_BAD", 40),
    "MACRO_AUTOEXEC": _int_env("WEIGHT_MACRO_AUTOEXEC", 30),
    "LOOKALIKE_DOMAIN": _int_env("WEIGHT_LOOKALIKE_DOMAIN", 15),
}

# Band thresholds. score < SUSPICIOUS -> Low, < MALICIOUS -> Suspicious, else Malicious.
BAND_SUSPICIOUS = _int_env("BAND_SUSPICIOUS", 30)
BAND_MALICIOUS = _int_env("BAND_MALICIOUS", 60)
SCORE_CAP = 100


@dataclass
class Config:
    weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    band_suspicious: int = BAND_SUSPICIOUS
    band_malicious: int = BAND_MALICIOUS
    score_cap: int = SCORE_CAP

    # Enrichment
    vt_api_key: str = field(default_factory=lambda: os.getenv("VT_API_KEY", ""))
    abuseipdb_api_key: str = field(
        default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY", "")
    )
    urlhaus_auth_key: str = field(
        default_factory=lambda: os.getenv("URLHAUS_AUTH_KEY", "")
    )
    threatlens_base_url: str = field(
        default_factory=lambda: os.getenv("THREATLENS_BASE_URL", "")
    )
    threatlens_api_key: str = field(
        default_factory=lambda: os.getenv("THREATLENS_API_KEY", "")
    )
    http_timeout: int = _int_env("HTTP_TIMEOUT", 10)

    def band_for(self, score: int) -> str:
        if score >= self.band_malicious:
            return "Malicious"
        if score >= self.band_suspicious:
            return "Suspicious"
        return "Low"


def load_config() -> Config:
    return Config()
