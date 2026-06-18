"""Streamlit demo UI for the Phishing Email Analyzer.

A thin presentation layer over the existing ``src`` pipeline. It does NOT
re-implement any analysis logic — it calls ``src.pipeline.analyze`` and renders
the same Markdown/JSON reports the CLI produces.

Security posture (this is a public, attacker-facing demo):
  * Static analysis only — no attachment is ever executed or detonated, and no
    link in the email is ever fetched. That property lives in the pipeline; the
    UI does nothing to weaken it.
  * Network enrichment (VirusTotal / AbuseIPDB / URLhaus) is OFF by default and
    can only be enabled when API keys are supplied via Streamlit secrets — never
    hard-coded, never taken from user input.
  * Upload/paste size is capped; oversized input is rejected before parsing.
  * A soft per-session rate limit slows abuse of the hosted instance.
  * The email's raw HTML body is never rendered as HTML (no XSS into this page).
    Only defanged indicators and the structured report are shown.
  * Uploaded bytes are written to a private temp file and deleted immediately
    after analysis; nothing is persisted server-side.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import streamlit as st

from src.config import load_config
from src.pipeline import analyze
from src.report import render_json, render_markdown

# --------------------------------------------------------------------------
# Constants / limits
# --------------------------------------------------------------------------
APP_TITLE = "Phishing Email Analyzer"
GITHUB_URL = "https://github.com/MetaMaaz/phishing-email-analyzer"
MAX_INPUT_BYTES = 1_500_000        # ~1.5 MB; emails are small, malware payloads are not
MAX_ANALYSES_PER_WINDOW = 10       # soft per-session throttle
RATE_WINDOW_SECONDS = 60
SAMPLES_DIR = Path(__file__).parent / "samples"

BAND_STYLE = {
    "Low": ("🟢", "#1a7f37"),
    "Suspicious": ("🟠", "#bf8700"),
    "Malicious": ("🔴", "#cf222e"),
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _enrichment_keys_present() -> bool:
    """True only if at least one threat-intel key is configured via secrets/env.

    Reading st.secrets is wrapped because accessing a missing secrets file
    raises in some Streamlit versions.
    """
    names = ("VT_API_KEY", "ABUSEIPDB_API_KEY", "URLHAUS_AUTH_KEY")
    try:
        for n in names:
            if str(st.secrets.get(n, "")).strip():  # type: ignore[attr-defined]
                # Push into env so load_config() (which reads os.getenv) sees it.
                os.environ[n] = str(st.secrets[n])
        return any(os.getenv(n, "").strip() for n in names)
    except Exception:
        return any(os.getenv(n, "").strip() for n in names)


def _rate_limited() -> bool:
    now = time.time()
    hits = [t for t in st.session_state.get("hits", []) if now - t < RATE_WINDOW_SECONDS]
    st.session_state["hits"] = hits
    return len(hits) >= MAX_ANALYSES_PER_WINDOW


def _record_hit() -> None:
    st.session_state.setdefault("hits", []).append(time.time())


def _run_analysis(raw: bytes, filename: str, enrich: bool):
    """Write bytes to a private temp file, analyze, and always clean up."""
    suffix = ".msg" if filename.lower().endswith(".msg") else ".eml"
    tmp = tempfile.NamedTemporaryFile(prefix="pea_", suffix=suffix, delete=False)
    try:
        tmp.write(raw)
        tmp.flush()
        tmp.close()
        config = load_config()
        return analyze(tmp.name, config=config, enrich=enrich)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def _list_samples() -> dict[str, Path]:
    if not SAMPLES_DIR.is_dir():
        return {}
    return {p.name: p for p in sorted(SAMPLES_DIR.glob("*.eml"))}


# --------------------------------------------------------------------------
# Page
# --------------------------------------------------------------------------
st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")

st.title("🛡️ Phishing Email Analyzer")
st.caption(
    "Paste or upload a suspicious email and get a SOC-style triage report — "
    "authentication checks, spoofing signals, defanged IOCs, attachment "
    "inspection, a weighted risk score, and MITRE ATT&CK mapping. "
    "**Static analysis only: nothing is executed, no link is ever fetched.**"
)

# ---- Sidebar -------------------------------------------------------------
with st.sidebar:
    st.header("About")
    st.markdown(
        f"A static phishing-triage tool built like a SOC analyst would work a "
        f"case. Source and docs on [GitHub]({GITHUB_URL})."
    )

    st.header("Enrichment")
    keys_present = _enrichment_keys_present()
    if keys_present:
        enrich = st.toggle(
            "Live threat-intel lookups",
            value=False,
            help="Query VirusTotal / AbuseIPDB / URLhaus for extracted IOCs. "
            "Adds latency and uses your API quota.",
        )
    else:
        enrich = False
        st.toggle(
            "Live threat-intel lookups",
            value=False,
            disabled=True,
            help="Disabled: no API keys configured in this deployment.",
        )
        st.caption("No threat-intel API keys set, so analysis runs fully offline.")

    st.header("Privacy & safety")
    st.markdown(
        "- Uploads are analysed in memory and **not stored**.\n"
        "- Attachments are **never opened or executed**; links are **never fetched**.\n"
        "- All indicators are **defanged** before display.\n"
        f"- Please don't upload real personal data. Max input: {MAX_INPUT_BYTES // 1000} KB."
    )

# ---- Input ---------------------------------------------------------------
tab_paste, tab_upload, tab_sample = st.tabs(
    ["📋 Paste raw email", "📎 Upload .eml / .msg", "🧪 Try a sample"]
)

raw_bytes: bytes | None = None
input_name = "pasted.eml"

with tab_paste:
    pasted = st.text_area(
        "Paste the full raw email (headers + body)",
        height=260,
        placeholder="Return-Path: <...>\nReceived: from ...\nAuthentication-Results: ...\nFrom: ...\nSubject: ...\n\n<body>",
    )
    if st.button("Analyze pasted email", type="primary", key="btn_paste"):
        if pasted.strip():
            raw_bytes = pasted.encode("utf-8", errors="replace")
            input_name = "pasted.eml"
        else:
            st.warning("Paste an email first.")

with tab_upload:
    up = st.file_uploader("Choose an .eml or .msg file", type=["eml", "msg"])
    if st.button("Analyze uploaded file", type="primary", key="btn_upload"):
        if up is not None:
            raw_bytes = up.getvalue()
            input_name = up.name
        else:
            st.warning("Upload a file first.")

with tab_sample:
    samples = _list_samples()
    if samples:
        choice = st.selectbox("Bundled sample emails", list(samples.keys()))
        if st.button("Analyze sample", type="primary", key="btn_sample"):
            raw_bytes = samples[choice].read_bytes()
            input_name = choice
    else:
        st.info("No bundled samples found in this deployment.")

# ---- Analyze + render ----------------------------------------------------
if raw_bytes is not None:
    if len(raw_bytes) > MAX_INPUT_BYTES:
        st.error(
            f"Input is {len(raw_bytes) // 1000} KB, over the "
            f"{MAX_INPUT_BYTES // 1000} KB limit. Trim it and try again."
        )
    elif _rate_limited():
        st.error(
            "Rate limit reached for this session. Wait a minute and try again."
        )
    else:
        _record_hit()
        with st.spinner("Analyzing…"):
            try:
                result = _run_analysis(raw_bytes, input_name, enrich)
            except Exception as exc:  # never leak a stack trace to the page
                st.error(f"Could not analyze this input: {exc}")
                result = None

        if result is not None:
            report = result.report
            emoji, color = BAND_STYLE.get(report.band, ("", "#444"))

            c1, c2, c3 = st.columns([2, 1, 1])
            with c1:
                st.markdown(
                    f"<h2 style='color:{color};margin:0'>{emoji} {report.band}</h2>",
                    unsafe_allow_html=True,  # our own static label, not user input
                )
            with c2:
                st.metric("Risk score", f"{report.score}/100")
            with c3:
                st.metric("IOCs found", len(report.iocs))

            if result.originating_ip:
                st.caption(f"Originating IP: `{result.originating_ip}`")
            if report.email.parse_warnings:
                st.warning("Parse notes: " + "; ".join(report.email.parse_warnings))

            md = render_markdown(report, result.auth, result.originating_ip)

            tab_report, tab_json = st.tabs(["📄 Triage report", "🧾 JSON"])
            with tab_report:
                # render_markdown emits only our own structured text with
                # defanged, backtick-wrapped indicators — safe for st.markdown,
                # which does not execute HTML here.
                st.markdown(md)
                st.download_button(
                    "Download Markdown report",
                    md,
                    file_name=f"{Path(input_name).stem}_report.md",
                    mime="text/markdown",
                )
            with tab_json:
                js = render_json(report)
                st.code(js, language="json")
                st.download_button(
                    "Download JSON report",
                    js,
                    file_name=f"{Path(input_name).stem}_report.json",
                    mime="application/json",
                )

st.divider()
st.caption(
    "Educational / triage aid. A low score is not proof an email is safe — "
    "when in doubt, escalate. Built by Maaz Husain."
)
