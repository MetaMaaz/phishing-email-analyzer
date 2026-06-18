# Deploying the live demo

The repo ships a Streamlit web UI (`app.py`) that wraps the existing CLI
pipeline. It lets anyone paste/upload a suspicious email and get the same
SOC-style triage report the CLI produces — a clickable demo for your portfolio.

The UI adds **no** analysis logic. It calls `src.pipeline.analyze` and renders
`render_markdown` / `render_json`, so the demo and the CLI can never disagree.

---

## Run it locally first

```bash
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501, go to **Try a sample**, pick one, and confirm you
get a verdict + report. That's the whole app.

---

## Deploy free on Streamlit Community Cloud

This is the lowest-effort host for a Python app and deploys straight from GitHub.

1. Push everything to GitHub (`app.py`, `src/`, `samples/`, `requirements.txt`,
   `.streamlit/config.toml`).
2. Go to **https://share.streamlit.io** and sign in with GitHub.
3. **Create app** → pick `MetaMaaz/phishing-email-analyzer`, branch `main`,
   main file `app.py`.
4. **Deploy**. First build installs `requirements.txt` (a few minutes — oletools
   and friends are chunky). You'll get a public URL like
   `https://phishing-email-analyzer-metamaaz.streamlit.app`.
5. Put that URL in your repo's **About → Website** field (the box in your
   screenshot), and link it from your "My website" portfolio page.

### Optional: enable live threat-intel enrichment

By default the demo runs **fully offline** — no outbound lookups. If you want
the VirusTotal / AbuseIPDB / URLhaus enrichment available in the UI, add keys as
**secrets** (never commit them):

In the Streamlit Cloud app → **Settings → Secrets**, paste:

```toml
VT_API_KEY = "your-virustotal-key"
ABUSEIPDB_API_KEY = "your-abuseipdb-key"
URLHAUS_AUTH_KEY = "your-urlhaus-key"
```

The app only shows the enrichment toggle when at least one key is present, and
the toggle still defaults to **off**. Keys are read from secrets/env only —
never from anything a visitor types.

---

## Security notes (read before you make it public)

This demo is **attacker-facing** the moment it's public — strangers will feed it
hostile input. The design already accounts for that; don't undo these:

- **Static analysis only.** No attachment is executed/detonated and no link in
  an email is ever fetched. This lives in the pipeline; the UI never weakens it.
- **Enrichment off by default**, keys from secrets only. Leaving it off means
  zero outbound requests driven by visitor input.
- **Size cap.** `.streamlit/config.toml` caps uploads at 2 MB and the app
  rejects input over ~1.5 MB before parsing.
- **No HTML rendering of the email body.** Only the structured report and
  defanged indicators are shown, so a malicious HTML email can't script this page.
- **No persistence.** Uploaded bytes go to a private temp file that's deleted
  right after analysis.
- **Soft rate limit** (10 analyses/min per session) to blunt abuse.
- **Don't expose real secrets** in screenshots or `.env`. `.env.example` is the
  only env file that belongs in git.

### Other hosts (if you outgrow Community Cloud)

- **Hugging Face Spaces** — same Streamlit model, popular in security/ML portfolios.
- **Render / Railway / Fly.io** — if you later wrap this in a FastAPI service or
  need a custom domain / always-on instance.

---

## For the job hunt

Lead recruiters here: **My website (portfolio hub) → this live demo → GitHub repo.**
A hiring manager can triage a sample email in 10 seconds, then read your code.
That loop — working tool + clean repo + clear write-up — is what gets a SOC /
blue-team callback.
