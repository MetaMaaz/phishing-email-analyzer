"""Command-line entry point.

    python -m src.cli analyze path/to/email.eml
    python -m src.cli batch   path/to/folder/

Uses stdlib ``argparse`` (no third-party CLI dependency) so the tool runs
fully offline with nothing installed beyond Python itself. Enrichment is on by
default but silently skips when no API keys are configured; pass
``--no-enrich`` to force a purely local run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_config
from .pipeline import analyze_to_files
from .report import now_iso

_EMAIL_EXTS = (".eml", ".msg")


def _cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config()
    path = Path(args.path)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    md, js, result = analyze_to_files(
        path, args.out, config=config, enrich=not args.no_enrich
    )
    r = result.report
    print(f"[{r.band}] score={r.score}/100  {path.name}")
    print(f"  markdown: {md}")
    print(f"  json:     {js}")
    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    config = load_config()
    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"error: not a folder: {folder}", file=sys.stderr)
        return 2

    emails = sorted(
        p for p in folder.iterdir()
        if p.is_file() and p.suffix.lower() in _EMAIL_EXTS
    )
    if not emails:
        print(f"no .eml/.msg files found in {folder}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    rows: list[tuple[str, int, str, str]] = []
    for p in emails:
        try:
            md, _js, result = analyze_to_files(
                p, out_dir, config=config, enrich=not args.no_enrich
            )
            r = result.report
            rows.append((p.name, r.score, r.band, md.name))
            print(f"[{r.band}] score={r.score}/100  {p.name}")
        except Exception as exc:
            rows.append((p.name, -1, "ERROR", "—"))
            print(f"[ERROR] {p.name}: {exc}", file=sys.stderr)

    _write_index(out_dir, rows)
    print(f"\nSummary index: {out_dir / 'index.md'}")
    return 0


def _write_index(out_dir: Path, rows: list[tuple[str, int, str, str]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    order = {"Malicious": 0, "Suspicious": 1, "Low": 2, "ERROR": 3}
    rows_sorted = sorted(rows, key=lambda r: (order.get(r[2], 9), -r[1]))
    lines = [
        "# Batch triage summary",
        "",
        f"_Generated {now_iso()} · {len(rows)} email(s) analysed._",
        "",
        "| Verdict | Score | Email | Report |",
        "|---------|------:|-------|--------|",
    ]
    emoji = {"Malicious": "🔴", "Suspicious": "🟠", "Low": "🟢", "ERROR": "⚠️"}
    for name, score, band, report in rows_sorted:
        score_str = "—" if score < 0 else f"{score}/100"
        link = f"[{report}]({report})" if report != "—" else "—"
        lines.append(f"| {emoji.get(band,'')} {band} | {score_str} | `{name}` | {link} |")
    lines.append("")
    (out_dir / "index.md").write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Static SOC phishing-triage tool: parse, analyse, score, report.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("analyze", help="analyse a single .eml/.msg file")
    pa.add_argument("path", help="path to the email file")
    pa.add_argument("--out", default="reports", help="output directory (default: reports)")
    pa.add_argument("--no-enrich", action="store_true",
                    help="skip all network enrichment (fully offline)")
    pa.set_defaults(func=_cmd_analyze)

    pb = sub.add_parser("batch", help="analyse every .eml/.msg in a folder")
    pb.add_argument("folder", help="folder containing email files")
    pb.add_argument("--out", default="reports", help="output directory (default: reports)")
    pb.add_argument("--no-enrich", action="store_true",
                    help="skip all network enrichment (fully offline)")
    pb.set_defaults(func=_cmd_batch)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
