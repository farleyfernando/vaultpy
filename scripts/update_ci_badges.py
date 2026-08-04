"""Generate CI badges from pytest and coverage reports."""

from __future__ import annotations

import argparse
import json
import math
import xml.etree.ElementTree as ET
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate SVG badges from CI reports.")
    parser.add_argument("--junitxml", type=Path, required=True, help="Path to the pytest JUnit XML report.")
    parser.add_argument("--coveragejson", type=Path, required=True, help="Path to the coverage JSON report.")
    parser.add_argument("--output", type=Path, required=True, help="Directory where badges will be written.")
    return parser


def read_test_stats(junitxml: Path) -> tuple[int, int]:
    root = ET.parse(junitxml).getroot()
    suite = root.find("testsuite")
    if suite is None:
        raise ValueError("JUnit XML report does not contain a testsuite element.")
    tests = int(suite.attrib["tests"])
    failures = int(suite.attrib.get("failures", 0))
    errors = int(suite.attrib.get("errors", 0))
    skipped = int(suite.attrib.get("skipped", 0))
    passed = tests - failures - errors - skipped
    return passed, tests


def read_coverage_percent(coveragejson: Path) -> float:
    with coveragejson.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return float(payload["totals"]["percent_covered"])


def color_for_percent(percent: float) -> str:
    if percent >= 95:
        return "#2ea44f"
    if percent >= 90:
        return "#22863a"
    if percent >= 80:
        return "#dbab09"
    return "#d73a49"


def escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def badge_svg(label: str, message: str, color: str) -> str:
    label_width = 10 + len(label) * 7
    message_width = 10 + len(message) * 7
    width = label_width + message_width
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{escape(label)}: {escape(message)}">
  <title>{escape(label)}: {escape(message)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="m">
    <rect width="{width}" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#m)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{message_width}" height="20" fill="{color}"/>
    <rect width="{width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_width / 2:.1f}" y="14">{escape(label)}</text>
    <text x="{label_width + message_width / 2:.1f}" y="14">{escape(message)}</text>
  </g>
</svg>
"""


def write_badge(path: Path, label: str, message: str, color: str) -> None:
    path.write_text(badge_svg(label, message, color), encoding="utf-8")


def main() -> int:
    args = build_parser().parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    passed, total = read_test_stats(args.junitxml)
    test_percent = 0.0 if total == 0 else (passed / total) * 100.0
    coverage_percent = read_coverage_percent(args.coveragejson)

    write_badge(
        args.output / "tests.svg",
        "tests",
        f"{passed}/{total} ({test_percent:.0f}%)",
        color_for_percent(test_percent),
    )
    write_badge(
        args.output / "coverage.svg",
        "coverage",
        f"{coverage_percent:.2f}%",
        color_for_percent(coverage_percent),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
