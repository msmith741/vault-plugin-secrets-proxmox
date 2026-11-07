#!/usr/bin/env python3
"""Validate Markdown relative links/anchors and generic example content.

Run with: python3 scripts/validate_docs.py
No third-party Python packages or network access are required.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
LINK = re.compile(r"!?\[[^\]\n]*\]\(([^)\n]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)
# Reject hard-coded private network addresses and non-example local domains
# in reusable documentation. RFC 5737 / .invalid addresses remain suitable.
PRIVATE_IPV4 = re.compile(r"\b(?:10|192\.168)\.(?:\d{1,3}\.){2}\d{1,3}\b")
LOCAL_DOMAIN = re.compile(r"\b[a-z0-9-]+\.home\.[a-z0-9.-]+\b", re.I)


def slug(heading: str) -> str:
    # Matching GitHub's common Markdown heading behavior for these docs.
    text = re.sub(r"[^\w\- ]", "", heading.lower().strip())
    return text.replace(" ", "-")


def main() -> int:
    problems: list[str] = []
    for path in FILES:
        source = path.relative_to(ROOT).as_posix()
        content = path.read_text(encoding="utf-8")
        if PRIVATE_IPV4.search(content) or LOCAL_DOMAIN.search(content):
            problems.append(f"{source}: use generic example hosts/addresses")

        for match in LINK.finditer(content):
            href = match.group(1).strip()
            if href.startswith(("https://", "http://", "mailto:", "#")) and not href.startswith("#"):
                continue
            if href.startswith("<") or href.startswith("data:"):
                continue
            target_path, _, fragment = unquote(href).partition("#")
            target = (path.parent / (target_path or path.name)).resolve()
            if not target.is_relative_to(ROOT):
                problems.append(f"{source}: link escapes repository: {href}")
                continue
            if not target.is_file():
                problems.append(f"{source}: broken relative link: {href}")
                continue
            if fragment and target.suffix.lower() == ".md":
                headings = {slug(x) for x in HEADING.findall(target.read_text(encoding="utf-8"))}
                if fragment not in headings:
                    problems.append(f"{source}: missing anchor {fragment!r} in {target.relative_to(ROOT)}")

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"Validated {len(FILES)} Markdown files: relative links, anchors and example address hygiene")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
