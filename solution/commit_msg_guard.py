#!/usr/bin/env python3
"""Reject commit messages that GitHub would render as references to someone else's issue or PR.

Why this exists: a bare `#123`, an `owner/repo#123`, or an issue/PR URL inside a commit
message is auto-linked by GitHub. When the referenced item is a pull request, GitHub
notifies its subscribers -- so a commit in this repository can page a stranger whose PR
number happened to match. That is an outward-facing action nobody here asked for.

The rule: a commit body names an item in words ("engine issue 499", "challenge PR 3")
and never in reference syntax. The number stays readable; the link does not exist.

Usage:
    python solution/commit_msg_guard.py <message-file>
    python solution/commit_msg_guard.py --selftest

Exit codes: 0 clean, 1 at least one linking token found, 2 usage error.
"""

from __future__ import annotations

import pathlib
import re
import sys

PATTERNS = [
    (re.compile(r"#\d+"), "bare reference (#123) -- write 'issue 123' or 'PR 123' instead"),
    (
        re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#\d+"),
        "cross-repo reference (owner/repo#123)",
    ),
    (
        re.compile(r"https?://(?:www\.)?github\.com/\S+?/(?:issues|pull)/\d+"),
        "issue/PR URL",
    ),
]

# Cases the guard must NOT fire on: this repository's own check counts, paths, versions.
CLEAN_SAMPLES = [
    "verify: 36 checks, 0 failures, exit 0\n\nC3 is the load-bearing group: 315/315 lengths, 21/21 blocks.\n",
    "docs: 1829 edges, noise_entropy_bits=128, include/pvac/core/types.hpp:209-219\n",
    "fix: run python solution/verify.py; 36 checks, 0 failures\n",
    "docs: cite solution/RESULT.md section 3 and PR 3 in words\n",
]

DIRTY_SAMPLES = [
    "watch\n\nengine #490 closed + #499-#503 open\n",
    "observe octra-labs/pvac_hfhe_cpp#499 before other work\n",
    "see https://github.com/octra-labs/hfhe-challenge/pull/3 for the audit\n",
]


def scan(text: str) -> list[tuple[int, str, str]]:
    """Return (line_number, matched_text, explanation) for every linking token."""
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pattern, why in PATTERNS:
            for match in pattern.finditer(line):
                hits.append((lineno, match.group(0), why))
    return hits


def selftest() -> int:
    failures = 0
    for sample in CLEAN_SAMPLES:
        hits = scan(sample)
        if hits:
            failures += 1
            print(f"SELFTEST FAIL (false positive): {hits} in {sample!r}")
    for sample in DIRTY_SAMPLES:
        if not scan(sample):
            failures += 1
            print(f"SELFTEST FAIL (false negative): {sample!r}")
    print(f"selftest: {len(CLEAN_SAMPLES)} clean samples, {len(DIRTY_SAMPLES)} dirty samples, "
          f"failures={failures}")
    return 0 if failures == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    if len(argv) != 2:
        print("usage: commit_msg_guard.py <message-file> | --selftest", file=sys.stderr)
        return 2

    path = pathlib.Path(argv[1])
    # A comment-only or empty message (merge, --amend without -m) has nothing to link.
    text = path.read_text(encoding="utf-8", errors="replace")
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    hits = scan(body)
    if not hits:
        return 0

    print("commit message rejected: it would page another account's issue or PR.\n")
    for lineno, token, why in hits:
        print(f"  line {lineno}: {token!r} -- {why}")
    print(
        "\nRewrite the reference in words, e.g. 'engine issue 499' or 'challenge PR 3'.\n"
        "The number stays readable; the auto-link (and the notification it sends) does not exist.\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
