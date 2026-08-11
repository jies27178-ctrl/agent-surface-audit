"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from .scanner import findings_as_dicts, scan_path

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent-surface-audit",
        description="Scan AI agent, skill, plugin, and automation repositories for common risks.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory to scan.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=("none", "medium", "high"), default="high")
    args = parser.parse_args()

    findings = scan_path(Path(args.path))
    if args.format == "json":
        print(json.dumps({"findings": findings_as_dicts(findings)}, indent=2))
    else:
        if not findings:
            print("No findings.")
        for finding in findings:
            print(
                f"{finding.severity.upper():6} {finding.rule_id} "
                f"{finding.path}:{finding.line} — {finding.message}"
            )
    threshold = {"none": 4, "medium": 2, "high": 3}[args.fail_on]
    severities = {"medium": 2, "high": 3}
    return 1 if any(severities[item.severity] >= threshold for item in findings) else 0

if __name__ == "__main__":
    raise SystemExit(main())
