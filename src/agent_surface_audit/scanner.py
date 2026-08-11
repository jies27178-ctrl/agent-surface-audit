"""Rule-based scanner for common AI-agent repository risks."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re

TEXT_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".js", ".ts", ".sh", ".ps1"}
SKIP_PARTS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    evidence: str

RULES = (
    (
        "ASA001",
        "high",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
        "Potential credential in source or configuration.",
    ),
    (
        "ASA002",
        "high",
        re.compile(r"(?i)(?:curl|wget|irm|iwr)\b[^\n|]*\|\s*(?:sh|bash|zsh|iex|invoke-expression)\b"),
        "Remote content is piped directly into a shell.",
    ),
    (
        "ASA003",
        "high",
        re.compile(r"(?i)\b(?:eval|exec|invoke-expression)\s*\("),
        "Dynamic code execution is present.",
    ),
    (
        "ASA004",
        "medium",
        re.compile(r"(?i)\b(?:rm\s+-rf|remove-item\s+.*-recurse.*-force|rmdir\s+/s\s+/q)\b"),
        "Destructive filesystem command is present.",
    ),
    (
        "ASA005",
        "medium",
        re.compile(r"(?i)(?:shell|terminal|command)[^\n]{0,80}(?:enabled|allow|true)"),
        "A configuration appears to grant command or shell execution.",
    ),
    (
        "ASA006",
        "medium",
        re.compile(r"(?i)(?:network|http|fetch|web)[^\n]{0,80}(?:enabled|allow|true)"),
        "A configuration appears to grant network access.",
    ),
)

def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            yield path

def _redact(text: str) -> str:
    if len(text) <= 120:
        return text
    return text[:117] + "..."

def scan_path(root: Path) -> list[Finding]:
    """Scan text files below root and return deterministic findings."""
    root = root.resolve()
    findings: list[Finding] = []
    for file_path in sorted(_iter_files(root)):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        relative = file_path.relative_to(root).as_posix()
        for number, line in enumerate(lines, start=1):
            for rule_id, severity, pattern, message in RULES:
                if pattern.search(line):
                    evidence = "[redacted]" if rule_id == "ASA001" else _redact(line.strip())
                    findings.append(Finding(rule_id, severity, relative, number, message, evidence))
    return findings

def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(finding) for finding in findings]
