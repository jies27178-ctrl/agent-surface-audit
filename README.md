# Agent Surface Audit

Agent Surface Audit is a small, dependency-free Python CLI for reviewing AI-agent, Skill, plugin, and automation repositories before merge or release.

It highlights common high-risk patterns without executing repository code:

- possible credentials in source or configuration;
- remote content piped directly into a shell;
- dynamic code execution;
- destructive filesystem commands;
- configuration that appears to grant shell or network access.

## Why this exists

Agent extensions can combine prompts, files, shell commands, network access, API credentials, and third-party code. A lightweight scanner gives maintainers a repeatable first-pass check for pull requests and releases.

## Install and run

    python -m pip install .
    agent-surface-audit path/to/repository

JSON output and CI-friendly exit behavior:

    agent-surface-audit . --format json --fail-on medium

--fail-on high is the default. Use --fail-on none when collecting findings without failing a job.

## Scope and limitations

This tool is intentionally rule-based. A finding is a review signal, not proof of a vulnerability. It does not execute scanned files, upload content, or make network requests. Review findings in project context before acting on them.

## Development

    python -m unittest discover -s tests -v
    python -m agent_surface_audit.cli . --fail-on none

## Contributing

Please open an issue before large changes. Pull requests should include tests for new or changed detection rules. Do not include live credentials in test fixtures, issues, or pull requests.

## Security

See SECURITY.md for vulnerability reporting guidance.

## License

MIT. See LICENSE.
