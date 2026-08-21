# ANTIGRAVITY-AUDIT

`antigravity-audit` is a read-only local security audit tool for the **Antigravity** (Google DeepMind agent environment) configuration on Windows (PowerShell) and macOS (Zsh).

It audits local and remote MCP server integrations, lifecycle hooks, plugins, workspace projects, trusted folders, customization rules/skills, security and sandbox policies, CLI and IDE settings, sensitive credentials, process runtimes, and local data retention limits. It reports findings classified by severity: `WARN`, `REVIEW`, and `INFO`.

> **Unofficial project.** Not affiliated with, endorsed by, sponsored by, or maintained by Google or DeepMind.

This project is a sibling tool of [claude-audit](../claude-audit) and [codex-audit](../codex-audit), sharing the same output schema to work seamlessly with the [audit-viewer](../audit-viewer) integrated dashboard.

## Features

- **Read-only**: Never modifies or deletes any of your local files or settings.
- **Self-contained**: Minimal external dependencies (uses standard PowerShell on Windows, standard Zsh on macOS. Recommends `jq` for deep JSON inspections on macOS).
- **Token Redaction**: Automatically sanitizes sensitive OAuth values, API keys, tokens, and credentials in output representation.
- **Snapshot Diffing**: Compare current configurations against historical snapshots using `--diff BASELINE.json`.
- **Policy Gate Mode**: Supports `--fail-on warn|review` exit status checks for CI/CD, automation hooks, or local pre-commit checks.

## Audited Areas

| Section | Description |
|---|---|
| Config | Evaluates `settings.json`, Antigravity 2.0 app settings, and CLI (`antigravity-cli/settings.json`) configuration and default model. |
| Security Settings | Audits critical security settings: Tool Execution Policy (`always-proceed` triggers `WARN`), Terminal Sandbox mode (`sandbox.enabled: false` triggers `WARN`), non-workspace file access policy (`allow` triggers `WARN`), unrestricted internet access (`allow`), browser allowlists, and command allowlists. |
| MCP Servers | Audits `mcp_config.json` (global, workspace, plugins). Warns on dangerous command runners (bash, python, node, curl, ssh, etc.) and unencrypted HTTP SSE endpoints; masks sensitive environment variables. |
| Lifecycle Hooks | Inspects `hooks.json` (global, workspace, plugins) across all supported lifecycle events (`PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`). Evaluates risk tags for privileged or destructive commands. |
| Plugins | Scans `plugins/`, `plugin.json` manifests, active states in `config.json`, and bundled capabilities (`skills`, `rules`, `hooks`, `mcp`). |
| Customizations | Scans `skills.json` and `plugins.json` for external paths and inheritance trees. |
| Projects | Inspects registered projects and scans workspace-scoped `.agents` customizations (skills, rules, hooks, plugins, and project-specific settings). |
| Trusted Folders | Checks folders configured with pre-approved execution authority (`trustedFolders.json`). Warns (`WARN`) on active folders due to higher agent autonomy. |
| Skills & Rules | Discovers active agent skills (`skills/*/SKILL.md`) and rule files (`GEMINI.md`, `AGENTS.md`, `.agents/rules/*.md`), detecting helper script files. |
| Sensitive Files | Scans permission levels of credentials (`oauth_creds.json`, `google_accounts.json`), settings, and config files; warns if permissions are too broad. |
| Retention | Calculates item count, sizes, and modification timestamps for `history/`, `tmp/`, `antigravity-cli/`, and agent session brain logs. |
| Runtime | Checks running OS processes related to the antigravity environment. |

## Quick Start

### Windows (PowerShell)

```powershell
# Run the audit and print a terminal report
.\antigravity_audit.ps1

# Print only high-severity findings
.\antigravity_audit.ps1 --summary

# Export JSON snapshot for audit-viewer integration
.\antigravity_audit.ps1 --json --output snapshot.json

# Diff against a baseline snapshot
.\antigravity_audit.ps1 --diff baseline.json

# Generate HTML report
.\antigravity_audit.ps1 --html report.html
```

### macOS (Zsh)

```bash
chmod +x ./antigravity_audit.sh

# Run audit
./antigravity_audit.sh

# Export JSON snapshot
./antigravity_audit.sh --json --output snapshot.json

# Diff against a baseline snapshot
./antigravity_audit.sh --diff baseline.json

# Generate HTML report
./antigravity_audit.sh --html report.html
```

## Options

| Option | Description |
|---|---|
| `--json` | Outputs report in structured JSON format. |
| `--html [FILE]` | Generates a standalone HTML report (auto-named if `FILE` omitted). |
| `--summary` | Prints a single-line summary with critical findings. |
| `--output FILE` | Writes output directly to the specified file path. |
| `--diff BASELINE.json` | Diffs current audit state against a baseline JSON snapshot. |
| `--diff-json` | Outputs diff results in JSON format (used with `--diff`). |
| `--fail-on warn\|review` | Exits with non-zero code if specific severity is present (warn=2, review=1). |
| `--redact-paths` | Masks user account names and home directory paths in findings. |
| `--user USER` | Audits another specific user on the machine. |
| `--all-users` | Scans all user profiles with Antigravity config (requires administrator privileges). |
| `--antigravity-dir DIR` | Explicitly targets a custom `.gemini` directory path. |
| `-q, --quiet` | Hides low-severity `INFO` level findings. |

## Exit Codes

- `0`: Completed successfully with no triggered gate conditions.
- `1`: Gate condition triggered by `REVIEW` severity, or invalid arguments.
- `2`: Gate condition triggered by `WARN` severity.

## License

MIT
