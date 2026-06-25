# ANTIGRAVITY-AUDIT

`antigravity-audit` is a read-only local security audit tool for the **Antigravity** (Google DeepMind agent environment) configuration on Windows (PowerShell) and macOS (Zsh).

It audits local MCP connections, registered workspace projects, trusted folders, customization rules/skills, sensitive credentials, process runtimes, and local data retention limits. It reports findings classified by severity: `WARN`, `REVIEW`, and `INFO`.

> **Unofficial project.** Not affiliated with, endorsed by, sponsored by, or maintained by Google or DeepMind.

This project is a sibling tool of [claude-audit](../claude-audit) and [codex-audit](../codex-audit), sharing the same output schema to work seamlessly with the [audit-viewer](../audit-viewer) integrated dashboard.

## Features

- **Read-only**: Never modifies or deletes any of your local files or settings.
- **Self-contained**: Minimal external dependencies (uses standard PowerShell on Windows, standard Zsh on macOS. Recommends `jq` for deep JSON inspections on macOS).
- **Token Redaction**: Automatically sanitizes sensitive OAuth values (access tokens, refresh tokens, auth keys) in output representation.
- **Policy Gate Mode**: Supports `--fail-on warn|review` exit status checks for CI/CD, automation hooks, or local pre-commit checks.

## Audited Areas

| Section | Description |
|---|---|
| Config | Evaluates `settings.json` model overrides, session retention duration, and config schema. |
| Projects | Inspects registered projects and scans workspace-scoped `.agents` customizations (skills and rules). |
| Trusted Folders | Checks folders configured with pre-approved execution authority (`trustedFolders.json`). Warns (`WARN`) on active folders due to higher agent autonomy. |
| Skills | Discovers active agent skills/actions (under global `config/skills` and project `.agents/skills`) and scans for custom script file extensions. |
| Sensitive Files | Scans permission levels of credentials (`oauth_creds.json`) and warns if permissions are too broad. |
| Retention | Calculates item count, sizes, and modification timestamps for `history/`, `tmp/`, and agent session brain logs. |
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
```

## Options

| Option | Description |
|---|---|
| `--json` | Outputs report in structured JSON format. |
| `--html [FILE]` | Generates a standalone HTML report (auto-named if `FILE` omitted). |
| `--summary` | Prints a single-line summary with critical findings. |
| `--output FILE` | Writes output directly to the specified file path. |
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
