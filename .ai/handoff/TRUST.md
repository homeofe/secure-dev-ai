# TRUST REGISTER - secure-dev-ai

> Documents all external systems, APIs, and data sources this project interacts with.

## External Dependencies

| System          | Trust Level | Notes                                                  |
|-----------------|-------------|--------------------------------------------------------|
| npm registry    | HIGH        | Package installs only. Lock file committed.            |
| Anthropic API   | HIGH        | Used for threat model generation. Key never committed. |
| Local filesystem| MEDIUM      | Reads project files. Scoped to project path only.      |
| npm audit       | HIGH        | Subprocess call, reads package.json only.              |

## Data Handling

- **No PII stored**: scan reports contain file paths and code snippets only
- **No secrets logged**: API keys masked in config --show output
- **Reports local only**: `~/.secure-dev-ai/reports/` - never sent anywhere
- **Threat model**: project context sent to Anthropic API (README, package.json only)

## Agent Constraints

- Agents must not scan files outside the declared project boundary
- Agents must not store API keys in source files
- Agents must not send full source code to external APIs (only README + package.json for threat model)
- Guard command fails open (exit 0) when project is not found, to avoid blocking CI by mistake

## Key Rotation

If Anthropic API key is compromised:
1. Revoke at console.anthropic.com
2. Run `secure-dev-ai config --api-key <new-key>`
3. The key lives only in `~/.secure-dev-ai.json` (local, not in repo)
