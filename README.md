# secure-dev-ai

Security by design CLI for AI-assisted development. Scans projects for secrets, vulnerable dependencies, insecure code patterns, and missing authentication coverage. Generates AI-powered STRIDE threat models. Integrates with `aahp-runner` as a guard hook to block autonomous agent runs when critical security issues are detected.

## Installation

```bash
npm install -g secure-dev-ai
```

Or run without installing:

```bash
npx secure-dev-ai scan my-project
```

## Quick Start

```bash
# Scan a single project
secure-dev-ai scan my-project

# Scan all projects in the workspace
secure-dev-ai scan --all

# See scores at a glance
secure-dev-ai list

# Full report for one project
secure-dev-ai report my-project
```

## Commands

### `scan [project]`

Scan one or all projects for security issues.

```bash
secure-dev-ai scan my-project
secure-dev-ai scan --all
secure-dev-ai scan --all --update-security-md    # writes SECURITY.md to each project
secure-dev-ai scan my-project --threat-model     # include AI threat model (needs API key)
secure-dev-ai scan my-project --json             # JSON output for scripting
```

### `list`

List all discovered projects with their last known security score and finding counts.

```bash
secure-dev-ai list
```

Output:

```
🔒 Security Status - 12 projects

  A  my-clean-project                     C: 0 H: 0 M: 1  today
  F  my-api                               C: 2 H: 5 M: 3  2d ago
  ?  new-project                          not yet scanned
```

### `report [project]`

Show the full findings from the last scan of a project.

```bash
secure-dev-ai report my-project
secure-dev-ai report my-project --json
```

### `guard`

Pre/post hook for `aahp-runner` agent runs. Exits 1 to block the run if critical findings are detected.

```bash
secure-dev-ai guard --project my-project --pre
secure-dev-ai guard --project my-project --post
secure-dev-ai guard --project my-project --pre --block-on HIGH
```

The guard command:
- Exits 0 (OK) when no blocking issues are found
- Exits 1 (BLOCKED) when findings at or above the threshold exist
- Exits 0 (fail-open) when the project cannot be found, to avoid breaking CI

### `threat-model [project]`

Generate an AI-powered STRIDE threat model for a project. Requires an Anthropic API key.
Writes the output to `THREAT-MODEL.md` in the project directory.

```bash
secure-dev-ai threat-model my-project
```

### `config`

Set persistent configuration stored at `~/.secure-dev-ai.json`.

```bash
secure-dev-ai config --api-key sk-ant-...         # set Anthropic API key
secure-dev-ai config --workspace /path/to/dev     # set workspace root
secure-dev-ai config --block-on HIGH              # tighten guard threshold
secure-dev-ai config --show                       # display current config (key masked)
```

## Scan Modules

### 1. Secrets (25+ patterns)

Detects hardcoded credentials and tokens:

- Anthropic, OpenAI, GitHub (PAT, OAuth), AWS (access key + secret), Google API keys
- Stripe live and test keys, Slack tokens, SendGrid, Twilio, GitLab tokens
- NPM auth tokens, SSH/RSA private keys, JWT tokens
- Database URLs with embedded credentials
- Hardcoded passwords, API key assignments, secret assignments
- Bearer and Basic auth headers

Skips `.env.example` placeholders, comments, and common false-positive patterns.

### 2. Dependencies (npm audit)

Runs `npm audit --json` and maps results:

- `critical` -> CRITICAL
- `high` -> HIGH
- `moderate` -> MEDIUM
- `low` -> LOW

Includes fix availability in remediation guidance.

### 3. Code Patterns (13 rules)

Detects insecure coding patterns:

- SQL injection via string concatenation and template literals with user input
- XSS via `dangerouslySetInnerHTML` and `innerHTML` with variables
- `eval()` and `new Function()` usage
- Path traversal (unsanitized `path.join`/`path.resolve` with user input)
- Command injection (`exec`/`execSync` with user input)
- Prototype pollution via `Object.assign`
- ReDoS via nested quantifiers in dynamic `RegExp`
- Hardcoded localhost URLs in production code
- `console.log` with sensitive field names
- Security-flagged TODO/FIXME comments

### 4. Authentication Coverage

Checks HTTP API projects for authentication:

- Detects whether any auth middleware is present at all
- Flags `POST`, `PUT`, `PATCH`, `DELETE` routes that lack auth middleware in their context window
- Skips test files and non-server projects

### 5. Threat Model (AI, STRIDE)

Uses `claude-haiku-4-5` to generate a concise STRIDE threat model:

- Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- 3-7 most relevant threats for the specific project
- Writes `THREAT-MODEL.md` to the project directory
- Skips gracefully if no API key is configured

## Security Scoring

Scores are computed from a weighted penalty system:

| Grade | Score | Criteria                         |
|-------|-------|----------------------------------|
| A     | 90+   | Clean or near-clean              |
| B     | 75+   | Minor issues, no CRITICAL/HIGH   |
| C     | 60+   | Some medium/high issues          |
| D     | 40+   | Multiple high-severity issues    |
| F     | any   | Any CRITICAL finding present     |

Penalty weights: CRITICAL = 30, HIGH = 10, MEDIUM = 3, LOW = 1

## Integrating with aahp-runner

Add guard hooks to your aahp-runner configuration to block agent runs when critical
security issues are detected in the target project:

```typescript
// In aahp-runner, before starting an agent run:
import { execSync } from 'child_process';

function runGuard(projectName: string, phase: 'pre' | 'post'): boolean {
  try {
    execSync(`secure-dev-ai guard --project ${projectName} --${phase}`, {
      stdio: 'inherit',
    });
    return true; // OK
  } catch {
    return false; // BLOCKED
  }
}

// Pre-run check
if (!runGuard(projectName, 'pre')) {
  console.error('Agent run blocked by secure-dev-ai guard.');
  process.exit(1);
}
```

Use `--block-on HIGH` to also block on high-severity findings, not just critical.

## Reports and Output Files

- **JSON reports:** `~/.secure-dev-ai/reports/<project>-<date>.json`
- **SECURITY.md:** Written to the project directory with `--update-security-md`
- **THREAT-MODEL.md:** Written to the project directory by `threat-model` command

## Requirements

- Node.js 20 or higher
- npm (for `deps` scanner)
- Anthropic API key (optional, for `threat-model` only)

## License

MIT
