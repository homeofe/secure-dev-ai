# DASHBOARD - secure-dev-ai

> Security by design CLI for AI-assisted development.

## Quick Reference

```bash
secure-dev-ai scan <project>          # Scan a project
secure-dev-ai scan --all              # Scan all projects
secure-dev-ai list                    # Show all project scores
secure-dev-ai report <project>        # Show detailed findings
secure-dev-ai guard --project <name> --pre   # Pre-run hook (blocks on CRITICAL)
secure-dev-ai threat-model <project>  # Generate STRIDE threat model
secure-dev-ai config --show           # Show current config
```

## Components

| Component              | File                          | Status  |
|------------------------|-------------------------------|---------|
| CLI entry point        | src/cli.ts                    | done    |
| Scan orchestrator      | src/scanner.ts                | done    |
| Report persistence     | src/report.ts                 | done    |
| Project discovery      | src/projects.ts               | done    |
| Config management      | src/config.ts                 | done    |
| Type definitions       | src/types.ts                  | done    |
| Secrets scanner        | src/scanners/secrets.ts       | done    |
| Deps scanner           | src/scanners/deps.ts          | done    |
| Patterns scanner       | src/scanners/patterns.ts      | done    |
| Auth scanner           | src/scanners/auth.ts          | done    |
| Threat model scanner   | src/scanners/threatModel.ts   | done    |
| Test suite             | src/tests/scanner.test.ts     | done    |
| Test fixtures          | src/tests/fixtures/           | done    |
| CI workflow            | .github/workflows/ci.yml      | done    |
| README                 | README.md                     | done    |

## Scoring

| Grade | Score | Condition          |
|-------|-------|--------------------|
| A     | 90+   | No CRITICAL/HIGH   |
| B     | 75+   | Minor issues only  |
| C     | 60+   | Some HIGH issues   |
| D     | 40+   | Multiple HIGH      |
| F     | any   | Any CRITICAL found |

## Scan Modules

1. **secrets** - 25+ patterns: API keys, tokens, private keys, DB URLs, hardcoded creds
2. **deps** - npm audit integration, maps severity to CRITICAL/HIGH/MEDIUM/LOW
3. **patterns** - SQL injection, XSS, eval, command injection, path traversal, etc.
4. **auth** - Detects unprotected mutation routes, missing auth middleware
5. **threat-model** - STRIDE analysis via Claude claude-haiku-4-5 (requires API key)

## Config Location

- Config: `~/.secure-dev-ai.json`
- Reports: `~/.secure-dev-ai/reports/<project>-<date>.json`

## Integration Status

- aahp-runner guard hook: **T-011 pending** (see NEXT_ACTIONS.md)
