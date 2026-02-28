# secure-dev-ai: Agent Conventions

> Every agent working on this project must read and follow these conventions.
> Update this file whenever a new standard is established.

---

## The Three Laws (Our Motto)

> **First Law:** A robot may not injure a human being or, through inaction, allow a human being to come to harm.
>
> **Second Law:** A robot must obey the orders given it by human beings except where such orders would conflict with the First Law.
>
> **Third Law:** A robot must protect its own existence as long as such protection does not conflict with the First or Second Laws.
>
> *- Isaac Asimov*

We are human beings and will remain human beings. Tasks are delegated to AI only when we choose to delegate them. **Do no damage** is the highest rule.

---

## Language

- All code, comments, commits, and documentation in **English only**
- Use clear, direct language in handoff files (agents are the primary readers)

## Code Style

- **TypeScript:** strict mode, ESM (`"type": "module"`), no `any` unless unavoidable
- **Imports:** always use `.js` extension in ESM imports (e.g. `import { foo } from './bar.js'`)
- **JSON:** 2-space indentation, no trailing commas
- **Markdown:** ATX headers, tables with alignment, code blocks with language tags
- **No em dashes:** never use Unicode em dashes anywhere - use a regular hyphen (`-`)

## Branching and Commits

```
feat/<scope>-<short-name>    - new feature
fix/<scope>-<short-name>     - bug fix
docs/<scope>-<short-name>    - documentation only
refactor/<scope>-<name>      - no behaviour change

Commit format:
  feat(scope): description [AAHP-auto]
  fix(scope): description [AAHP-auto]
  docs(scope): description [AAHP-auto]
```

## File Organization

- `src/` - TypeScript source files
  - `cli.ts` - Commander.js entry point (commands: scan, list, report, guard, threat-model, config)
  - `scanner.ts` - Scan orchestrator and scoring engine
  - `report.ts` - Report persistence and SECURITY.md generation
  - `projects.ts` - Project discovery across the workspace
  - `config.ts` - Persistent config at `~/.secure-dev-ai.json`
  - `types.ts` - Shared TypeScript interfaces
  - `scanners/` - Individual scanner modules
    - `secrets.ts` - 25+ secret/credential pattern detection
    - `deps.ts` - npm audit integration
    - `patterns.ts` - Insecure code pattern detection
    - `auth.ts` - Authentication coverage analysis
    - `threatModel.ts` - AI-powered STRIDE threat modeling
  - `tests/` - Vitest test suite
    - `fixtures/` - Intentionally insecure code for testing
- `dist/` - Compiled output (do not edit)
- `.ai/handoff/` - AAHP handoff files

## Architecture Principles

- **5 scan modules run in parallel** via `Promise.allSettled`
- **Scoring:** A (90+), B (75+), C (60+), D (40+), F (critical found or <40)
- **Guard hook:** exits 1 to block aahp-runner when CRITICAL findings exist
- **Reports stored** in `~/.secure-dev-ai/reports/` as JSON
- **Config stored** at `~/.secure-dev-ai.json`

## Build and Compile

- `npm run build` - compiles TypeScript to `dist/`
- `npm run dev` - run with ts-node directly (dev only)
- `npm test` - run Vitest test suite
- Always run `npm run build` before committing to verify compilation

## Testing

- Tests use Vitest with ESM support
- Fixture files in `src/tests/fixtures/` contain intentional security issues
- Run `npm test` before every commit

## What Agents Must NOT Do

- **Violate the Three Laws** - never cause damage to data, systems, or people
- Push directly to `main` without human approval
- Write secrets, credentials, or API keys into any file
- Delete existing source files without providing a replacement
- Use em dashes anywhere in the codebase
- Modify `~/.secure-dev-ai.json` directly (use the config command)
- Scan files outside the project boundary

---

*This file is maintained by agents and humans together. Update it when conventions evolve.*
