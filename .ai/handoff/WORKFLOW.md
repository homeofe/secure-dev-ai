# WORKFLOW - secure-dev-ai

## Development Pipeline (4 Phases)

### Phase 1: Scan

Identify security issues before making changes.

```bash
# Scan the project itself
secure-dev-ai scan secure-dev-ai

# Or scan any project in the workspace
secure-dev-ai scan <project-name>
```

### Phase 2: Develop

Make changes to the codebase. Follow CONVENTIONS.md.

```bash
# Run in dev mode (ts-node, no build needed)
npm run dev -- scan --help

# Build to verify TypeScript compiles
npm run build
```

### Phase 3: Test

```bash
# Run full test suite
npm test

# Watch mode during development
npm run test:watch
```

### Phase 4: Commit

```bash
# Build + test must pass
npm run build && npm test

# Commit with descriptive message
git add -A
git commit -m "feat(scope): what changed and why

Detailed explanation.

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"

# Push
git push
```

## Guard Hook Integration

When integrated with aahp-runner (T-011), the pipeline becomes:

```
aahp-runner triggers agent run
  -> secure-dev-ai guard --project <name> --pre
     -> if CRITICAL found: EXIT 1 (run blocked)
     -> if OK: continue
  -> agent executes tasks
  -> secure-dev-ai guard --project <name> --post
     -> report findings
     -> if new CRITICAL found: EXIT 1 (flag for review)
```

## Adding a New Scanner

1. Create `src/scanners/<name>.ts` exporting `async function scan<Name>(projectPath: string): Promise<Finding[]>`
2. Import and add to `scanPromises` array in `src/scanner.ts`
3. Add a test case in `src/tests/scanner.test.ts`
4. Add the module name to the `Finding.module` union type in `src/types.ts`
5. Document in DASHBOARD.md

## Releasing a New Version

1. Update version in `package.json` and `src/cli.ts` `VERSION` constant
2. Run `npm run build && npm test`
3. Tag: `git tag v<version> && git push --tags`
4. Publish: `npm publish` (runs `prepublishOnly` which builds + tests)
