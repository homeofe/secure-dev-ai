# NEXT ACTIONS - secure-dev-ai

## Immediate (next session)

### T-011: aahp-runner integration

Wire `secure-dev-ai guard` into `aahp-runner` as a pre/post hook so that
autonomous agent runs are blocked if CRITICAL security findings exist.

**Steps:**
1. Open `~/Development/aahp-runner`
2. In `src/agent.ts` (or wherever the run lifecycle is managed), add calls:
   - Before run: `execSync('secure-dev-ai guard --project <name> --pre', { stdio: 'inherit' })`
   - After run: `execSync('secure-dev-ai guard --project <name> --post', { stdio: 'inherit' })`
3. Exit the run with code 1 if guard exits 1
4. Make this opt-in via config: `secureDevAi: { enabled: true, blockOn: 'CRITICAL' }`
5. Update aahp-runner README with integration instructions
6. Commit to aahp-runner with `feat(security): integrate secure-dev-ai guard hooks`

**Notes:**
- `secure-dev-ai guard` exits 0 if OK, 1 if blocked, 0 if project not found (fail-open)
- The `--block-on HIGH` flag tightens the gate to block on HIGH severity too
- Install globally first: `npm install -g secure-dev-ai` or use `npx secure-dev-ai`
