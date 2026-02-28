/**
 * Suppression and test-fixture detection for secure-dev-ai.
 *
 * Three suppression mechanisms are supported:
 *
 *  1. Line-level:   append `// nosec` (or variants) to the offending line
 *                   → the finding is completely skipped
 *
 *  2. File-level:   add a pragma in the first 5 lines of the file:
 *                     // secure-dev-ai: test-fixture
 *                     // nosec: intentional
 *                   → all findings in that file are downgraded to INFO
 *
 *  3. Path-based:   files whose path contains well-known test-data directories
 *                   (fixtures/, __fixtures__/, mocks/, testdata/, stubs/, fakes/)
 *                   or whose name matches *.fixture.ts / *.mock.ts etc.
 *                   → all findings downgraded to INFO
 *
 * INFO findings do NOT contribute to the security score but are still visible
 * in the report, so developers know what intentional test data exists.
 */

// ── Line-level suppression ────────────────────────────────────────────────────

const NOSEC_RE = /\/\/\s*(?:nosec|secure-dev-ai[-:\s]+ignore|security[-:\s]+ignore)\b/i

/**
 * Returns true if the line ends with a `// nosec` (or equivalent) comment.
 * When true, the finding on that line should be skipped entirely.
 */
export function isLineSuppressed(lineContent: string): boolean {
  return NOSEC_RE.test(lineContent)
}

// ── File-level & path-based detection ────────────────────────────────────────

/** Directories whose contents are treated as intentional test data */
const TEST_DIRS_RE =
  /(?:^|\/)(?:fixtures?|__fixtures__|testdata|test[-_]data|mocks?|stubs?|fakes?|test[-_]helpers?|spec[-_]helpers?)\//i

/** File-name suffixes that indicate intentional test / mock data */
const TEST_FILE_RE = /\.(?:fixture|mock|stub|fake|testdata|test[-_]data)\.[a-z]+$/i

/** Pragma patterns accepted in the first 5 lines of a file */
const PRAGMA_RE =
  /(?:secure-dev-ai|nosec|security).*(?:test[-._\s]?fixture|intentional|test[-._\s]?data|test[-._\s]?only|mock|fixture)/i

/**
 * Returns true if the file should be treated as intentional test data,
 * meaning all findings should be downgraded to INFO rather than suppressed.
 *
 * @param relPath   Path relative to the project root (used for directory / name checks)
 * @param content   Raw file content (first 5 lines inspected for pragmas)
 */
export function isTestFixtureFile(relPath: string, content: string): boolean {
  const normalized = relPath.replace(/\\/g, '/')

  // Path-based: known test-data directories
  if (TEST_DIRS_RE.test('/' + normalized)) return true

  // File-name suffix
  if (TEST_FILE_RE.test(normalized)) return true

  // File-level pragma in the first 5 lines
  const header = content.split('\n').slice(0, 5).join('\n')
  if (PRAGMA_RE.test(header)) return true

  return false
}

// ── Severity downgrade helper ─────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

/**
 * When a finding is in a test fixture file, downgrade its severity to INFO
 * and annotate its title so it remains visible but doesn't affect the score.
 */
export function asTestFixtureFinding<T extends { severity: Severity; title: string; description: string }>(
  finding: T,
): T {
  return {
    ...finding,
    severity: 'INFO',
    title: `[test fixture] ${finding.title}`,
    description: `${finding.description}  ·  intentional test data – add // nosec to suppress`,
  }
}
