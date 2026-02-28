import fs from 'fs';
import path from 'path';
import { Finding } from '../types.js';
import { loadIgnoreRules } from '../ignoreRules.js';
import { isLineSuppressed, isTestFixtureFile, asTestFixtureFinding } from '../suppressions.js';

// 25+ patterns for secrets and credentials
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: Finding['severity'] }> = [
  { name: 'Anthropic API Key', pattern: /sk-ant-[a-zA-Z0-9\-_]{20,}/g, severity: 'CRITICAL' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{20,}/g, severity: 'CRITICAL' },
  { name: 'GitHub Personal Access Token', pattern: /ghp_[a-zA-Z0-9]{36}/g, severity: 'CRITICAL' },
  { name: 'GitHub OAuth Token', pattern: /gho_[a-zA-Z0-9]{36}/g, severity: 'CRITICAL' },
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL' },
  { name: 'AWS Secret Key', pattern: /aws_secret_access_key\s*=\s*[^\s]+/gi, severity: 'CRITICAL' },
  { name: 'Private RSA Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { name: 'Private Key', pattern: /-----BEGIN PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { name: 'Bearer Token (hardcoded)', pattern: /Bearer\s+[a-zA-Z0-9\-_\.]{20,}/g, severity: 'HIGH' },
  { name: 'Basic Auth (hardcoded)', pattern: /Authorization:\s*Basic\s+[a-zA-Z0-9+\/=]{10,}/g, severity: 'HIGH' },
  { name: 'Database URL with credentials', pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@/gi, severity: 'HIGH' },
  { name: 'Slack Token', pattern: /xox[bpoa]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/g, severity: 'HIGH' },
  { name: 'Stripe API Key', pattern: /sk_live_[a-zA-Z0-9]{24}/g, severity: 'CRITICAL' },
  { name: 'Stripe Test Key (in prod file)', pattern: /sk_test_[a-zA-Z0-9]{24}/g, severity: 'MEDIUM' },
  { name: 'Hardcoded password', pattern: /password\s*=\s*["'][^"']{6,}["']/gi, severity: 'HIGH' },
  { name: 'Hardcoded password (2)', pattern: /PASSWORD\s*=\s*[^\s#"']+/g, severity: 'HIGH' },
  { name: 'Hardcoded API key assignment', pattern: /api_key\s*=\s*["'][a-zA-Z0-9\-_\.]{10,}["']/gi, severity: 'HIGH' },
  { name: 'Hardcoded secret assignment', pattern: /secret\s*[:=]\s*["'][a-zA-Z0-9\-_\.+\/=]{10,}["']/gi, severity: 'HIGH' },
  { name: 'JWT token (hardcoded)', pattern: /eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/g, severity: 'MEDIUM' },
  { name: 'SSH private key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: 'CRITICAL' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'HIGH' },
  { name: 'SendGrid API Key', pattern: /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/g, severity: 'HIGH' },
  { name: 'Twilio API Key', pattern: /SK[a-zA-Z0-9]{32}/g, severity: 'HIGH' },
  { name: 'GitLab Personal Token', pattern: /glpat-[a-zA-Z0-9\-_]{20}/g, severity: 'HIGH' },
  { name: 'NPM Auth Token', pattern: /\/\/registry\.npmjs\.org\/:_authToken=[^\s]+/g, severity: 'CRITICAL' },
];

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.ai', 'coverage', '__pycache__', '.venv', 'vendor']);
const SCAN_EXTENSIONS = new Set(['.ts', '.js', '.py', '.go', '.env', '.json', '.yaml', '.yml', '.sh', '.bash', '.conf', '.config', '.ini', '.toml', '.php', '.rb', '.java', '.cs', '.cpp', '.c', '.h']);
const SKIP_FILES = new Set(['.aiignore', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);

function collectFiles(dir: string, projectRoot: string, isIgnored: (rel: string) => boolean): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(projectRoot, fullPath);
    if (isIgnored(relPath)) continue;
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath, projectRoot, isIgnored));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SCAN_EXTENSIONS.has(ext) || entry.name.startsWith('.env')) {
        if (!SKIP_FILES.has(entry.name)) results.push(fullPath);
      }
    }
  }
  return results;
}

export async function scanSecrets(projectPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const isIgnored = loadIgnoreRules(projectPath);
  const files = collectFiles(projectPath, projectPath, isIgnored);

  for (const filePath of files) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }
    const lines = content.split('\n');
    const relPath = path.relative(projectPath, filePath);
    const isFixture = isTestFixtureFile(relPath, content);

    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(content)) !== null) {
        // Find line number
        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split('\n').length;
        const lineContent = lines[lineNumber - 1] || '';

        // Skip comments
        if (/^\s*(#|\/\/|\/\*)/.test(lineContent)) continue;

        // Skip if the match sits inside a regex literal (e.g. pattern: /BEGIN RSA KEY-----/g)
        if (match.index > 0 && content[match.index - 1] === '/') continue;
        // Skip lines that define a detection pattern or rule property (scanner source files)
        if (/\bpattern\s*:\s*\//.test(lineContent)) continue;

        // Line-level suppression: // nosec
        if (isLineSuppressed(lineContent)) continue;

        // Skip if line contains common placeholder indicators
        const PLACEHOLDER_LINE = /example|placeholder|your[-_]?(?:key|secret|token|api|password)|changeme|todo|insert|replace|fill.?in|enter.?(?:key|secret|token)|sample|fake|dummy|mock|redacted|omit|<[^>]+>/i;
        if (PLACEHOLDER_LINE.test(lineContent)) continue;

        // Skip if the matched value itself looks like a placeholder
        const matchedValue = match[0];
        // All-uppercase or contains placeholder words
        if (/YOUR|EXAMPLE|PLACEHOLDER|CHANGEME|REPLACE|INSERT|FILL|SAMPLE|FAKE|DUMMY|MOCK|REDACTED/i.test(matchedValue)) continue;
        // Value contains common test/dev indicator words
        if (/(?:^|[-_:/"'])(?:test|tests|testing|dev|development|local|dummy|fake|sample|mock|stub|secret|example|demo)(?:[-_:/"']|$)/i.test(matchedValue)) continue;
        // Repeating characters (e.g. xxxxxxxx, 00000000, aaaaaaaa)
        if (/(.)\1{7,}/.test(matchedValue)) continue;
        // Angle-bracket or curly-brace template tokens like <TOKEN> or {{SECRET}}
        if (/<[A-Z_]+>|\{\{[^}]+\}\}|\$\{[^}]+\}/.test(matchedValue)) continue;
        // Ends with common placeholder suffixes
        if (/[-_](here|key|token|secret|value|goes|placeholder|example|xxx+)$/i.test(matchedValue)) continue;

        // Downgrade database URLs pointing to localhost/127.x - these are dev credentials only
        if (name === 'Database URL with credentials' && /(?:@localhost|@127\.\d+\.\d+\.\d+|@0\.0\.0\.0|@::1)/.test(matchedValue)) {
          const devFinding: Finding = {
            module: 'secrets', severity: 'LOW',
            title: `${name} detected (localhost - dev only)`,
            description: `Local database URL with credentials in ${relPath}:${lineNumber}. Fine for development; ensure production uses env vars.`,
            file: relPath, line: lineNumber,
            remediation: 'Use a DATABASE_URL environment variable so production credentials are never in source code.',
          };
          findings.push(isFixture ? asTestFixtureFinding(devFinding) : devFinding);
          continue;
        }

        let finding: Finding = {
          module: 'secrets',
          severity,
          title: `${name} detected`,
          description: `Potential secret found in ${relPath}:${lineNumber}`,
          file: relPath,
          line: lineNumber,
          remediation: 'Move to environment variables. Never commit secrets to source code.',
        };
        if (isFixture) finding = asTestFixtureFinding(finding);

        findings.push(finding);
        // Limit matches per pattern per file to avoid noise
        if (findings.filter(f => f.file === relPath && f.title.endsWith(`${name} detected`)).length >= 3) break;
      }
    }
  }

  return findings;
}
