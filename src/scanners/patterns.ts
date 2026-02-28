import fs from 'fs';
import path from 'path';
import { Finding } from '../types.js';
import { loadIgnoreRules } from '../ignoreRules.js';

interface PatternRule {
  name: string;
  pattern: RegExp;
  severity: Finding['severity'];
  remediation: string;
  extensions: string[];
}

const PATTERN_RULES: PatternRule[] = [
  {
    name: 'SQL Injection - string concatenation in query',
    pattern: /(?:query|execute|db\.run|sequelize\.query|knex\.raw)\s*\(\s*[`"'].*?\+\s*(?:req\.|params\.|body\.|query\.)/g,
    severity: 'CRITICAL',
    remediation: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL.',
    extensions: ['.ts', '.js', '.py', '.php'],
  },
  {
    name: 'SQL Injection - raw query with template literal',
    pattern: /(?:query|raw|execute)\s*\(`[^`]*\$\{(?:req\.|params\.|body\.|query\.|user\.)/g,
    severity: 'CRITICAL',
    remediation: 'Use parameterized queries. Template literals with user input in SQL are dangerous.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'XSS - dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
    severity: 'HIGH',
    remediation: 'Avoid dangerouslySetInnerHTML. If necessary, sanitize with DOMPurify first.',
    extensions: ['.tsx', '.jsx', '.ts', '.js'],
  },
  {
    name: 'XSS - innerHTML with variable',
    pattern: /\.innerHTML\s*=\s*(?!["'`]<)/g,
    severity: 'HIGH',
    remediation: 'Use textContent instead of innerHTML, or sanitize the value with DOMPurify.',
    extensions: ['.ts', '.js', '.tsx', '.jsx'],
  },
  {
    name: 'eval() usage',
    pattern: /\beval\s*\(/g,
    severity: 'HIGH',
    remediation: 'Avoid eval(). Use JSON.parse() for JSON, or safer alternatives.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'new Function() usage',
    pattern: /new\s+Function\s*\(/g,
    severity: 'HIGH',
    remediation: 'Avoid new Function() - it executes arbitrary code similar to eval().',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'Path traversal - unsanitized path join with user input',
    pattern: /path\.(?:join|resolve)\s*\([^)]*(?:req\.|params\.|body\.|query\.)[^)]*\)/g,
    severity: 'HIGH',
    remediation: 'Validate and sanitize file paths. Use path.normalize() and verify the result stays within allowed directories.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'Command injection - exec with user input',
    pattern: /(?:exec|execSync|spawn)\s*\([^)]*(?:req\.|params\.|body\.|query\.)[^)]*\)/g,
    severity: 'CRITICAL',
    remediation: 'Never pass user input to shell commands. Use allowlists and escape inputs if shell execution is required.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'Prototype pollution',
    pattern: /Object\.assign\s*\(\s*(?:req\.|this\.|global\.)/g,
    severity: 'HIGH',
    remediation: 'Validate object shapes before merging. Use Object.create(null) for prototype-free objects.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'Regex DoS (ReDoS) - nested quantifiers',
    pattern: /new RegExp\([^)]*\([^)]*\+[^)]*\)\+/g,
    severity: 'MEDIUM',
    remediation: 'Avoid nested quantifiers in regular expressions to prevent ReDoS attacks.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'Hardcoded localhost/IP in production code',
    pattern: /(?:http:\/\/localhost|http:\/\/127\.0\.0\.1|http:\/\/0\.0\.0\.0)(?!.*(?:dev|test|local))/g,
    severity: 'LOW',
    remediation: 'Use environment variables for URLs. Hardcoded localhost addresses may cause issues in production.',
    extensions: ['.ts', '.js', '.py'],
  },
  {
    name: 'console.log with sensitive data patterns',
    pattern: /console\.(?:log|info|debug)\s*\([^)]*(?:password|secret|token|key|credential)[^)]*\)/gi,
    severity: 'MEDIUM',
    remediation: 'Remove logging of sensitive data. Use redaction for debug output.',
    extensions: ['.ts', '.js'],
  },
  {
    name: 'TODO/FIXME security note',
    pattern: /\/\/\s*(?:TODO|FIXME|HACK|XXX).*(?:security|auth|secret|password|safe|inject)/gi,
    severity: 'LOW',
    remediation: 'Address this security TODO before production deployment.',
    extensions: ['.ts', '.js', '.py', '.go', '.php'],
  },
];

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage', '__pycache__', '.venv']);

function collectFiles(dir: string, extensions: string[], projectRoot: string, isIgnored: (rel: string) => boolean): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  const extSet = new Set(extensions);
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(projectRoot, fullPath);
    if (isIgnored(relPath)) continue;
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath, extensions, projectRoot, isIgnored));
    } else if (entry.isFile() && extSet.has(path.extname(entry.name).toLowerCase())) {
      results.push(fullPath);
    }
  }
  return results;
}

export async function scanPatterns(projectPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const isIgnored = loadIgnoreRules(projectPath);

  // Collect all unique extensions needed
  const allExtensions = [...new Set(PATTERN_RULES.flatMap(r => r.extensions))];
  const files = collectFiles(projectPath, allExtensions, projectPath, isIgnored);

  for (const filePath of files) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }
    const ext = path.extname(filePath).toLowerCase();
    const relPath = path.relative(projectPath, filePath);
    const lines = content.split('\n');

    for (const rule of PATTERN_RULES) {
      if (!rule.extensions.includes(ext)) continue;
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      let matchCount = 0;
      while ((match = rule.pattern.exec(content)) !== null && matchCount < 5) {
        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split('\n').length;
        const lineContent = lines[lineNumber - 1] || '';
        // Skip test files for some rules
        if (/\.test\.|\.spec\./.test(filePath) && rule.severity === 'LOW') continue;
        // Skip if line is a comment
        if (/^\s*(#|\/\/|\/\*|\*)/.test(lineContent) && rule.name !== 'TODO/FIXME security note') continue;
        // Skip if match is inside a regex literal (e.g. pattern: /eval\(/)
        if (match.index > 0 && content[match.index - 1] === '/') continue;
        // Skip rule definition property lines (name/remediation strings in scanner source)
        if (/^\s*(?:name|remediation|description)\s*:\s*['"`]/.test(lineContent)) continue;

        findings.push({
          module: 'patterns',
          severity: rule.severity,
          title: rule.name,
          description: `${relPath}:${lineNumber} - ${lineContent.trim().slice(0, 120)}`,
          file: relPath,
          line: lineNumber,
          remediation: rule.remediation,
        });
        matchCount++;
      }
    }
  }

  return findings;
}
