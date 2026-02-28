import fs from 'fs';
import os from 'os';
import path from 'path';
import { ScanResult } from './types.js';

const REPORTS_DIR = path.join(os.homedir(), '.secure-dev-ai', 'reports');

export function saveReport(result: ScanResult): string {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  const date = new Date().toISOString().split('T')[0];
  const reportPath = path.join(REPORTS_DIR, `${result.project}-${date}.json`);
  fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));
  return reportPath;
}

export function loadLatestReport(projectName: string): ScanResult | null {
  if (!fs.existsSync(REPORTS_DIR)) return null;
  const files = fs.readdirSync(REPORTS_DIR)
    .filter(f => f.startsWith(projectName + '-') && f.endsWith('.json'))
    .sort()
    .reverse();
  if (!files.length) return null;
  try {
    return JSON.parse(fs.readFileSync(path.join(REPORTS_DIR, files[0]), 'utf-8'));
  } catch {
    return null;
  }
}

export function generateSecurityMd(result: ScanResult, projectPath: string): void {
  const critical = result.findings.filter(f => f.severity === 'CRITICAL');
  const high = result.findings.filter(f => f.severity === 'HIGH');
  const medium = result.findings.filter(f => f.severity === 'MEDIUM');

  const content = `# Security Status - ${result.project}

> Last scanned: ${result.scannedAt.split('T')[0]} by secure-dev-ai
> Score: **${result.score}** (${result.scoreNumeric}/100)

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | ${result.summary.critical} |
| HIGH | ${result.summary.high} |
| MEDIUM | ${result.summary.medium} |
| LOW | ${result.summary.low} |
| INFO | ${result.summary.info} |

${critical.length > 0 ? `## Critical Issues (MUST FIX)

${critical.map(f => `### ${f.title}
- **File:** ${f.file || 'n/a'}${f.line ? `:${f.line}` : ''}
- **Description:** ${f.description}
- **Remediation:** ${f.remediation || 'See security documentation'}
`).join('\n')}` : ''}

${high.length > 0 ? `## High Severity

${high.map(f => `- **${f.title}** - ${f.file || 'n/a'}${f.line ? `:${f.line}` : ''} - ${f.remediation || f.description}`).join('\n')}` : ''}

${medium.length > 0 ? `## Medium Severity

${medium.map(f => `- **${f.title}** - ${f.file || 'n/a'}${f.line ? `:${f.line}` : ''}`).join('\n')}` : ''}

---
*Regenerate: \`secure-dev-ai scan ${result.project}\`*
`;

  fs.writeFileSync(path.join(projectPath, 'SECURITY.md'), content);
}
