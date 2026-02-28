import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { Finding } from '../types.js';

interface NpmAuditVuln {
  name: string;
  severity: string;
  via: Array<string | { title?: string; url?: string }>;
  fixAvailable: boolean | { name: string; version: string };
}

interface NpmAuditResult {
  vulnerabilities?: Record<string, NpmAuditVuln>;
  metadata?: { vulnerabilities: { critical: number; high: number; moderate: number; low: number; info: number } };
}

function mapNpmSeverity(sev: string): Finding['severity'] {
  switch (sev.toLowerCase()) {
    case 'critical': return 'CRITICAL';
    case 'high': return 'HIGH';
    case 'moderate': return 'MEDIUM';
    case 'low': return 'LOW';
    default: return 'INFO';
  }
}

export async function scanDeps(projectPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // npm audit
  const pkgJson = path.join(projectPath, 'package.json');
  if (fs.existsSync(pkgJson)) {
    try {
      const output = execSync('npm audit --json', {
        cwd: projectPath,
        timeout: 30000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).toString();
      const audit: NpmAuditResult = JSON.parse(output);
      if (audit.vulnerabilities) {
        for (const [pkg, vuln] of Object.entries(audit.vulnerabilities)) {
          const severity = mapNpmSeverity(vuln.severity);
          const via = vuln.via.map(v => (typeof v === 'string' ? v : v.title || v.url || '')).filter(Boolean).join(', ');
          findings.push({
            module: 'deps',
            severity,
            title: `Vulnerable dependency: ${pkg}`,
            description: `${pkg} has a ${vuln.severity} severity vulnerability. Via: ${via || 'transitive'}`,
            file: 'package.json',
            remediation: vuln.fixAvailable
              ? `Run \`npm audit fix\` to apply available fixes.`
              : 'No automatic fix available. Consider replacing or pinning the dependency.',
          });
        }
      }
    } catch (e: unknown) {
      // npm audit exits with code 1 when vulns found - parse stdout anyway
      const err = e as { stdout?: Buffer };
      if (err.stdout) {
        try {
          const audit: NpmAuditResult = JSON.parse(err.stdout.toString());
          if (audit.vulnerabilities) {
            for (const [pkg, vuln] of Object.entries(audit.vulnerabilities)) {
              findings.push({
                module: 'deps',
                severity: mapNpmSeverity(vuln.severity),
                title: `Vulnerable dependency: ${pkg}`,
                description: `${pkg} has a ${vuln.severity} severity vulnerability`,
                file: 'package.json',
                remediation: 'Run `npm audit fix` or update the package.',
              });
            }
          }
        } catch {
          // Could not parse audit output
        }
      }
    }
  }

  return findings;
}
