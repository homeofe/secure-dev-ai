import path from 'path';
import { Finding, ScanResult } from './types.js';
import { scanSecrets } from './scanners/secrets.js';
import { scanDeps } from './scanners/deps.js';
import { scanPatterns } from './scanners/patterns.js';
import { scanAuth } from './scanners/auth.js';
import { scanThreatModel } from './scanners/threatModel.js';
import { loadConfig } from './config.js';

function computeScore(findings: Finding[]): { score: ScanResult['score']; scoreNumeric: number } {
  const critical = findings.filter(f => f.severity === 'CRITICAL').length;
  const high = findings.filter(f => f.severity === 'HIGH').length;
  const medium = findings.filter(f => f.severity === 'MEDIUM').length;
  const low = findings.filter(f => f.severity === 'LOW').length;

  // Weighted penalty
  const penalty = critical * 30 + high * 10 + medium * 3 + low * 1;
  const scoreNumeric = Math.max(0, 100 - penalty);

  let score: ScanResult['score'];
  if (critical > 0) score = 'F';
  else if (scoreNumeric >= 90) score = 'A';
  else if (scoreNumeric >= 75) score = 'B';
  else if (scoreNumeric >= 60) score = 'C';
  else if (scoreNumeric >= 40) score = 'D';
  else score = 'F';

  return { score, scoreNumeric };
}

export async function scanProject(projectPath: string, options: { threatModel?: boolean } = {}): Promise<ScanResult> {
  const start = Date.now();
  const config = loadConfig();
  const projectName = path.basename(projectPath);
  const enableThreatModel = options.threatModel ?? config.threatModelEnabled ?? false;

  // Run all scanners in parallel
  const scanPromises: Promise<Finding[]>[] = [
    scanSecrets(projectPath),
    scanDeps(projectPath),
    scanPatterns(projectPath),
    scanAuth(projectPath),
  ];
  if (enableThreatModel) {
    scanPromises.push(scanThreatModel(projectPath));
  }

  const results = await Promise.allSettled(scanPromises);
  const findings: Finding[] = [];
  for (const result of results) {
    if (result.status === 'fulfilled') findings.push(...result.value);
    // Silently skip failed scanners
  }

  const summary = {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
    info: findings.filter(f => f.severity === 'INFO').length,
  };

  const { score, scoreNumeric } = computeScore(findings);

  return {
    project: projectName,
    projectPath,
    scannedAt: new Date().toISOString(),
    score,
    scoreNumeric,
    findings,
    summary,
    durationMs: Date.now() - start,
  };
}
