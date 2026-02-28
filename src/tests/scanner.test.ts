import { describe, it, expect } from 'vitest';
import path from 'path';
import { fileURLToPath } from 'url';
import { scanProject } from '../scanner.js';

const FIXTURE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

describe('scanProject', () => {
  it('returns a ScanResult with expected shape', async () => {
    // Use the test fixtures directory
    const result = await scanProject(FIXTURE_DIR);
    expect(result).toHaveProperty('project');
    expect(result).toHaveProperty('score');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('summary');
    expect(['A', 'B', 'C', 'D', 'F']).toContain(result.score);
    expect(result.scoreNumeric).toBeGreaterThanOrEqual(0);
    expect(result.scoreNumeric).toBeLessThanOrEqual(100);
  });

  it('detects secrets in fixture files', async () => {
    const result = await scanProject(FIXTURE_DIR);
    const secretFindings = result.findings.filter(f => f.module === 'secrets');
    // The fixture has intentional secrets
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  it('detects code patterns in fixture files', async () => {
    const result = await scanProject(FIXTURE_DIR);
    const patternFindings = result.findings.filter(f => f.module === 'patterns');
    expect(patternFindings.length).toBeGreaterThan(0);
  });
});

describe('score computation', () => {
  it('returns F when critical findings exist', async () => {
    const result = await scanProject(FIXTURE_DIR);
    const hasCritical = result.summary.critical > 0;
    if (hasCritical) {
      expect(result.score).toBe('F');
    }
  });
});
