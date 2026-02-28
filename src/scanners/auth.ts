import fs from 'fs';
import path from 'path';
import { Finding } from '../types.js';

const AUTH_INDICATORS = /auth|guard|protect|middleware|jwt|session|verify|require|authenticated|isAuth|checkAuth|passport|bearer|token/i;

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', 'coverage', 'test', 'tests', '__tests__', 'spec']);
const SCAN_EXTENSIONS = ['.ts', '.js'];

function collectFiles(dir: string): string[] {
  const results: string[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.spec.ts')) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath));
    } else if (entry.isFile() && SCAN_EXTENSIONS.includes(path.extname(entry.name))) {
      results.push(fullPath);
    }
  }
  return results;
}

export async function scanAuth(projectPath: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = collectFiles(projectPath);

  // Check if project has any auth setup at all
  let hasAnyAuth = false;
  for (const filePath of files) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      if (AUTH_INDICATORS.test(content)) {
        hasAnyAuth = true;
        break;
      }
    } catch { /* skip */ }
  }

  // Only flag missing auth on individual routes if the project uses auth somewhere
  if (!hasAnyAuth) {
    // Check if it's a server/API project at all
    const hasRoutes = files.some(f => {
      try {
        const c = fs.readFileSync(f, 'utf-8');
        return /(?:express|fastify|@nestjs\/core|koa)\b/.test(c);
      } catch { return false; }
    });
    if (hasRoutes) {
      findings.push({
        module: 'auth',
        severity: 'HIGH',
        title: 'No authentication middleware detected',
        description: 'This project appears to be an HTTP API/server but has no authentication middleware configured.',
        remediation: 'Implement authentication (JWT, sessions, OAuth) before exposing endpoints. Use middleware like passport.js, @nestjs/jwt, or express-jwt.',
      });
    }
    return findings;
  }

  // Scan for unprotected mutation routes
  for (const filePath of files) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch { continue; }

    if (!/(router|app|server)\.(post|put|patch|delete)\s*\(/i.test(content)) continue;

    const relPath = path.relative(projectPath, filePath);
    const lines = content.split('\n');

    // Look for mutation routes
    const routeRegex = /(?:router|app|server)\.(post|put|patch|delete)\s*\(\s*['"`]([^'"`,]+)['"`]/gi;
    let match: RegExpExecArray | null;
    while ((match = routeRegex.exec(content)) !== null) {
      const method = match[1].toUpperCase();
      const routePath = match[2];
      const lineNumber = content.slice(0, match.index).split('\n').length;

      // Get context window (5 lines around the route)
      const startLine = Math.max(0, lineNumber - 3);
      const endLine = Math.min(lines.length, lineNumber + 5);
      const context = lines.slice(startLine, endLine).join('\n');

      if (!AUTH_INDICATORS.test(context)) {
        findings.push({
          module: 'auth',
          severity: 'HIGH',
          title: `Unprotected ${method} route`,
          description: `${relPath}:${lineNumber} - Route ${routePath} may lack authentication middleware`,
          file: relPath,
          line: lineNumber,
          remediation: 'Add authentication middleware to mutation routes. Example: router.post(\'/path\', authMiddleware, handler)',
        });
      }
    }
  }

  return findings;
}
