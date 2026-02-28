import fs from 'fs';
import path from 'path';

/** Convert a single gitignore-style pattern to a RegExp. */
function patternToRegex(raw: string): RegExp {
  // Anchored if pattern contains a slash somewhere other than at the end
  const hasSlash = raw.replace(/\/$/, '').includes('/');
  // Remove leading slash (anchoring is handled separately)
  let p = raw.startsWith('/') ? raw.slice(1) : raw;
  // Remove trailing slash (we handle dir matching via (/.*)?$)
  if (p.endsWith('/')) p = p.slice(0, -1);

  // Escape regex special chars except * and ?
  p = p.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  // ** matches anything including path separators
  p = p.replace(/\*\*/g, '\x00');
  // * matches anything within a single segment
  p = p.replace(/\*/g, '[^/]*');
  // restore **
  p = p.replace(/\x00/g, '.*');
  // ? matches a single char (not /)
  p = p.replace(/\?/g, '[^/]');

  const pattern = hasSlash ? `^${p}(/.*)?$` : `(^|/)${p}(/.*)?$`;
  return new RegExp(pattern);
}

/** Parse an ignore file and return compiled regex list (skips comments/negations). */
function parseIgnoreFile(filePath: string): RegExp[] {
  try {
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    return lines
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !l.startsWith('!'))
      .map(patternToRegex);
  } catch {
    return [];
  }
}

/**
 * Load ignore rules from .gitignore and .aiignore at the project root.
 * Returns a function that, given a path relative to the project root,
 * returns true if the path should be ignored.
 */
export function loadIgnoreRules(projectRoot: string): (relPath: string) => boolean {
  const rules: RegExp[] = [
    ...parseIgnoreFile(path.join(projectRoot, '.gitignore')),
    ...parseIgnoreFile(path.join(projectRoot, '.aiignore')),
  ];

  if (rules.length === 0) return () => false;

  return (relPath: string) => {
    // Normalize to forward slashes for consistent matching
    const normalized = relPath.replace(/\\/g, '/');
    return rules.some(r => r.test(normalized));
  };
}
