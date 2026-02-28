import fs from 'fs';
import path from 'path';
import os from 'os';
import { AahpManifest } from './types.js';
import { loadConfig } from './config.js';

export interface ProjectInfo {
  name: string;
  projectPath: string;
  phase?: string;
  quickContext?: string;
  hasAahp: boolean;
}

function getWorkspaceRoot(): string {
  const config = loadConfig();
  return config.workspaceRoot || path.join(os.homedir(), '..', '..', '_dev', '_Data', '_Development');
}

export function discoverProjects(): ProjectInfo[] {
  // First try to find workspace from the executable location
  let workspaceRoot = getWorkspaceRoot();

  // Also try common locations
  const candidates = [
    workspaceRoot,
    'E:\\_dev\\_Data\\_Development',
    process.cwd(),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      workspaceRoot = candidate;
      break;
    }
  }

  if (!fs.existsSync(workspaceRoot)) return [];

  const projects: ProjectInfo[] = [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(workspaceRoot, { withFileTypes: true });
  } catch {
    return projects;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.')) continue;

    const projectPath = path.join(workspaceRoot, entry.name);
    const manifestPath = path.join(projectPath, '.ai', 'handoff', 'MANIFEST.json');

    if (fs.existsSync(manifestPath)) {
      try {
        const manifest: AahpManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
        projects.push({
          name: entry.name,
          projectPath,
          phase: manifest.last_session?.phase,
          quickContext: manifest.quick_context,
          hasAahp: true,
        });
      } catch {
        projects.push({ name: entry.name, projectPath, hasAahp: false });
      }
    } else {
      // Include non-AAHP projects too if they have package.json or similar
      const hasCode = ['package.json', 'go.mod', 'requirements.txt', 'Cargo.toml'].some(f =>
        fs.existsSync(path.join(projectPath, f))
      );
      if (hasCode) {
        projects.push({ name: entry.name, projectPath, hasAahp: false });
      }
    }
  }

  return projects.sort((a, b) => a.name.localeCompare(b.name));
}
