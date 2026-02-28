import fs from 'fs';
import os from 'os';
import path from 'path';
import { SecureDevConfig } from './types.js';

const CONFIG_PATH = path.join(os.homedir(), '.secure-dev-ai.json');

export function loadConfig(): SecureDevConfig {
  if (!fs.existsSync(CONFIG_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  } catch {
    return {};
  }
}

export function saveConfig(config: SecureDevConfig): void {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}
