export interface Finding {
  module: 'secrets' | 'deps' | 'patterns' | 'auth' | 'threat-model';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  description: string;
  file?: string;
  line?: number;
  remediation?: string;
}

export interface ScanResult {
  project: string;
  projectPath: string;
  scannedAt: string;
  score: 'A' | 'B' | 'C' | 'D' | 'F';
  scoreNumeric: number; // 0-100
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  durationMs: number;
}

export interface SecureDevConfig {
  anthropicApiKey?: string;
  workspaceRoot?: string;
  blockOnSeverity?: 'CRITICAL' | 'HIGH';
  excludeProjects?: string[];
  threatModelEnabled?: boolean;
}

export interface AahpManifest {
  aahp_version: string;
  project: string;
  last_session?: {
    phase?: string;
  };
  quick_context?: string;
  tasks?: Record<string, { title: string; status: string; priority?: string; depends_on?: string[] }>;
  next_task_id?: number;
}
