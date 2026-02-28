import chalk from 'chalk';
import { Finding, ScanResult } from './types.js';

// ─── box-drawing helpers ──────────────────────────────────────────────────────

const ANSI_RE = /\u001b\[[0-9;]*m/g;
function visibleLen(s: string): number { return s.replace(ANSI_RE, '').length; }

function pad(s: string, width: number): string {
  const vis = visibleLen(s);
  if (vis > width) return s.replace(ANSI_RE, '').slice(0, width - 1) + '…';
  return s + ' '.repeat(width - vis);
}

function row(cols: string[], widths: number[]): string {
  return '│ ' + cols.map((c, i) => pad(c, widths[i])).join(' │ ') + ' │';
}

function divider(widths: number[], left: string, mid: string, right: string, fill = '─'): string {
  return left + widths.map(w => fill.repeat(w + 2)).join(mid) + right;
}

function table(headers: string[], rows: string[][], widths: number[]): string {
  const lines: string[] = [];
  lines.push(divider(widths, '┌', '┬', '┐'));
  lines.push(row(headers.map(h => chalk.bold(h)), widths));
  lines.push(divider(widths, '├', '┼', '┤'));
  for (const r of rows) {
    lines.push(row(r, widths));
  }
  lines.push(divider(widths, '└', '┴', '┘'));
  return lines.join('\n');
}

// ─── severity coloring ────────────────────────────────────────────────────────

export function severityColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return chalk.bgRed.white(' CRITICAL ');
    case 'HIGH':     return chalk.red('   HIGH   ');
    case 'MEDIUM':   return chalk.yellow('  MEDIUM  ');
    case 'LOW':      return chalk.cyan('   LOW    ');
    default:         return chalk.gray('   INFO   ');
  }
}

export function scoreColor(score: string): string {
  switch (score) {
    case 'A': return chalk.bgGreen.black(` ${score} `);
    case 'B': return chalk.green(` ${score} `);
    case 'C': return chalk.yellow(` ${score} `);
    case 'D': return chalk.red(` ${score} `);
    case 'F': return chalk.bgRed.white(` ${score} `);
    default:  return ` ${score} `;
  }
}

// ─── scan result output ───────────────────────────────────────────────────────

export function printScanResult(result: ScanResult): void {
  const { project, score, scoreNumeric, summary, findings, durationMs } = result;

  // Header bar
  console.log('');
  console.log(
    chalk.bold(`  🔒 ${project}`) +
    `  Score: ${scoreColor(score)} ${chalk.gray(`(${scoreNumeric}/100)`)}` +
    chalk.gray(`  ${durationMs}ms`)
  );

  // Summary pill row
  const pills = [
    summary.critical > 0 ? chalk.bgRed.white(` ${summary.critical} CRITICAL `) : chalk.gray(` 0 CRITICAL `),
    summary.high     > 0 ? chalk.red(` ${summary.high} HIGH `)                 : chalk.gray(` 0 HIGH `),
    summary.medium   > 0 ? chalk.yellow(` ${summary.medium} MEDIUM `)           : chalk.gray(` 0 MEDIUM `),
    summary.low      > 0 ? chalk.cyan(` ${summary.low} LOW `)                   : chalk.gray(` 0 LOW `),
  ];
  console.log('  ' + pills.join('  '));

  if (findings.length === 0) {
    console.log(chalk.green('  ✔ No issues found\n'));
    return;
  }

  // Findings table - show CRITICAL + HIGH inline, others summarized
  const visible = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  if (visible.length === 0) {
    const med = findings.filter(f => f.severity === 'MEDIUM').length;
    const low = findings.filter(f => f.severity === 'LOW').length;
    console.log(chalk.gray(`  ${med} medium, ${low} low severity findings. Run: secure-dev-ai report ${project}\n`));
    return;
  }

  console.log('');
  const rows = visible.map(f => [
    f.severity,
    f.title,
    f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '—',
    f.remediation ? f.remediation.slice(0, 40) : '—',
  ]);

  // Dynamic width: severity fixed, title 38, location 28, remediation 40
  const widths = [8, 38, 28, 40];
  console.log('  ' + table(
    ['Severity', 'Finding', 'Location', 'Remediation'],
    rows.map(r => [
      r[0], r[1], r[2], r[3]
    ]),
    widths
  ).split('\n').join('\n  '));

  const remaining = findings.length - visible.length;
  if (remaining > 0) {
    console.log(chalk.gray(`  + ${remaining} more (MEDIUM/LOW). Run: secure-dev-ai report ${project}`));
  }
  console.log('');
}

// ─── multi-project summary table ─────────────────────────────────────────────

export function printSummaryTable(results: ScanResult[]): void {
  if (results.length <= 1) return;
  console.log(chalk.bold('\n  Summary\n'));
  const widths = [35, 5, 2, 2, 2, 2, 8];
  const rows = results.map(r => [
    r.project,
    r.score,
    String(r.summary.critical),
    String(r.summary.high),
    String(r.summary.medium),
    String(r.summary.low),
    `${r.durationMs}ms`,
  ]);
  console.log('  ' + table(
    ['Project', 'Score', 'C', 'H', 'M', 'L', 'Time'],
    rows,
    widths
  ).split('\n').join('\n  '));

  const totalC = results.reduce((s, r) => s + r.summary.critical, 0);
  const totalH = results.reduce((s, r) => s + r.summary.high, 0);
  console.log('');
  if (totalC > 0) {
    console.log(chalk.bgRed.white(`  ✖ ${totalC} critical issue(s) require immediate attention`));
  } else if (totalH > 0) {
    console.log(chalk.red(`  ⚠ ${totalH} high severity issue(s) found`));
  } else {
    console.log(chalk.green(`  ✔ All ${results.length} projects clean`));
  }
  console.log('');
}

// ─── list command table ───────────────────────────────────────────────────────

export function printProjectList(
  projects: { name: string; projectPath: string }[],
  getReport: (name: string) => ScanResult | null
): void {
  console.log(chalk.bold(`\n  🔒 Security Overview  —  ${projects.length} projects\n`));

  const widths = [35, 5, 2, 2, 2, 2, 8];
  const rows = projects.map(p => {
    const report = getReport(p.name);
    if (!report) return [p.name, '?', '—', '—', '—', '—', 'not scanned'];
    const age = Math.floor((Date.now() - new Date(report.scannedAt).getTime()) / 86400000);
    return [
      p.name,
      report.score,
      String(report.summary.critical),
      String(report.summary.high),
      String(report.summary.medium),
      String(report.summary.low),
      age === 0 ? 'today' : `${age}d ago`,
    ];
  });

  // Color the score column
  const coloredRows = rows.map(r => {
    const colored = [...r];
    if (r[1] !== '?') colored[1] = r[1]; // plain score - color applied separately
    return colored;
  });

  console.log('  ' + table(
    ['Project', 'Score', 'C', 'H', 'M', 'L', 'Last Scan'],
    coloredRows,
    widths
  ).split('\n').join('\n  '));

  const scanned = projects.filter(p => getReport(p.name) !== null).length;
  console.log('');
  console.log(chalk.gray(`  ${scanned}/${projects.length} scanned  ·  secure-dev-ai scan --all`));
  console.log('');
}

// ─── full report command ──────────────────────────────────────────────────────

export function printFullReport(report: ScanResult): void {
  console.log(chalk.bold(`\n  🔒 Security Report  —  ${report.project}`));
  console.log(`  Scanned: ${report.scannedAt.replace('T', ' ').slice(0, 19)}  Score: ${scoreColor(report.score)} (${report.scoreNumeric}/100)\n`);

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
  for (const sev of severities) {
    const group = report.findings.filter(f => f.severity === sev);
    if (!group.length) continue;

    console.log(`  ${severityColor(sev)}  ${chalk.bold(String(group.length) + ' finding' + (group.length > 1 ? 's' : ''))}`);
    console.log('');

    const widths = [38, 28, 45];
    const rows = group.map(f => [
      f.title,
      f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '—',
      f.remediation ?? f.description.slice(0, 45),
    ]);
    console.log('  ' + table(['Finding', 'Location', 'Remediation'], rows, widths).split('\n').join('\n  '));
    console.log('');
  }
}
