#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'fs';
import path from 'path';
import { scanProject } from './scanner.js';
import { saveReport, loadLatestReport, generateSecurityMd } from './report.js';
import { discoverProjects } from './projects.js';
import { loadConfig, saveConfig } from './config.js';

const VERSION = '0.1.0';

function scoreColor(score: string): string {
  switch (score) {
    case 'A': return chalk.green(score);
    case 'B': return chalk.greenBright(score);
    case 'C': return chalk.yellow(score);
    case 'D': return chalk.red(score);
    case 'F': return chalk.bgRed.white(score);
    default: return score;
  }
}

function severityColor(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return chalk.bgRed.white(sev);
    case 'HIGH': return chalk.red(sev);
    case 'MEDIUM': return chalk.yellow(sev);
    case 'LOW': return chalk.cyan(sev);
    default: return chalk.gray(sev);
  }
}

const program = new Command();

program
  .name('secure-dev-ai')
  .version(VERSION)
  .description('Security by design CLI for AI-assisted development');

// scan command
program
  .command('scan [project]')
  .description('Scan one or all projects for security issues')
  .option('--all', 'Scan all discovered projects')
  .option('--threat-model', 'Enable AI-powered threat modeling (requires API key)')
  .option('--update-security-md', 'Write/update SECURITY.md in each project', false)
  .option('--json', 'Output results as JSON')
  .action(async (project: string | undefined, opts: { all?: boolean; threatModel?: boolean; updateSecurityMd?: boolean; json?: boolean }) => {
    const projects = discoverProjects();

    let toScan = opts.all
      ? projects
      : project
        ? projects.filter(p => p.name === project || p.projectPath === project)
        : [];

    if (!toScan.length && !opts.all && project) {
      // Try as a direct path
      if (fs.existsSync(project)) {
        toScan = [{ name: path.basename(project), projectPath: project, hasAahp: false }];
      } else {
        console.error(chalk.red(`Project not found: ${project}`));
        process.exit(1);
      }
    }

    if (!toScan.length) {
      console.error(chalk.red('No projects to scan. Use --all or specify a project name.'));
      process.exit(1);
    }

    const results = [];
    for (const p of toScan) {
      const spinner = ora(`Scanning ${chalk.bold(p.name)}...`).start();
      try {
        const result = await scanProject(p.projectPath, { threatModel: opts.threatModel });
        saveReport(result);
        if (opts.updateSecurityMd) generateSecurityMd(result, p.projectPath);
        spinner.succeed(`${chalk.bold(p.name)} - Score: ${scoreColor(result.score)} (${result.scoreNumeric}/100) - C:${result.summary.critical} H:${result.summary.high} M:${result.summary.medium} L:${result.summary.low}`);
        results.push(result);

        if (!opts.json && result.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length > 0) {
          const topFindings = result.findings
            .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
            .slice(0, 5);
          for (const f of topFindings) {
            console.log(`  ${severityColor(f.severity)} ${f.title}${f.file ? chalk.gray(` (${f.file}${f.line ? ':' + f.line : ''})`) : ''}`);
          }
          if (result.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length > 5) {
            console.log(chalk.gray(`  ... and ${result.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length - 5} more`));
          }
        }
      } catch (e) {
        spinner.fail(`${p.name} - scan failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (opts.json) {
      console.log(JSON.stringify(results, null, 2));
    } else if (results.length > 1) {
      const critCount = results.reduce((s, r) => s + r.summary.critical, 0);
      const highCount = results.reduce((s, r) => s + r.summary.high, 0);
      console.log('');
      console.log(chalk.bold(`Total: ${results.length} projects scanned - ${critCount} critical, ${highCount} high severity findings`));
    }
  });

// list command
program
  .command('list')
  .description('List all projects with their last known security score')
  .action(() => {
    const projects = discoverProjects();
    if (!projects.length) {
      console.log(chalk.yellow('No projects found.'));
      return;
    }
    console.log(chalk.bold(`\n🔒 Security Status - ${projects.length} projects\n`));
    let scanned = 0;
    for (const p of projects) {
      const report = loadLatestReport(p.name);
      if (report) {
        scanned++;
        const age = Math.floor((Date.now() - new Date(report.scannedAt).getTime()) / 86400000);
        const ageStr = age === 0 ? 'today' : `${age}d ago`;
        console.log(
          `  ${scoreColor(report.score)} ${chalk.bold(p.name.padEnd(35))} C:${String(report.summary.critical).padStart(2)} H:${String(report.summary.high).padStart(2)} M:${String(report.summary.medium).padStart(2)} ${chalk.gray(ageStr)}`
        );
      } else {
        console.log(`  ${chalk.gray('?')} ${chalk.gray(p.name.padEnd(35))} ${chalk.gray('not yet scanned')}`);
      }
    }
    console.log('');
    console.log(chalk.gray(`${scanned}/${projects.length} projects scanned. Run: secure-dev-ai scan --all`));
  });

// report command
program
  .command('report [project]')
  .description('Show the last scan report for a project')
  .option('--json', 'Output as JSON')
  .action((project: string | undefined, opts: { json?: boolean }) => {
    if (!project) {
      console.error(chalk.red('Specify a project name'));
      process.exit(1);
    }
    const report = loadLatestReport(project);
    if (!report) {
      console.log(chalk.yellow(`No scan report found for ${project}. Run: secure-dev-ai scan ${project}`));
      return;
    }
    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }

    console.log(chalk.bold(`\n🔒 Security Report - ${report.project}`));
    console.log(`Scanned: ${report.scannedAt} | Score: ${scoreColor(report.score)} (${report.scoreNumeric}/100)\n`);

    const bySeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
    for (const sev of bySeverity) {
      const group = report.findings.filter(f => f.severity === sev);
      if (!group.length) continue;
      console.log(chalk.bold(`${severityColor(sev)} (${group.length})`));
      for (const f of group) {
        console.log(`  ${f.title}`);
        if (f.file) console.log(chalk.gray(`    ${f.file}${f.line ? ':' + f.line : ''}`));
        if (f.remediation) console.log(chalk.cyan(`    Fix: ${f.remediation}`));
      }
      console.log('');
    }
  });

// guard command
program
  .command('guard')
  .description('Pre/post hook for aahp-runner agent runs. Exits 1 if CRITICAL findings found.')
  .requiredOption('--project <name>', 'Project name or path')
  .option('--pre', 'Pre-run check (scan project before agent starts)')
  .option('--post', 'Post-run check (scan after agent completes)')
  .option('--block-on <severity>', 'Block on severity level: CRITICAL or HIGH', 'CRITICAL')
  .action(async (opts: { project: string; pre?: boolean; post?: boolean; blockOn: string }) => {
    const projects = discoverProjects();
    const p = projects.find(proj => proj.name === opts.project || proj.projectPath === opts.project);
    const projectPath = p?.projectPath || (fs.existsSync(opts.project) ? opts.project : null);

    if (!projectPath) {
      console.error(`secure-dev-ai guard: project not found: ${opts.project}`);
      process.exit(0); // Don't block if we can't find the project
    }

    const phase = opts.pre ? 'pre' : 'post';
    console.log(`secure-dev-ai: ${phase}-run security check for ${opts.project}`);

    try {
      const result = await scanProject(projectPath);
      saveReport(result);

      const blockSeverity = opts.blockOn.toUpperCase() as 'CRITICAL' | 'HIGH';
      const blockingFindings = result.findings.filter(f =>
        blockSeverity === 'HIGH'
          ? f.severity === 'CRITICAL' || f.severity === 'HIGH'
          : f.severity === 'CRITICAL'
      );

      if (blockingFindings.length > 0) {
        console.error(`secure-dev-ai: BLOCKED - ${blockingFindings.length} ${blockSeverity}+ finding(s):`);
        for (const f of blockingFindings.slice(0, 5)) {
          console.error(`  [${f.severity}] ${f.title}${f.file ? ` (${f.file})` : ''}`);
        }
        process.exit(1);
      }

      console.log(`secure-dev-ai: OK - Score ${result.score} (${result.scoreNumeric}/100), no blocking issues`);
      process.exit(0);
    } catch (e) {
      console.error(`secure-dev-ai: scan error: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(0); // Don't block on scan error
    }
  });

// threat-model command
program
  .command('threat-model [project]')
  .description('Generate an AI-powered STRIDE threat model for a project')
  .action(async (project: string | undefined) => {
    if (!project) {
      console.error(chalk.red('Specify a project name'));
      process.exit(1);
    }
    const projects = discoverProjects();
    const p = projects.find(proj => proj.name === project);
    if (!p) {
      console.error(chalk.red(`Project not found: ${project}`));
      process.exit(1);
    }
    const spinner = ora(`Generating threat model for ${chalk.bold(project)}...`).start();
    const { scanThreatModel } = await import('./scanners/threatModel.js');
    const findings = await scanThreatModel(p.projectPath);
    spinner.stop();
    for (const f of findings) {
      if (f.severity === 'INFO') {
        console.log(chalk.gray(f.description));
      } else {
        console.log(`${severityColor(f.severity)} ${f.title}`);
        if (f.remediation) console.log(chalk.cyan(`  Fix: ${f.remediation}`));
      }
    }
    if (findings.some(f => f.severity !== 'INFO')) {
      console.log(chalk.green(`\nTHREAT-MODEL.md written to ${p.projectPath}`));
    }
  });

// config command
program
  .command('config')
  .description('Set persistent configuration')
  .option('--api-key <key>', 'Set Anthropic API key')
  .option('--workspace <path>', 'Set workspace root path')
  .option('--block-on <severity>', 'Set blocking severity: CRITICAL or HIGH')
  .option('--show', 'Show current config')
  .action((opts: { apiKey?: string; workspace?: string; blockOn?: string; show?: boolean }) => {
    const config = loadConfig();
    if (opts.show) {
      console.log(JSON.stringify({ ...config, anthropicApiKey: config.anthropicApiKey ? '***set***' : undefined }, null, 2));
      return;
    }
    if (opts.apiKey) config.anthropicApiKey = opts.apiKey;
    if (opts.workspace) config.workspaceRoot = opts.workspace;
    if (opts.blockOn) config.blockOnSeverity = opts.blockOn as 'CRITICAL' | 'HIGH';
    saveConfig(config);
    console.log(chalk.green('Config saved.'));
  });

program.parse(process.argv);

// Show help if no args
if (process.argv.length <= 2) {
  program.help();
}
