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
import { scoreColor, severityColor, printScanResult, printSummaryTable, printProjectList, printFullReport } from './ui.js';
const VERSION = '0.1.0';

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
        spinner.succeed(chalk.bold(p.name));
        if (!opts.json) printScanResult(result);
        results.push(result);
      } catch (e) {
        spinner.fail(`${p.name} - scan failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    if (opts.json) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      printSummaryTable(results);
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
    printProjectList(projects, name => loadLatestReport(name));
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
    printFullReport(report);
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
