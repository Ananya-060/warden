#!/usr/bin/env node
import { Command } from 'commander';
import pc from 'picocolors';
import fs from 'node:fs';
import path from 'node:path';
import { canonicalizeJson, computeSha256, verifyCanonicalJsonSignature, WardenCertificate } from '@warden/shared';
import { Warden } from '@warden/sdk';

const program = new Command();
const API_BASE = process.env.WARDEN_API_URL || 'http://localhost:3000';

program
  .name('warden')
  .description('🛡️ Warden — Portable Trust Infrastructure for AI Tools (CLI)')
  .version('1.0.0');

// 1. SCAN COMMAND
program
  .command('scan <target>')
  .description('Inspect an MCP tool manifest file or URL')
  .action(async (target: string) => {
    console.log(pc.cyan(`🔍 Inspecting MCP target: ${target}`));

    let manifest: any;
    let toolName = 'mcp-tool';

    try {
      if (fs.existsSync(target)) {
        const fileContent = fs.readFileSync(target, 'utf-8');
        manifest = JSON.parse(fileContent);
        toolName = manifest.name || path.basename(target, '.json');
      } else if (target.startsWith('http://') || target.startsWith('https://')) {
        const res = await fetch(target);
        manifest = await res.json();
        toolName = manifest.name || 'remote-mcp-tool';
      } else {
        console.error(pc.red(`❌ Target file or URL not found: ${target}`));
        process.exit(1);
      }

      const response = await fetch(`${API_BASE}/v1/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool_name: toolName,
          source_url: target,
          manifest,
          actor: 'cli:developer',
        }),
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.error || response.statusText);
      }

      const data = await response.json();
      console.log(pc.green(`\n✅ Scan completed successfully!`));
      console.log(pc.bold(`Scan ID:`), data.scan.id);
      console.log(pc.bold(`Tool Hash:`), pc.yellow(data.scan.tool_hash));
      console.log(pc.bold(`Risk Findings (${data.findings.length}):`));

      if (data.findings.length === 0) {
        console.log(pc.dim('  No risk findings detected. Tool appears safe.'));
      } else {
        data.findings.forEach((f: any) => {
          const color = f.severity === 'critical' ? pc.red : f.severity === 'high' ? pc.yellow : pc.blue;
          console.log(`  - [${color(f.severity.toUpperCase())}] ${f.description}`);
          if (f.evidence) console.log(pc.dim(`    Evidence: ${f.evidence}`));
        });
      }

      if (data.diff) {
        console.log(pc.bold(`\nManifest Diff:`));
        console.log(pc.dim(data.diff));
      }

      console.log(pc.cyan(`\nTo approve this scan and issue a trust certificate, run:`));
      console.log(pc.bold(`  warden approve ${data.scan.id}`));
    } catch (err) {
      console.error(pc.red(`❌ Scan failed: ${(err as Error).message}`));
      process.exit(1);
    }
  });

// 2. APPROVE COMMAND
program
  .command('approve <scan-id>')
  .description('Apply organizational policy and issue an Ed25519 signed certificate')
  .action(async (scanId: string) => {
    console.log(pc.cyan(`⚖️ Evaluating scan ${scanId} against policy...`));

    try {
      // 1. Evaluate Decision
      const decRes = await fetch(`${API_BASE}/v1/decisions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, actor: 'cli:security-admin' }),
      });

      if (!decRes.ok) {
        const err = await decRes.json();
        throw new Error(err.error || decRes.statusText);
      }

      const decision = await decRes.json();
      console.log(`\nPolicy Decision: [${pc.bold(decision.outcome.toUpperCase())}]`);
      console.log(`Reason: ${decision.reason}`);

      if (decision.outcome === 'block') {
        console.error(pc.red(`❌ Certificate issuing blocked by policy!`));
        process.exit(1);
      }

      // 2. Issue Certificate
      const certRes = await fetch(`${API_BASE}/v1/certificates`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision_id: decision.id, actor: 'cli:security-admin' }),
      });

      if (!certRes.ok) {
        const err = await certRes.json();
        throw new Error(err.error || certRes.statusText);
      }

      const cert: WardenCertificate = await certRes.json();
      const safeToolName = cert.tool.name.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const filename = `warden-cert-${safeToolName}.json`;

      fs.writeFileSync(filename, JSON.stringify(cert, null, 2));

      console.log(pc.green(`\n📜 Trust Certificate successfully issued & signed!`));
      console.log(pc.bold(`Certificate ID:`), cert.certificate_id);
      console.log(pc.bold(`Issuer:`), cert.issuer.org_name);
      console.log(pc.bold(`Public Key:`), pc.dim(cert.issuer.public_key));
      console.log(pc.bold(`Signature:`), pc.dim(cert.signature.substring(0, 32) + '...'));
      console.log(pc.green(`Saved portable certificate to: ${filename}`));
    } catch (err) {
      console.error(pc.red(`❌ Approval failed: ${(err as Error).message}`));
      process.exit(1);
    }
  });

// 3. VERIFY COMMAND (CI/CD Exit Codes: 0 = allow, 1 = block, 2 = sandbox)
program
  .command('verify [target]')
  .option('-h, --hash <currentToolHash>', 'Specify current tool manifest SHA-256 hash to verify against')
  .option('-c, --config <file>', 'Verify all tools listed in a config file (JSON array or { "tools": [...] })')
  .option('--fail-on-invalid', 'Exit non-zero if any tool in --config fails verification')
  .description('Verify tool trust via API, or verify a certificate file/ID')
  .action(async (target: string | undefined, options: any) => {
    const warden = new Warden({
      apiKey: process.env.WARDEN_API_KEY,
      baseUrl: API_BASE,
    });

    // Batch config mode (CI/CD pipeline gate)
    if (options.config) {
      if (!fs.existsSync(options.config)) {
        console.error(pc.red(`❌ Config file not found: ${options.config}`));
        process.exit(1);
      }

      const configRaw = JSON.parse(fs.readFileSync(options.config, 'utf-8'));
      const tools: string[] = Array.isArray(configRaw) ? configRaw : configRaw.tools;

      if (!Array.isArray(tools) || tools.length === 0) {
        console.error(pc.red('❌ Config must be a JSON array of tool URLs/paths or { "tools": [...] }'));
        process.exit(1);
      }

      console.log(pc.cyan(`🚀 Verifying ${tools.length} tool(s) from ${options.config}...`));
      let allPassed = true;

      for (const toolUrl of tools) {
        console.log(pc.bold(`\n→ ${toolUrl}`));
        try {
          const result = await warden.verify(toolUrl);
          console.log(`  Decision: [${result.decision.toUpperCase()}] ${result.reason}`);
          if (result.decision !== 'allow') {
            allPassed = false;
            if (options.failOnInvalid) {
              console.error(pc.red(`  ❌ Blocked`));
            }
          } else {
            console.log(pc.green(`  ✅ Allowed`));
          }
        } catch (err) {
          allPassed = false;
          console.error(pc.red(`  💥 Error: ${(err as Error).message}`));
        }
      }

      if (!allPassed) {
        console.error(pc.red('\n❌ CI/CD GATE FAILED: One or more tools did not pass Warden verification.'));
        process.exit(1);
      }

      console.log(pc.green('\n✅ CI/CD GATE PASSED: All tools verified successfully.'));
      process.exit(0);
    }

    // SDK verify mode for manifest files / URLs
    if (target && (fs.existsSync(target) || target.startsWith('http://') || target.startsWith('https://'))) {
      try {
        const isCertFile = target.endsWith('.json') && fs.existsSync(target) &&
          JSON.parse(fs.readFileSync(target, 'utf-8')).certificate_id;

        if (!isCertFile || target.includes('manifest')) {
          const result = await warden.verify(target);
          console.log(`\n🛡️  Warden Verification Report`);
          console.log(`-----------------------------------`);
          console.log(`Tool:     ${pc.bold(target)}`);
          console.log(`Decision: [${pc.bold(result.decision.toUpperCase())}]`);
          console.log(`Reason:   ${result.reason}`);
          if (result.certificate_id) {
            console.log(`Cert ID:  ${result.certificate_id}`);
          }

          if (result.decision === 'allow') {
            console.log(pc.green(`\n✅ TRUST VERIFIED. SAFE TO EXECUTE.`));
            process.exit(0);
          }
          if (result.decision === 'sandbox') {
            console.log(pc.yellow(`\n⚠️  ALLOWED IN SANDBOX MODE`));
            process.exit(2);
          }
          console.error(pc.red(`\n❌ VERIFICATION FAILED: Tool not trusted.`));
          process.exit(1);
        }
      } catch (err) {
        // fall through to certificate verification if SDK path fails for cert files
        if (!target.endsWith('.json') || !(err as Error).message.includes('certificate_id')) {
          console.error(pc.red(`❌ Verification error: ${(err as Error).message}`));
          process.exit(1);
        }
      }
    }

    if (!target) {
      console.error(pc.red('❌ Provide a target, or use --config <file> for batch verification.'));
      process.exit(1);
    }

    // Certificate file / ID verification (legacy path)
    try {
      let cert: WardenCertificate;

      if (fs.existsSync(target)) {
        cert = JSON.parse(fs.readFileSync(target, 'utf-8'));
      } else {
        const res = await fetch(`${API_BASE}/v1/certificates/${target}`);
        if (!res.ok) throw new Error(`Certificate '${target}' not found in API or file.`);
        cert = await res.json();
      }

      // Perform verification
      const { signature, status, ...body } = cert;
      const signatureValid = await verifyCanonicalJsonSignature(body, signature, cert.issuer.public_key);

      let hashMatch = true;
      if (options.hash && options.hash !== cert.tool.hash) {
        hashMatch = false;
      }

      console.log(`\n🛡️  Warden Verification Report`);
      console.log(`-----------------------------------`);
      console.log(`Tool Name: ${pc.bold(cert.tool.name)} (v${cert.tool.version})`);
      console.log(`Issuer:    ${cert.issuer.org_name}`);
      console.log(`Signature: ${signatureValid ? pc.green('VALID (Ed25519)') : pc.red('INVALID')}`);
      console.log(`Tool Hash: ${hashMatch ? pc.green('MATCHED') : pc.red(`MISMATCHED (Cert: ${cert.tool.hash.slice(0, 16)}..., Live: ${options.hash?.slice(0, 16)}...)`)}`);
      console.log(`Decision:  ${pc.bold(cert.decision.outcome.toUpperCase())}`);

      if (!signatureValid) {
        console.error(pc.red(`\n❌ VERIFICATION FAILED: Forged or corrupted signature!`));
        process.exit(1);
      }

      if (!hashMatch) {
        console.error(pc.red(`\n❌ VERIFICATION FAILED: Tool code or manifest has changed since certification!`));
        process.exit(1);
      }

      if (cert.decision.outcome === 'sandbox') {
        console.log(pc.yellow(`\n⚠️  ALLOWED IN SANDBOX MODE: ${cert.decision.reason}`));
        process.exit(2);
      }

      console.log(pc.green(`\n✅ TRUST CERTIFICATE VERIFIED & ACTIVE. SAFE TO EXECUTE.`));
      process.exit(0);
    } catch (err) {
      console.error(pc.red(`❌ Verification error: ${(err as Error).message}`));
      process.exit(1);
    }
  });

// 4. IMPORT COMMAND
program
  .command('import <cert-file>')
  .description('Import a trust certificate into Warden registry')
  .action(async (certFile: string) => {
    try {
      const certData = JSON.parse(fs.readFileSync(certFile, 'utf-8'));
      const res = await fetch(`${API_BASE}/v1/certificates/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(certData),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || res.statusText);
      }

      const result = await res.json();
      console.log(pc.green(`✅ Certificate for '${certData.tool.name}' successfully imported into Warden registry.`));
    } catch (err) {
      console.error(pc.red(`❌ Import failed: ${(err as Error).message}`));
      process.exit(1);
    }
  });

// 5. POLICY SIMULATE COMMAND
program
  .command('policy-simulate <policy-file>')
  .description('Dry-run a candidate YAML policy against historical scans')
  .action(async (policyFile: string) => {
    try {
      const yamlStr = fs.readFileSync(policyFile, 'utf-8');
      const res = await fetch(`${API_BASE}/v1/policies/simulation/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules: yamlStr }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || res.statusText);
      }

      const data = await res.json();
      console.log(pc.cyan(`\n📊 Policy Simulation Results`));
      console.log(`Scans Evaluated: ${data.total_scans}`);
      console.log(`Outcomes: Allow (${pc.green(data.outcomes.allow)}), Sandbox (${pc.yellow(data.outcomes.sandbox)}), Block (${pc.red(data.outcomes.block)})`);
    } catch (err) {
      console.error(pc.red(`❌ Policy simulation failed: ${(err as Error).message}`));
      process.exit(1);
    }
  });

program.parse(process.argv);
