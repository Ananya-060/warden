import fs from 'node:fs';
import path from 'node:path';
import { db } from '../db/index.js';
import { InspectorService } from './inspector.js';
import { PolicyEngineService } from './policy-engine.js';
import { CertificateAuthorityService } from './ca.js';

export async function seedRealWorldMCPTools() {
  // Check if a real-world MCP tool has already been seeded
  const alreadySeeded = db
    .prepare("SELECT COUNT(*) as count FROM tools WHERE name LIKE '%modelcontextprotocol%'")
    .get() as { count: number } | undefined;
  if (alreadySeeded && alreadySeeded.count >= 5) {
    return; // All 5 official MCP servers already seeded
  }


  const samplesDir = path.resolve(process.cwd(), 'samples');
  if (!fs.existsSync(samplesDir)) return;

  const sampleFolders = fs.readdirSync(samplesDir);

  for (const folder of sampleFolders) {
    const manifestPath = path.join(samplesDir, folder, 'manifest.json');
    if (!fs.existsSync(manifestPath)) continue;

    try {
      const manifestStr = fs.readFileSync(manifestPath, 'utf-8');
      const manifest = JSON.parse(manifestStr);
      const toolName = manifest.name || folder;

      // Check if tool already exists in DB
      const existingTool = db.prepare('SELECT id FROM tools WHERE name = ?').get(toolName);
      if (existingTool) continue;

      // 1. Inspect Tool
      const inspectResult = await InspectorService.inspectTool({
        tool_name: toolName,
        source_url: manifest.source_url || `https://github.com/modelcontextprotocol/servers/tree/main/src/${folder.replace('mcp-', '').replace('-server', '')}`,
        manifest,
        actor: 'system:seeder',
      });

      // 2. Evaluate Policy Decision
      const decision = PolicyEngineService.evaluateScan(inspectResult.scan.id, undefined, 'system:seeder');

      // 3. Issue Trust Certificate if decision is not block
      if (decision.outcome !== 'block') {
        await CertificateAuthorityService.issueCertificate(decision.id, 'system:seeder');
      }
    } catch (e) {
      console.warn(`Failed to seed real-world MCP server from '${folder}':`, (e as Error).message);
    }
  }
}
