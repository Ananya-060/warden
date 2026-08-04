import { MCPManifest, RiskFinding } from '@warden/shared';
import crypto from 'node:crypto';

export class RiskEngine {
  /**
   * Runs all pluggable static risk checkers over an MCP manifest.
   */
  static analyzeManifest(manifest: MCPManifest): RiskFinding[] {
    const findings: RiskFinding[] = [];

    findings.push(...this.checkInjectionPatterns(manifest));
    findings.push(...this.checkPermissionMismatches(manifest));
    findings.push(...this.checkExcessivePermissions(manifest));
    findings.push(...this.checkSupplyChainPinning(manifest));
    findings.push(...this.checkMetadataCompleteness(manifest));

    return findings;
  }

  /**
   * 1. Prompt Injection Pattern Checker
   */
  private static checkInjectionPatterns(manifest: MCPManifest): RiskFinding[] {
    const findings: RiskFinding[] = [];
    const injectionRegexes = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /system\s*:\s*you\s+must/i,
      /override\s+(system\s+)?prompt/i,
      /exfiltrate/i,
      /curl\s+-X\s+POST/i,
      /<script[\s\S]*?>/i,
      /eval\s*\(/i,
      /rm\s+-rf\s+\//i,
    ];

    const inspectText = (text: string, source: string) => {
      for (const regex of injectionRegexes) {
        if (regex.test(text)) {
          findings.push({
            id: `inj-${crypto.randomUUID()}`,
            checker: 'injection_pattern_checker',
            type: 'prompt_injection',
            severity: 'critical',
            description: `Potential prompt injection / instruction override pattern detected in ${source}.`,
            evidence: text.length > 120 ? text.substring(0, 120) + '...' : text,
          });
          break;
        }
      }
    };

    if (manifest.description) inspectText(manifest.description, 'tool description');

    for (const tool of manifest.tools || []) {
      if (tool.description) inspectText(tool.description, `tool '${tool.name}' description`);
      if (tool.inputSchema) {
        const schemaStr = JSON.stringify(tool.inputSchema);
        inspectText(schemaStr, `tool '${tool.name}' input schema`);
      }
    }

    return findings;
  }

  /**
   * 2. Permission vs Description Mismatch Checker
   */
  private static checkPermissionMismatches(manifest: MCPManifest): RiskFinding[] {
    const findings: RiskFinding[] = [];

    const isReadOnlyDesc = (desc?: string) => {
      if (!desc) return false;
      const lower = desc.toLowerCase();
      return (
        lower.includes('read-only') ||
        lower.includes('read only') ||
        lower.includes('view') ||
        lower.includes('fetch only') ||
        lower.includes('inspect')
      );
    };

    const isMutatingTool = (name: string) => {
      const lower = name.toLowerCase();
      return (
        lower.includes('delete') ||
        lower.includes('remove') ||
        lower.includes('drop') ||
        lower.includes('write') ||
        lower.includes('update') ||
        lower.includes('exec') ||
        lower.includes('modify')
      );
    };

    if (isReadOnlyDesc(manifest.description)) {
      for (const tool of manifest.tools || []) {
        if (isMutatingTool(tool.name)) {
          findings.push({
            id: `mismatch-${crypto.randomUUID()}`,
            checker: 'permission_mismatch_checker',
            type: 'permission_mismatch',
            severity: 'high',
            description: `Tool '${tool.name}' provides mutating capabilities, but manifest description claims to be read-only.`,
            evidence: `Tool name '${tool.name}' contradicts read-only manifest description: "${manifest.description}"`,
          });
        }
      }
    }

    return findings;
  }

  /**
   * 3. Excessive Permission / High Scope Checker
   */
  private static checkExcessivePermissions(manifest: MCPManifest): RiskFinding[] {
    const findings: RiskFinding[] = [];

    const dangerousKeywords = ['shell_exec', 'system_command', 'run_terminal', 'eval_code', 'file_write_root', 'raw_sql'];

    for (const tool of manifest.tools || []) {
      if (dangerousKeywords.some((kw) => tool.name.toLowerCase().includes(kw))) {
        findings.push({
          id: `excess-${crypto.randomUUID()}`,
          checker: 'excessive_permission_checker',
          type: 'excessive_permission',
          severity: 'high',
          description: `Tool '${tool.name}' requests dangerous direct system execution capability.`,
          evidence: `Tool capability: ${tool.name}`,
        });
      }
    }

    for (const perm of manifest.permissions || []) {
      if (perm === '*' || perm === 'root' || perm === 'all') {
        findings.push({
          id: `excess-perm-${crypto.randomUUID()}`,
          checker: 'excessive_permission_checker',
          type: 'excessive_permission',
          severity: 'critical',
          description: `Manifest requests unconstrained wildcard permission '${perm}'.`,
          evidence: `Declared permission: ${perm}`,
        });
      }
    }

    return findings;
  }

  /**
   * 4. Supply Chain Pinning Checker
   * Flags tools without pinned versions or missing source URLs (supply chain risk).
   */
  private static checkSupplyChainPinning(manifest: MCPManifest): RiskFinding[] {
    const findings: RiskFinding[] = [];

    // Flag 'latest' or unpinned version tags
    const version = (manifest as any).version || '';
    if (!version || version === 'latest' || version === '*' || version === 'next') {
      findings.push({
        id: `supply-version-${crypto.randomUUID()}`,
        checker: 'supply_chain_pinning_checker',
        type: 'supply_chain_risk',
        severity: 'medium',
        description: `Manifest does not declare a pinned version (found: '${version || 'none'}').`,
        evidence: `version: "${version || 'none'}". Unpinned tools may silently update to malicious versions.`,
      });
    }

    // Flag missing source URL — cannot verify provenance
    if (!manifest.source_url || manifest.source_url.trim() === '') {
      findings.push({
        id: `supply-nourl-${crypto.randomUUID()}`,
        checker: 'supply_chain_pinning_checker',
        type: 'supply_chain_risk',
        severity: 'low',
        description: 'Manifest does not include a source_url. Cannot verify tool provenance or check for upstream changes.',
        evidence: 'source_url field is missing or empty.',
      });
    }

    // Flag GitHub source URLs without commit SHAs (only branch refs)
    if (manifest.source_url && /github\.com\/.*\/tree\/(?!main|master)/i.test(manifest.source_url) === false) {
      const hasCommitSha = /github\.com\/.*\/(?:tree|blob)\/[0-9a-f]{40}/i.test(manifest.source_url);
      if (!hasCommitSha && manifest.source_url.includes('github.com')) {
        findings.push({
          id: `supply-unpinned-${crypto.randomUUID()}`,
          checker: 'supply_chain_pinning_checker',
          type: 'supply_chain_risk',
          severity: 'low',
          description: 'GitHub source URL is not pinned to a specific commit SHA. Code may change silently.',
          evidence: `source_url: ${manifest.source_url}`,
        });
      }
    }

    return findings;
  }

  /**
   * 5. Metadata Completeness Checker
   * Tools without adequate descriptions may be hiding their capabilities.
   */
  private static checkMetadataCompleteness(manifest: MCPManifest): RiskFinding[] {
    const findings: RiskFinding[] = [];

    // Missing tool-level description
    if (!manifest.description || manifest.description.trim().length < 20) {
      findings.push({
        id: `meta-desc-${crypto.randomUUID()}`,
        checker: 'metadata_completeness_checker',
        type: 'metadata_incomplete',
        severity: 'low',
        description: `Manifest description is missing or too short (${manifest.description?.length ?? 0} chars). Auditors cannot assess tool intent without a clear description.`,
        evidence: `description: "${manifest.description || ''}"`,
      });
    }

    // Tool-level missing descriptions
    const toolsWithoutDesc = (manifest.tools || []).filter((t) => !t.description || t.description.trim().length < 10);
    if (toolsWithoutDesc.length > 0) {
      findings.push({
        id: `meta-tools-${crypto.randomUUID()}`,
        checker: 'metadata_completeness_checker',
        type: 'metadata_incomplete',
        severity: 'low',
        description: `${toolsWithoutDesc.length} tool(s) lack adequate descriptions: ${toolsWithoutDesc.map((t) => `'${t.name}'`).join(', ')}.`,
        evidence: `Undescribed tools: ${toolsWithoutDesc.map((t) => t.name).join(', ')}`,
      });
    }

    // Empty permissions array on a tool with write-capable tools
    const hasMutatingTools = (manifest.tools || []).some((t) => {
      const lower = t.name.toLowerCase();
      return lower.includes('write') || lower.includes('create') || lower.includes('delete') || lower.includes('update');
    });
    if (hasMutatingTools && (!manifest.permissions || manifest.permissions.length === 0)) {
      findings.push({
        id: `meta-perms-${crypto.randomUUID()}`,
        checker: 'metadata_completeness_checker',
        type: 'metadata_incomplete',
        severity: 'medium',
        description: 'Manifest declares mutating tools but lists no permissions. Scope is ambiguous and cannot be audited.',
        evidence: 'permissions array is empty while write-capable tools are declared.',
      });
    }

    return findings;
  }
}
