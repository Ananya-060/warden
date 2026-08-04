import { db } from '../db/index.js';
import { AuditLogService } from './audit-log.js';
import { Decision, DecisionOutcome, Policy, PolicyRule, RiskFinding, Scan } from '@warden/shared';
import crypto from 'node:crypto';
import YAML from 'yaml';

export class PolicyEngineService {
  /**
   * Evaluates a scan against an active org policy to produce a Decision (allow/sandbox/block).
   */
  static evaluateScan(scanId: string, policyId?: string, actor = 'system:cli'): Decision {
    const scanRow = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId) as any;
    if (!scanRow) {
      throw new Error(`Scan with ID '${scanId}' not found.`);
    }

    const findings: RiskFinding[] = JSON.parse(scanRow.findings || '[]');

    // Load policy (either requested or active policy for org)
    let policyRow: any;
    if (policyId) {
      policyRow = db.prepare('SELECT * FROM policies WHERE id = ?').get(policyId);
    } else {
      policyRow = db.prepare('SELECT * FROM policies WHERE active = 1 ORDER BY created_at DESC LIMIT 1').get();
    }

    if (!policyRow) {
      throw new Error('No active security policy found.');
    }

    const rules: PolicyRule[] = JSON.parse(policyRow.rules || '[]');
    const { outcome, reason } = this.evaluateRules(findings, rules);

    const decisionId = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare(
      `INSERT INTO decisions (id, scan_id, policy_id, outcome, reason, decided_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(decisionId, scanId, policyRow.id, outcome, reason, now);

    const decisionRecord: Decision = {
      id: decisionId,
      scan_id: scanId,
      policy_id: policyRow.id,
      outcome,
      reason,
      decided_at: now,
    };

    AuditLogService.logEvent({
      event_type: 'decision_made',
      entity_id: decisionId,
      actor,
      detail: {
        scan_id: scanId,
        policy_id: policyRow.id,
        outcome,
        reason,
      },
    });

    return decisionRecord;
  }

  /**
   * Evaluates rules array against findings.
   */
  private static evaluateRules(findings: RiskFinding[], rules: PolicyRule[]): { outcome: DecisionOutcome; reason: string } {
    for (const rule of rules) {
      if (rule.condition === 'default') continue;

      for (const finding of findings) {
        let matchesType = !rule.finding_type || rule.finding_type === finding.type;
        let matchesSeverity = true;

        if (rule.min_severity) {
          const severities = ['low', 'medium', 'high', 'critical'];
          const ruleMinIdx = severities.indexOf(rule.min_severity);
          const findingIdx = severities.indexOf(finding.severity);
          matchesSeverity = findingIdx >= ruleMinIdx;
        }

        if (matchesType && matchesSeverity) {
          return {
            outcome: rule.outcome,
            reason: `${rule.reason} (Triggered by finding '${finding.type}' - ${finding.description})`,
          };
        }
      }
    }

    // Default fallthrough
    const defaultRule = rules.find((r) => r.condition === 'default');
    return {
      outcome: defaultRule ? defaultRule.outcome : 'allow',
      reason: defaultRule ? defaultRule.reason : 'No policy violations detected.',
    };
  }

  /**
   * Dry-runs a candidate policy against historical scans to analyze impact.
   */
  static simulatePolicy(candidateRulesYamlOrJson: string, limit = 50): {
    total_scans: number;
    outcomes: Record<DecisionOutcome, number>;
    changes: Array<{ scan_id: string; tool_name: string; previous_outcome: string; simulated_outcome: DecisionOutcome; reason: string }>;
  } {
    let rules: PolicyRule[];
    try {
      rules = YAML.parse(candidateRulesYamlOrJson);
      if (!Array.isArray(rules)) throw new Error('Policy must be an array of rules');
    } catch (e) {
      throw new Error(`Invalid policy YAML format: ${(e as Error).message}`);
    }

    const scans = db.prepare('SELECT s.*, t.name as tool_name FROM scans s JOIN tools t ON s.tool_id = t.id ORDER BY s.scanned_at DESC LIMIT ?').all(limit) as any[];

    const outcomes: Record<DecisionOutcome, number> = { allow: 0, sandbox: 0, block: 0 };
    const changes: Array<{ scan_id: string; tool_name: string; previous_outcome: string; simulated_outcome: DecisionOutcome; reason: string }> = [];

    for (const scan of scans) {
      const findings: RiskFinding[] = JSON.parse(scan.findings || '[]');
      const simResult = this.evaluateRules(findings, rules);
      outcomes[simResult.outcome]++;

      // Get last decision if available
      const lastDecision = db.prepare('SELECT outcome FROM decisions WHERE scan_id = ? ORDER BY decided_at DESC LIMIT 1').get(scan.id) as { outcome: string } | undefined;
      const prevOutcome = lastDecision?.outcome || 'none';

      changes.push({
        scan_id: scan.id,
        tool_name: scan.tool_name,
        previous_outcome: prevOutcome,
        simulated_outcome: simResult.outcome,
        reason: simResult.reason,
      });
    }

    return {
      total_scans: scans.length,
      outcomes,
      changes,
    };
  }
}
