import { z } from 'zod';

export const RiskSeveritySchema = z.enum(['low', 'medium', 'high', 'critical']);
export type RiskSeverity = z.infer<typeof RiskSeveritySchema>;

export const DecisionOutcomeSchema = z.enum(['allow', 'sandbox', 'block']);
export type DecisionOutcome = z.infer<typeof DecisionOutcomeSchema>;

export const CertificateStatusSchema = z.enum(['active', 'invalidated', 'expired', 'revoked']);
export type CertificateStatus = z.infer<typeof CertificateStatusSchema>;

export const RiskFindingSchema = z.object({
  id: z.string(),
  checker: z.string(),
  type: z.string(),
  severity: RiskSeveritySchema,
  description: z.string(),
  evidence: z.string().optional(),
});
export type RiskFinding = z.infer<typeof RiskFindingSchema>;

export const MCPToolCapabilitySchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  inputSchema: z.record(z.unknown()).optional(),
  category: z.string().optional(),
});
export type MCPToolCapability = z.infer<typeof MCPToolCapabilitySchema>;

export const MCPManifestSchema = z.object({
  name: z.string(),
  version: z.string().default('1.0.0'),
  description: z.string().optional(),
  source_url: z.string().optional(),
  tools: z.array(MCPToolCapabilitySchema).default([]),
  permissions: z.array(z.string()).default([]),
});
export type MCPManifest = z.infer<typeof MCPManifestSchema>;

export const ToolSchema = z.object({
  id: z.string(),
  org_id: z.string(),
  name: z.string(),
  source_url: z.string().optional(),
  created_at: z.string(),
});
export type Tool = z.infer<typeof ToolSchema>;

export const ScanSchema = z.object({
  id: z.string(),
  tool_id: z.string(),
  tool_hash: z.string(),
  manifest: MCPManifestSchema,
  findings: z.array(RiskFindingSchema),
  scanned_at: z.string(),
  scanned_by: z.string(),
});
export type Scan = z.infer<typeof ScanSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().optional(),
  condition: z.string(), // Simple evaluation condition e.g. "finding.type == 'prompt_injection'"
  finding_type: z.string().optional(),
  min_severity: RiskSeveritySchema.optional(),
  outcome: DecisionOutcomeSchema,
  reason: z.string(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  id: z.string(),
  org_id: z.string(),
  name: z.string(),
  rules: z.array(PolicyRuleSchema),
  version: z.number().default(1),
  active: z.boolean().default(true),
  created_at: z.string(),
});
export type Policy = z.infer<typeof PolicySchema>;

export const DecisionSchema = z.object({
  id: z.string(),
  scan_id: z.string(),
  policy_id: z.string(),
  outcome: DecisionOutcomeSchema,
  reason: z.string(),
  decided_at: z.string(),
});
export type Decision = z.infer<typeof DecisionSchema>;

export const WardenCertificateBodySchema = z.object({
  warden_certificate_version: z.literal('1.0'),
  certificate_id: z.string(),
  tool: z.object({
    name: z.string(),
    source_url: z.string().optional(),
    hash: z.string(),
    version: z.string(),
  }),
  approved_capabilities: z.array(z.string()),
  risk_summary: z.object({
    findings_count: z.number(),
    highest_severity: z.string(),
    notes: z.string(),
  }),
  decision: z.object({
    outcome: DecisionOutcomeSchema,
    reason: z.string(),
  }),
  issuer: z.object({
    org_id: z.string(),
    org_name: z.string(),
    public_key: z.string(),
  }),
  issued_at: z.string(),
  expires_at: z.string(),
});
export type WardenCertificateBody = z.infer<typeof WardenCertificateBodySchema>;

export const WardenCertificateSchema = WardenCertificateBodySchema.extend({
  signature: z.string(),
  status: CertificateStatusSchema.default('active'),
});
export type WardenCertificate = z.infer<typeof WardenCertificateSchema>;

export const AuditLogEntrySchema = z.object({
  id: z.number(),
  event_type: z.string(),
  entity_id: z.string().nullable().optional(),
  actor: z.string(),
  detail: z.record(z.unknown()).optional(),
  prev_row_hash: z.string(),
  row_hash: z.string(),
  created_at: z.string(),
});
export type AuditLogEntry = z.infer<typeof AuditLogEntrySchema>;

export const OrganizationSchema = z.object({
  id: z.string(),
  name: z.string(),
  ca_public_key: z.string(),
  ca_key_managed_externally: z.boolean().default(false),
  created_at: z.string(),
});
export type Organization = z.infer<typeof OrganizationSchema>;

export const VerifyResponseSchema = z.object({
  decision: DecisionOutcomeSchema,
  reason: z.string(),
  certificate_id: z.string().nullable().optional(),
  risk_score: z.number().default(0),
  approved_capabilities: z.array(z.string()).optional(),
});
export type VerifyResponse = z.infer<typeof VerifyResponseSchema>;

export const ApiKeySchema = z.object({
  id: z.string(),
  org_id: z.string(),
  name: z.string(),
  key_hash: z.string(),
  key_prefix: z.string(),
  created_at: z.string(),
  last_used_at: z.string().nullable().optional(),
});
export type ApiKey = z.infer<typeof ApiKeySchema>;

export const WebhookSubscriptionSchema = z.object({
  id: z.string(),
  org_id: z.string(),
  url: z.string().url(),
  events: z.array(z.string()).default(['cert_revoked']),
  secret: z.string().optional(),
  created_at: z.string(),
  active: z.boolean().default(true),
});
export type WebhookSubscription = z.infer<typeof WebhookSubscriptionSchema>;
