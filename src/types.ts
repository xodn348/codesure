export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'vulnerability' | 'malicious';
export type TaxonomyCode = 'EXS' | 'EXM' | 'EXF' | 'NET' | 'SYS' | 'DEF' | 'MET';

export interface PathContext {
  is_test: boolean;
  is_vendor: boolean;
  is_generated: boolean;
  is_docs: boolean;
  context_multiplier: number; // 1.0=production, 0.3=test, 0.1=vendor/docs
}

export interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  confidence: number; // 0-100
  rule_id: string;
  taxonomy?: TaxonomyCode;
  message: string;
  location: {
    file?: string;
    line?: number;
    column?: number;
  };
  snippet?: string;
  fix_suggestion?: string;
  evidence_chain?: string[];
  entropy?: number;
  suppressed?: boolean;
  suppression_rule?: string;
  path_context?: PathContext;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  suppressed_count: number;
  scan_time_ms: number;
}

export interface ScanResult {
  findings: Finding[];
  summary: ScanSummary;
}

export interface SecurityRule {
  id: string;
  category: Category;
  taxonomy?: TaxonomyCode;
  severity: Severity;
  languages: string[];
  pattern: string;
  pattern_not?: string;
  message: string;
  fix?: string;
  metadata?: {
    cwe?: string;
    owasp?: string;
    confidence?: 'high' | 'medium' | 'low';
  };
}

export interface PackageCheckResult {
  name: string;
  exists: boolean;
  risk_score: number;
  issues: string[];
}

export interface ManifestCheckResult {
  permissions_score: number;
  dangerous_permissions: string[];
  findings: Finding[];
}

export interface AgentInfo {
  name: string;
  version: string;
}
