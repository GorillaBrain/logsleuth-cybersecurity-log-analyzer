export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type InvestigationStatus = 'new' | 'investigating' | 'resolved' | 'false_positive';

export type EventCategory = 
  | 'authentication' 
  | 'authorization' 
  | 'network' 
  | 'web_access' 
  | 'system' 
  | 'application' 
  | 'security' 
  | 'unknown';

export interface ParsedEvent {
  id: string;
  timestamp: string | null;
  raw_message: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  username?: string | null;
  hostname?: string | null;
  event_category: EventCategory;
  event_action?: string | null;
  http_method?: string | null;
  http_path?: string | null;
  http_status?: number | null;
  http_user_agent?: string | null;
  process_name?: string | null;
  pid?: number | null;
  severity: Severity;
  is_suspicious: boolean;
  detection_ids: string[];
  extra?: Record<string, unknown>;
  line_number?: number | null;
}

export interface ParseError {
  line: number;
  content: string;
  error: string;
}

export interface ParseResult {
  events: ParsedEvent[];
  total_lines: number;
  parsed_count: number;
  skipped_count: number;
  error_count: number;
  errors: ParseError[];
  format_detected: string | null;
}

export type IOCType = 'ipv4' | 'domain' | 'url' | 'email' | 'md5' | 'sha1' | 'sha256';

export interface IOC {
  value: string;
  ioc_type: IOCType;
  count: number;
  first_seen: string | null;
  last_seen: string | null;
  event_ids: string[];
  context: string;
  is_private: boolean;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  rule_id: string;
  rule_name: string;
  description: string;
  explanation: string;
  evidence_strength: 'Weak' | 'Moderate' | 'Strong';
  first_seen: string | null;
  last_seen: string | null;
  source_ips: string[];
  usernames: string[];
  event_count: number;
  event_ids: string[];
  recommended_actions: string[];
  mitre_technique?: string | null;
  investigation_status: InvestigationStatus;
  analyst_notes: string[];
}

export interface AnalysisSummary {
  total_events: number;
  total_findings: number;
  severity_counts: Record<string, number>;
  category_counts: Record<string, number>;
  top_source_ips: Array<{ ip: string; count: number }>;
  top_usernames: Array<{ username: string; count: number }>;
  auth_success: number;
  auth_failed: number;
  timeline: Array<{ time: string; count: number }>;
  parse_stats: {
    total_lines: number;
    parsed: number;
    skipped: number;
    errors: number;
    format: string | null;
  };
  suspicious_events: number;
}

export interface AnalysisResult {
  analysis_id: string;
  analysis_timestamp: string;
  dataset_name?: string | null;
  parse_result: ParseResult;
  events: ParsedEvent[];
  findings: Finding[];
  iocs: IOC[];
  summary: AnalysisSummary;
}

export interface DetectionRuleMeta {
  rule_id: string;
  rule_name: string;
  description: string;
  mitre_technique?: string | null;
  severity: Severity;
  logic: string;
  limitations: string;
  false_positives: string;
  category: string;
}

export interface SampleDataset {
  id: string;
  name: string;
  description: string;
  format: string;
  content: string;
  eventCount: number;
}

export interface EventFilterState {
  search: string;
  severity: Severity | 'all';
  category: EventCategory | 'all';
  sourceIp: string;
  username: string;
  httpStatus: string;
  suspiciousOnly: boolean;
}
