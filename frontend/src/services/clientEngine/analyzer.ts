import type {
  AnalysisResult,
  AnalysisSummary,
  ParsedEvent,
  Finding,
  ParseResult,
} from '../../types';
import { parseLogsClient } from './parsers/parserRouter';
import { runDetectionRules } from './detection/engine';
import { extractIOCsClient } from './iocExtractor';
import type { DetectionConfig } from './detection/rules';

function buildSummary(
  events: ParsedEvent[],
  findings: Finding[],
  parseResult: ParseResult
): AnalysisSummary {
  const severityCounts: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  }

  const categoryCounts: Record<string, number> = {};
  for (const e of events) {
    categoryCounts[e.event_category] = (categoryCounts[e.event_category] || 0) + 1;
  }

  // Top IPs
  const ipMap = new Map<string, number>();
  for (const e of events) {
    if (e.source_ip) {
      ipMap.set(e.source_ip, (ipMap.get(e.source_ip) || 0) + 1);
    }
  }
  const topSourceIps = Array.from(ipMap.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Top Usernames
  const userMap = new Map<string, number>();
  for (const e of events) {
    if (e.username) {
      userMap.set(e.username, (userMap.get(e.username) || 0) + 1);
    }
  }
  const topUsernames = Array.from(userMap.entries())
    .map(([username, count]) => ({ username, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Auth counts
  let authSuccess = 0;
  let authFailed = 0;
  for (const e of events) {
    const act = (e.event_action || '').toLowerCase();
    if (act.includes('success') || act.includes('accept')) authSuccess++;
    else if (act.includes('fail') || act.includes('invalid') || act.includes('denied')) authFailed++;
  }

  // Timeline by hour
  const timelineMap = new Map<string, number>();
  for (const e of events) {
    if (e.timestamp) {
      const d = new Date(e.timestamp);
      if (!isNaN(d.getTime())) {
        const hourKey = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')} ${String(d.getUTCHours()).padStart(2, '0')}:00`;
        timelineMap.set(hourKey, (timelineMap.get(hourKey) || 0) + 1);
      }
    }
  }
  const timeline = Array.from(timelineMap.entries())
    .map(([time, count]) => ({ time, count }))
    .sort((a, b) => a.time.localeCompare(b.time));

  return {
    total_events: events.length,
    total_findings: findings.length,
    severity_counts: severityCounts,
    category_counts: categoryCounts,
    top_source_ips: topSourceIps,
    top_usernames: topUsernames,
    auth_success: authSuccess,
    auth_failed: authFailed,
    timeline,
    parse_stats: {
      total_lines: parseResult.total_lines,
      parsed: parseResult.parsed_count,
      skipped: parseResult.skipped_count,
      errors: parseResult.error_count,
      format: parseResult.format_detected,
    },
    suspicious_events: events.filter(e => e.is_suspicious).length,
  };
}

export function analyzeLogsClient(
  content: string,
  datasetName?: string | null,
  formatHint?: string | null,
  columnMapping?: Record<string, string>,
  detectionConfig?: Partial<DetectionConfig>
): AnalysisResult {
  const parseResult = parseLogsClient(content, formatHint, columnMapping);
  const findings = runDetectionRules(parseResult.events, detectionConfig);
  const iocs = extractIOCsClient(parseResult.events);
  const summary = buildSummary(parseResult.events, findings, parseResult);

  return {
    analysis_id: `client-analysis-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    analysis_timestamp: new Date().toISOString(),
    dataset_name: datasetName || 'Uploaded Dataset',
    parse_result: parseResult,
    events: parseResult.events,
    findings,
    iocs,
    summary,
  };
}
