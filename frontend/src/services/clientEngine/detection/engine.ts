import type { ParsedEvent, Finding } from '../../../types';
import {
  DEFAULT_DETECTION_CONFIG,
  type DetectionConfig,
  checkBruteForce,
  checkPasswordSpray,
  checkSuccessAfterFailure,
  checkHTTPRecon,
  checkSensitivePaths,
  checkHTTPAuthFailures,
  checkHighVolume,
  checkSystemErrorBurst,
} from './rules';

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export function runDetectionRules(
  events: ParsedEvent[],
  customConfig?: Partial<DetectionConfig>
): Finding[] {
  const config: DetectionConfig = {
    ...DEFAULT_DETECTION_CONFIG,
    ...(customConfig || {}),
  };

  const findings: Finding[] = [
    ...checkBruteForce(events, config),
    ...checkPasswordSpray(events, config),
    ...checkSuccessAfterFailure(events, config),
    ...checkHTTPRecon(events, config),
    ...checkSensitivePaths(events),
    ...checkHTTPAuthFailures(events, config),
    ...checkHighVolume(events, config),
    ...checkSystemErrorBurst(events, config),
  ];

  // Tag matching events as suspicious and record detection IDs
  const suspiciousMap = new Map<string, string[]>();
  for (const f of findings) {
    for (const eid of f.event_ids) {
      if (!suspiciousMap.has(eid)) suspiciousMap.set(eid, []);
      suspiciousMap.get(eid)!.push(f.rule_id);
    }
  }

  for (const e of events) {
    if (suspiciousMap.has(e.id)) {
      e.is_suspicious = true;
      e.detection_ids = Array.from(new Set([...e.detection_ids, ...suspiciousMap.get(e.id)!]));
    }
  }

  // Sort findings by severity (Critical first)
  findings.sort((a, b) => (SEVERITY_WEIGHTS[a.severity] ?? 5) - (SEVERITY_WEIGHTS[b.severity] ?? 5));

  return findings;
}
