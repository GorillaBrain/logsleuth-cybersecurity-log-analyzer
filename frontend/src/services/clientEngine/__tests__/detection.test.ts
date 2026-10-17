import { describe, it, expect } from 'vitest';
import { analyzeLogsClient } from '../analyzer';
import { SAMPLE_DATASETS } from '../../sampleData';

describe('Detection Engine & Rules Verification', () => {
  it('Normal baseline auth log produces ZERO threat findings (False-Positive verification)', () => {
    const normalSample = SAMPLE_DATASETS.find(s => s.id === 'auth_normal')!;
    expect(normalSample).toBeDefined();

    const result = analyzeLogsClient(normalSample.content, 'Normal Test', normalSample.format);
    expect(result.events.length).toBeGreaterThan(30);
    expect(result.findings.length).toBe(0);
    expect(result.summary.total_findings).toBe(0);
    expect(result.summary.suspicious_events).toBe(0);
  });

  it('Detects SSH Brute Force, Password Spray, and Success After Failure on auth_bruteforce dataset', () => {
    const bruteSample = SAMPLE_DATASETS.find(s => s.id === 'auth_bruteforce')!;
    expect(bruteSample).toBeDefined();

    const result = analyzeLogsClient(bruteSample.content, 'Brute Test', bruteSample.format);
    expect(result.findings.length).toBeGreaterThanOrEqual(3);

    const ruleIds = result.findings.map(f => f.rule_id);
    expect(ruleIds).toContain('AUTH-001'); // Brute force
    expect(ruleIds).toContain('AUTH-002'); // Password spray
    expect(ruleIds).toContain('AUTH-003'); // Success after failure

    // Check AUTH-001 details
    const bfFinding = result.findings.find(f => f.rule_id === 'AUTH-001')!;
    expect(bfFinding.source_ips).toContain('198.51.100.23');
    expect(bfFinding.severity).toBe('high');
    expect(bfFinding.mitre_technique).toBe('T1110.001');

    // Check AUTH-003 (Success after failures for admin)
    const safFinding = result.findings.find(f => f.rule_id === 'AUTH-003')!;
    expect(safFinding.usernames).toContain('admin');
    expect(safFinding.severity).toBe('high');
    expect(safFinding.evidence_strength).toBe('Strong');
  });

  it('Detects Web Recon, Path Traversal, Sensitive Paths, and HTTP Failures on web_recon dataset', () => {
    const webSample = SAMPLE_DATASETS.find(s => s.id === 'web_recon')!;
    expect(webSample).toBeDefined();

    const result = analyzeLogsClient(webSample.content, 'Web Recon Test', webSample.format);
    expect(result.findings.length).toBeGreaterThanOrEqual(3);

    const ruleIds = result.findings.map(f => f.rule_id);
    expect(ruleIds).toContain('WEB-001'); // 404 scanning
    expect(ruleIds).toContain('WEB-002'); // Path traversal or sensitive path
    expect(ruleIds).toContain('WEB-003'); // 401/403 failure

    // Verify traversal detection flagged high severity
    const traversalFinding = result.findings.find(f => f.id.toLowerCase().includes('traversal'));
    expect(traversalFinding).toBeDefined();
    expect(traversalFinding?.severity).toBe('high');
    expect(traversalFinding?.title).toContain('Path traversal');
  });

  it('Detects System Error Bursts on mixed_application dataset', () => {
    const mixedSample = SAMPLE_DATASETS.find(s => s.id === 'mixed_application')!;
    expect(mixedSample).toBeDefined();

    const result = analyzeLogsClient(mixedSample.content, 'Mixed Test', mixedSample.format);
    const sysFinding = result.findings.find(f => f.rule_id === 'SYS-001');
    expect(sysFinding).toBeDefined();
    expect(sysFinding?.title).toContain('Error');
  });
});
