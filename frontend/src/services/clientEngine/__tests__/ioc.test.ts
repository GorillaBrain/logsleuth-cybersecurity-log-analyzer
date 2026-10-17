import { describe, it, expect } from 'vitest';
import { extractIOCsClient } from '../iocExtractor';
import { isPrivateIP } from '../ipUtils';
import type { ParsedEvent } from '../../../types';

describe('IOC Extraction & Classification', () => {
  it('correctly classifies private vs public IPv4 addresses', () => {
    expect(isPrivateIP('127.0.0.1')).toBe(true);
    expect(isPrivateIP('10.0.10.5')).toBe(true);
    expect(isPrivateIP('172.20.5.1')).toBe(true);
    expect(isPrivateIP('192.168.1.100')).toBe(true);
    expect(isPrivateIP('169.254.1.1')).toBe(true);
    // Public / documentation IPs
    expect(isPrivateIP('198.51.100.23')).toBe(false);
    expect(isPrivateIP('8.8.8.8')).toBe(false);
    expect(isPrivateIP('203.0.113.1')).toBe(false);
  });

  it('extracts and deduplicates IPv4, domains, URLs, and hashes from events', () => {
    const dummyEvent: ParsedEvent = {
      id: 'test-1',
      timestamp: '2026-10-15T12:00:00Z',
      raw_message: 'Alert: Client 198.51.100.44 connected to https://malicious-c2.dev/payload.sh with hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and user admin@company.internal',
      event_category: 'security',
      severity: 'high',
      is_suspicious: true,
      detection_ids: ['TEST-001'],
      line_number: 1,
    };

    const iocs = extractIOCsClient([dummyEvent]);
    const values = iocs.map(i => i.value);

    expect(values).toContain('198.51.100.44');
    expect(values).toContain('https://malicious-c2.dev/payload.sh');
    expect(values).toContain('malicious-c2.dev');
    expect(values).toContain('admin@company.internal');
    expect(values).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

    const sha256Ioc = iocs.find(i => i.ioc_type === 'sha256')!;
    expect(sha256Ioc).toBeDefined();
    expect(sha256Ioc.count).toBe(1);

    const ipIoc = iocs.find(i => i.value === '198.51.100.44')!;
    expect(ipIoc.is_private).toBe(false);
  });
});
