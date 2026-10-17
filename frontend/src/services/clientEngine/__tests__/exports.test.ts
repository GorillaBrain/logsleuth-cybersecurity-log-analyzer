import { describe, it, expect } from 'vitest';
import { redactSecrets } from '../../exportUtils';

describe('Export Sanitization & Redaction', () => {
  it('redacts password and credential query params and key-value pairs', () => {
    const raw = 'Login request: username=admin&password=SuperSecretPassword123! from 192.0.2.1';
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain('SuperSecretPassword123!');
    expect(redacted).toContain('password=[REDACTED]');
  });

  it('redacts bearer and authorization tokens', () => {
    const raw = 'API request: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz123abc456';
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz123abc456');
    expect(redacted).toContain('Bearer [REDACTED]');
  });

  it('redacts api_key and token parameters', () => {
    const raw = 'URL requested: /api/v1/data?api_key=sk_live_1234567890abcdef&format=json';
    const redacted = redactSecrets(raw);
    expect(redacted).not.toContain('sk_live_1234567890abcdef');
    expect(redacted).toContain('api_key=[REDACTED]');
  });
});
