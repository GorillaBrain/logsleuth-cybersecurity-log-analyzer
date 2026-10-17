import type { ParsedEvent, IOC, IOCType } from '../../types';
import { isPrivateIP } from './ipUtils';

const IPV4_REGEX = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])/g;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|io|co|info|biz|dev|xyz|me|tv|cc|ru|cn|de|uk|fr|au|ca|jp|br|in|nl|se|no|fi|dk|ch|at|be|es|it|pt|pl|cz|sk|hu|ro|bg|hr|si|lt|lv|ee|ie|lu|onion)\b/gi;
const URL_REGEX = /https?:\/\/[^\s<>"]+/gi;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;

const IGNORED_DOMAINS = new Set([
  'localhost', 'example.com', 'example.org', 'example.net', 'schema.org', 'w3.org'
]);

export function extractIOCsClient(events: ParsedEvent[]): IOC[] {
  const iocMap = new Map<string, IOC>();

  const addIOC = (val: string, type: IOCType, event: ParsedEvent, isPrivate = false) => {
    const key = `${type}::${val.toLowerCase()}`;
    const ts = event.timestamp || null;

    if (iocMap.has(key)) {
      const existing = iocMap.get(key)!;
      existing.count += 1;
      if (!existing.event_ids.includes(event.id)) {
        existing.event_ids.push(event.id);
      }
      if (ts) {
        if (!existing.first_seen || new Date(ts).getTime() < new Date(existing.first_seen).getTime()) {
          existing.first_seen = ts;
        }
        if (!existing.last_seen || new Date(ts).getTime() > new Date(existing.last_seen).getTime()) {
          existing.last_seen = ts;
        }
      }
    } else {
      iocMap.set(key, {
        value: val,
        ioc_type: type,
        count: 1,
        first_seen: ts,
        last_seen: ts,
        event_ids: [event.id],
        context: `Observed at line ${event.line_number || 'unknown'} in event ${event.id.slice(0, 8)}`,
        is_private: isPrivate,
      });
    }
  };

  for (const event of events) {
    const text = event.raw_message;

    // IPv4
    const ips = text.match(IPV4_REGEX) || [];
    for (const ip of ips) {
      addIOC(ip, 'ipv4', event, isPrivateIP(ip));
    }

    // URLs
    const urls = text.match(URL_REGEX) || [];
    for (const url of urls) {
      addIOC(url, 'url', event);
    }

    // Domains
    const domains = text.match(DOMAIN_REGEX) || [];
    for (const domain of domains) {
      const lower = domain.toLowerCase();
      if (!IGNORED_DOMAINS.has(lower) && lower.length > 4) {
        addIOC(lower, 'domain', event);
      }
    }

    // Emails
    const emails = text.match(EMAIL_REGEX) || [];
    for (const email of emails) {
      addIOC(email.toLowerCase(), 'email', event);
    }

    // Hashes (longest first)
    const sha256List = text.match(SHA256_REGEX) || [];
    for (const hash of sha256List) {
      addIOC(hash.toLowerCase(), 'sha256', event);
    }

    const sha1List = text.match(SHA1_REGEX) || [];
    for (const hash of sha1List) {
      const lower = hash.toLowerCase();
      if (!sha256List.some(s => s.toLowerCase().includes(lower))) {
        addIOC(lower, 'sha1', event);
      }
    }

    const md5List = text.match(MD5_REGEX) || [];
    for (const hash of md5List) {
      const lower = hash.toLowerCase();
      if (!sha256List.some(s => s.toLowerCase().includes(lower)) && !sha1List.some(s => s.toLowerCase().includes(lower))) {
        addIOC(lower, 'md5', event);
      }
    }
  }

  const result = Array.from(iocMap.values());
  result.sort((a, b) => b.count - a.count);
  return result;
}
