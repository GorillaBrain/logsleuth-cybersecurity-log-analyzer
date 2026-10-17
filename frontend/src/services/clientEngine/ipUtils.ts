// IP address utilities for IPv4 validation and private IP classification

const IPV4_REGEX = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])/g;

export function extractIPv4(text: string): string[] {
  if (!text) return [];
  const matches = text.match(IPV4_REGEX);
  return matches ? Array.from(new Set(matches)) : [];
}

export function isPrivateIP(ip: string): boolean {
  if (!ip) return false;
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return false;

  const [a, b] = parts;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 10.0.0.0/8 (RFC 1918)
  if (a === 10) return true;
  // 172.16.0.0/12 (RFC 1918)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (RFC 1918)
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (Link Local)
  if (a === 169 && b === 254) return true;
  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;
  // 224.0.0.0/4 (Multicast)
  if (a >= 224) return true;

  return false;
}
