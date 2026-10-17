// Timestamp parsing utilities supporting ISO 8601, Syslog, Apache CLF, and Unix epoch

const MONTH_MAP: Record<string, number> = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
};

export function parseTimestamp(text: string): string | null {
  if (!text) return null;

  // 1. ISO 8601: 2026-10-15T09:00:02 or 2026-10-15 09:00:02
  const isoMatch = text.match(/\b(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|[+-]\d{2}:?\d{2})?\b/);
  if (isoMatch) {
    const d = new Date(isoMatch[0].replace(' ', 'T'));
    if (!isNaN(d.getTime())) return d.toISOString();
  }

  // 2. Syslog format: Oct 15 09:00:02 or Oct  5 09:00:02
  const syslogMatch = text.match(/\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b/);
  if (syslogMatch) {
    const month = MONTH_MAP[syslogMatch[1].toLowerCase()];
    if (month !== undefined) {
      const day = parseInt(syslogMatch[2], 10);
      const hour = parseInt(syslogMatch[3], 10);
      const min = parseInt(syslogMatch[4], 10);
      const sec = parseInt(syslogMatch[5], 10);
      const year = new Date().getFullYear();
      const d = new Date(Date.UTC(year, month, day, hour, min, sec));
      if (!isNaN(d.getTime())) return d.toISOString();
    }
  }

  // 3. Apache/Nginx CLF format: 15/Oct/2026:09:00:02 +0000
  const clfMatch = text.match(/\b(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\b/);
  if (clfMatch) {
    const day = parseInt(clfMatch[1], 10);
    const month = MONTH_MAP[clfMatch[2].toLowerCase()];
    const year = parseInt(clfMatch[3], 10);
    const hour = parseInt(clfMatch[4], 10);
    const min = parseInt(clfMatch[5], 10);
    const sec = parseInt(clfMatch[6], 10);
    if (month !== undefined) {
      const d = new Date(Date.UTC(year, month, day, hour, min, sec));
      if (!isNaN(d.getTime())) return d.toISOString();
    }
  }

  // 4. Unix Epoch (seconds or ms)
  const epochMatch = text.match(/(?<![\d.])1[6-9]\d{8}(?:\d{3})?(?![\d.])/);
  if (epochMatch) {
    let epoch = parseInt(epochMatch[0], 10);
    if (epoch < 1e11) epoch *= 1000;
    const d = new Date(epoch);
    if (!isNaN(d.getTime())) return d.toISOString();
  }

  // 5. YYYY/MM/DD or MM/DD/YYYY HH:MM:SS
  const dateSlashMatch = text.match(/\b(\d{1,4})\/(\d{1,2})\/(\d{1,4})\s+(\d{2}):(\d{2}):(\d{2})\b/);
  if (dateSlashMatch) {
    const d = new Date(dateSlashMatch[0]);
    if (!isNaN(d.getTime())) return d.toISOString();
  }

  return null;
}
