import type { Detection } from '../types';

export type Sev = 'HIGH' | 'MEDIUM' | 'LOW';

// Semantic scale: anything threat-related renders in its severity color,
// benign / informational data stays in muted slate-blue.
export const SEV_COLOR: Record<Sev, string> = {
  HIGH: '#d65353',
  MEDIUM: '#d99a4e',
  LOW: '#5a7fa3',
};
export const BENIGN = '#4a90d9';
export const BENIGN_MUTED = '#6b87a6';
export const CLEAR_GREEN = '#48bb78';

const RANK: Record<Sev, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

export const asSev = (s: string): Sev => {
  const u = s.toUpperCase();
  return u === 'HIGH' || u === 'MEDIUM' ? u : 'LOW';
};

export const sortDetections = (dets: Detection[]): Detection[] =>
  [...dets].sort((a, b) => RANK[asSev(b.severity)] - RANK[asSev(a.severity)]);

export const topSeverity = (dets: Detection[]): Sev | null =>
  dets.length === 0 ? null : asSev(sortDetections(dets)[0].severity);

// Backdoor / C2 ports (detected as suspicious_ports) and plaintext service ports.
const C2_PORTS = new Set([1337, 4444, 6667, 31337]);
const PLAINTEXT_PORTS = new Set([21, 23, 25, 80, 110, 143]);

export const portSeverity = (port: number): Sev | null =>
  C2_PORTS.has(port) ? 'HIGH' : PLAINTEXT_PORTS.has(port) ? 'MEDIUM' : null;

export const portColor = (port: number): string => {
  const sev = portSeverity(port);
  return sev ? SEV_COLOR[sev] : BENIGN;
};

const PORT_NAMES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  123: 'NTP', 143: 'IMAP', 443: 'HTTPS', 1337: 'backdoor', 4444: 'metasploit',
  6667: 'IRC C2', 31337: 'BackOrifice',
};
export const portLabel = (port: number): string =>
  PORT_NAMES[port] ? `${port} ${PORT_NAMES[port]}` : String(port);

// Hosts named by a threat detection -> the color their bars / probes should use.
export const threatHostColors = (dets: Detection[]): Map<string, string> => {
  const map = new Map<string, string>();
  for (const d of dets) {
    const color =
      d.id === 'port_scan' ? SEV_COLOR.HIGH : d.id === 'heavy_talkers' ? SEV_COLOR.MEDIUM : null;
    if (!color) continue;
    for (const row of d.evidence ?? []) {
      const ip = row.src_ip;
      if (typeof ip === 'string' && ip && !map.has(ip)) map.set(ip, color);
    }
  }
  return map;
};

export const formatBytes = (b: number): string => {
  if (b >= 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(1)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
};
