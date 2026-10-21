// A random per-browser id so the backend can keep each visitor's capture isolated.
let cached: string | null = null;

const newId = (): string =>
  (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`).replace(/[^A-Za-z0-9_-]/g, '');

export function getSessionId(): string {
  if (cached) return cached;
  try {
    const stored = localStorage.getItem('pcap-session-id');
    if (stored) return (cached = stored);
    const id = newId();
    localStorage.setItem('pcap-session-id', id);
    return (cached = id);
  } catch {
    return (cached = newId()); // storage blocked: fall back to a per-tab id
  }
}
