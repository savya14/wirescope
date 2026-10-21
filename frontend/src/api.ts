import type { AnalysisResponse, HealthInfo, PaginatedPacketsResponse, ScenarioInfo } from './types';
import { getSessionId } from './lib/session';

// Dev server talks to the backend on :8000; a production build is served by the
// backend itself, so relative URLs work. VITE_API_BASE overrides both.
const API_BASE: string =
  import.meta.env.VITE_API_BASE ?? (import.meta.env.DEV ? 'http://localhost:8000' : '');

const apiFetch = (url: string, init: RequestInit = {}): Promise<Response> =>
  fetch(url, { ...init, headers: { ...(init.headers ?? {}), 'X-Session-Id': getSessionId() } });

export async function fetchHealth(): Promise<HealthInfo> {
  const res = await apiFetch(`${API_BASE}/api/health`);
  if (!res.ok) {
    throw new Error(`Health check failed: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function fetchSampleAnalysis(): Promise<AnalysisResponse> {
  const res = await apiFetch(`${API_BASE}/api/sample`);
  if (!res.ok) {
    const errText = await res.text();
    throw new Error(errText || `Failed to analyze sample capture: ${res.status}`);
  }
  return res.json();
}

export async function fetchScenarios(): Promise<ScenarioInfo[]> {
  const res = await apiFetch(`${API_BASE}/api/scenarios`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scenarios: ${res.status}`);
  }
  return res.json();
}

export async function fetchScenarioAnalysis(scenarioId: string): Promise<AnalysisResponse> {
  const res = await apiFetch(`${API_BASE}/api/scenario/${scenarioId}`);
  if (!res.ok) {
    const errJson = await res.json().catch(() => null);
    const msg = errJson?.detail || `Scenario analysis failed: ${res.status}`;
    throw new Error(msg);
  }
  return res.json();
}

export async function uploadAndAnalyzeCapture(file?: File): Promise<AnalysisResponse> {
  const formData = new FormData();
  if (file) {
    formData.append('file', file);
  }

  const res = await apiFetch(`${API_BASE}/api/analyze`, {
    method: 'POST',
    body: file ? formData : undefined,
  });

  if (!res.ok) {
    const errJson = await res.json().catch(() => null);
    const msg = errJson?.detail || `Analysis failed: ${res.status} ${res.statusText}`;
    throw new Error(msg);
  }

  return res.json();
}

export async function fetchPackets(params: {
  protocol?: string;
  search?: string;
  port?: number;
  host?: string;
  src?: string;
  dst?: string;
  alert?: string;
  limit?: number;
  offset?: number;
}): Promise<PaginatedPacketsResponse> {
  const url = new URL(`${API_BASE}/api/packets`, window.location.origin);
  if (params.protocol) url.searchParams.set('protocol', params.protocol);
  if (params.search) url.searchParams.set('search', params.search);
  if (params.port && params.port > 0) url.searchParams.set('port', params.port.toString());
  if (params.host) url.searchParams.set('host', params.host);
  if (params.src) url.searchParams.set('src', params.src);
  if (params.dst) url.searchParams.set('dst', params.dst);
  if (params.alert) url.searchParams.set('alert', params.alert);
  if (params.limit) url.searchParams.set('limit', params.limit.toString());
  if (params.offset !== undefined) url.searchParams.set('offset', params.offset.toString());

  const res = await apiFetch(url.toString());
  if (!res.ok) {
    throw new Error(`Failed to fetch packets: ${res.status}`);
  }
  return res.json();
}

export function getDownloadUrl(artifact: string): string {
  return `${API_BASE}/api/download/${artifact}?sid=${encodeURIComponent(getSessionId())}`;
}

