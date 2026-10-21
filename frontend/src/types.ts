export interface Metadata {
  parser_used: string;
  total_packets: number;
  total_bytes: number;
  unique_hosts: number;
  protocol_count: number;
  duration_seconds: number;
  alert_count: number;
  cap_hit: boolean;
  capture_name: string;
}

export interface Detection {
  id: string;
  title: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  summary: string;
  evidence: Record<string, any>[];
}

export interface ProtocolItem {
  protocol: string;
  count: number;
}

export interface TopTalkerItem {
  src_ip: string;
  bytes: number;
}

export interface TimelineItem {
  second: number;
  packets: number;
  bytes: number;
}

export interface PacketSizeItem {
  bucket: string;
  count: number;
}

export interface DstPortItem {
  port: number;
  count: number;
  insecure: boolean;
}

export interface PortScanPointItem {
  elapsed: number;
  dst_port: number;
  src_ip: string;
}

export interface HostFlowItem {
  src_ip: string;
  dst_ip: string;
  bytes: number;
}

export interface ConversationMatrix {
  sources: string[];
  destinations: string[];
  z: number[][];
}

export interface ChartsData {
  protocol_distribution: ProtocolItem[];
  top_talkers: TopTalkerItem[];
  traffic_timeline: TimelineItem[];
  packet_sizes: PacketSizeItem[];
  top_dst_ports: DstPortItem[];
  port_scan_points: PortScanPointItem[];
  host_flow: HostFlowItem[];
  conversation_matrix: ConversationMatrix;
}

export interface AnalysisResponse {
  meta: Metadata;
  detections: Detection[];
  charts: ChartsData;
}

export interface PacketRow {
  packet_no: number;
  timestamp: number;
  time_utc?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  app_protocol?: string;
  tcp_flags?: string;
  length: number;
}

export interface PaginatedPacketsResponse {
  total: number;
  limit: number;
  offset: number;
  packets: PacketRow[];
}

export interface HealthInfo {
  status: string;
  parser_used: string;
  packet_count: number;
  database_ready: boolean;
}

export interface ScenarioInfo {
  id: string;
  name: string;
  description: string;
  severity_tag: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'CLEAR';
  expected_alerts: number;
}

// Cross-filter state shared by the charts, threat cards and the packet explorer.
export interface AlertFilter {
  id: string;
  title: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface ExplorerFilter {
  protocol: string;
  host: string;
  port: string;
  search: string;
  pair: { src: string; dst: string } | null;
  alert: AlertFilter | null;
}

export const EMPTY_FILTER: ExplorerFilter = {
  protocol: '',
  host: '',
  port: '',
  search: '',
  pair: null,
  alert: null,
};
