import React from 'react';
import type { Metadata } from '../types';
import { CLEAR_GREEN, SEV_COLOR, formatBytes, type Sev } from '../lib/severity';

interface KpiRowProps {
  meta: Metadata;
  topSeverity: Sev | null;
}

export const KpiRow: React.FC<KpiRowProps> = ({ meta, topSeverity }) => {
  const alertColor = topSeverity ? SEV_COLOR[topSeverity] : CLEAR_GREEN;

  const cards = [
    {
      label: 'TOTAL PACKETS',
      value: meta.total_packets.toLocaleString(),
      subtext: meta.cap_hit ? 'Capped at 20,000' : 'Frames Indexed',
      color: '#4a90d9',
    },
    {
      label: 'DATA VOLUME',
      value: formatBytes(meta.total_bytes),
      subtext: `${meta.total_bytes.toLocaleString()} raw bytes`,
      color: '#e6e9ef',
    },
    {
      label: 'UNIQUE HOSTS',
      value: meta.unique_hosts.toString(),
      subtext: 'Active Endpoints',
      color: '#e6e9ef',
    },
    {
      label: 'PROTOCOLS',
      value: meta.protocol_count.toString(),
      subtext: 'Network & Transport',
      color: '#e6e9ef',
    },
    {
      label: 'CAPTURE DURATION',
      value: `${meta.duration_seconds.toFixed(1)}s`,
      subtext: 'Elapsed Time Window',
      color: '#e6e9ef',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-7">
      {cards.map((card) => (
        <div
          key={card.label}
          className="bg-[#1a1f29] border border-[#2a313d] rounded p-4 flex flex-col justify-between"
        >
          <div className="text-[11px] font-medium tracking-[0.08em] text-[#8b94a7] uppercase mb-2">
            {card.label}
          </div>
          <div
            className="text-[24px] font-semibold font-mono tracking-tight leading-none mb-1.5"
            style={{ color: card.color }}
          >
            {card.value}
          </div>
          <div className="text-[11.5px] text-[#8b94a7]">{card.subtext}</div>
        </div>
      ))}

      <div
        id="kpi-threat-alerts"
        data-severity={topSeverity ?? 'CLEAR'}
        className="rounded p-4 flex flex-col justify-between border"
        style={{
          backgroundColor: `${alertColor}1f`,
          borderColor: `${alertColor}99`,
          boxShadow: `inset 3px 0 0 ${alertColor}`,
        }}
      >
        <div className="text-[11px] font-semibold tracking-[0.08em] uppercase mb-2" style={{ color: alertColor }}>
          THREAT ALERTS
        </div>
        <div
          className="text-[24px] font-semibold font-mono tracking-tight leading-none mb-1.5"
          style={{ color: alertColor }}
        >
          {meta.alert_count}
        </div>
        <div className="text-[11.5px] text-[#c4c9d4]">
          {topSeverity ? `Highest severity: ${topSeverity}` : 'No anomalies detected'}
        </div>
      </div>
    </div>
  );
};
