import React, { useState } from 'react';
import { ArrowRight, Check } from 'lucide-react';
import type { AlertFilter, Detection } from '../types';
import { CLEAR_GREEN, SEV_COLOR, asSev, sortDetections } from '../lib/severity';

interface ThreatSignalsProps {
  detections: Detection[];
  activeAlertId: string | null;
  onInvestigate: (alert: AlertFilter) => void;
}

export const ThreatSignals: React.FC<ThreatSignalsProps> = ({ detections, activeAlertId, onInvestigate }) => {
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});
  const sorted = sortDetections(detections);

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const counts = (['HIGH', 'MEDIUM', 'LOW'] as const)
    .map((sev) => ({ sev, n: detections.filter((d) => asSev(d.severity) === sev).length }))
    .filter((c) => c.n > 0);

  return (
    <section id="threat-signals-section" className="mb-10">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-[16px] font-semibold text-[#e6e9ef] tracking-tight m-0">
          Threat Detection Signals
        </h2>
        <div className="flex items-center gap-3 text-[12px] font-mono">
          {counts.map((c) => (
            <span key={c.sev} style={{ color: SEV_COLOR[c.sev] }}>
              {c.n} {c.sev}
            </span>
          ))}
          <span className="text-[#8b94a7]">
            {detections.length} {detections.length === 1 ? 'Rule Triggered' : 'Rules Triggered'}
          </span>
        </div>
      </div>
      <div className="h-px bg-[#2a313d] mb-4" />

      {detections.length === 0 ? (
        <div
          id="threat-clear-state"
          className="border rounded p-5 flex items-start gap-4"
          style={{
            backgroundColor: `${CLEAR_GREEN}12`,
            borderColor: `${CLEAR_GREEN}66`,
            boxShadow: `inset 3px 0 0 ${CLEAR_GREEN}`,
          }}
        >
          <span
            className="w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5"
            style={{ backgroundColor: `${CLEAR_GREEN}26`, color: CLEAR_GREEN }}
          >
            <Check size={16} strokeWidth={2.5} />
          </span>
          <div>
            <div className="flex items-center gap-3 mb-1.5">
              <span className="text-[15px] font-semibold text-[#e6e9ef]">
                Baseline Normal — No Threat Signals Identified
              </span>
              <span
                className="text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded"
                style={{ backgroundColor: `${CLEAR_GREEN}26`, color: CLEAR_GREEN }}
              >
                CLEAR
              </span>
            </div>
            <p className="text-[13.5px] text-[#8b94a7] m-0 leading-relaxed">
              All heuristic modules evaluated cleanly. No reconnaissance port scans, plaintext credentials,
              suspicious backdoor channels, traffic volume anomalies, or ICMP sweep patterns were observed.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {sorted.map((d) => {
            const sev = asSev(d.severity);
            const color = SEV_COLOR[sev];
            const isHigh = sev === 'HIGH';
            const isExpanded = !!expandedIds[d.id];
            const evidenceCount = d.evidence?.length || 0;
            const evidenceKeys = evidenceCount > 0 ? Object.keys(d.evidence[0]) : [];
            const isActive = activeAlertId === d.id;

            return (
              <div
                key={d.id}
                data-testid={`threat-card-${d.id}`}
                data-severity={sev}
                role="button"
                tabIndex={0}
                aria-pressed={isActive}
                onClick={() => onInvestigate({ id: d.id, title: d.title, severity: sev })}
                onKeyDown={(e) => {
                  if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    onInvestigate({ id: d.id, title: d.title, severity: sev });
                  }
                }}
                className={`rounded cursor-pointer border transition-colors ${
                  isHigh ? 'p-5' : 'p-4'
                }`}
                style={{
                  backgroundColor: isHigh ? `${color}1f` : sev === 'MEDIUM' ? `${color}0f` : '#1a1f29',
                  borderColor: isActive ? color : isHigh ? `${color}99` : sev === 'MEDIUM' ? `${color}55` : '#2a313d',
                  boxShadow: `inset ${isHigh ? 5 : 3}px 0 0 ${color}`,
                }}
              >
                <div className="flex items-center justify-between gap-4 mb-2">
                  <div className="flex items-center gap-3 min-w-0">
                    <span
                      className="text-[10px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded text-white shrink-0"
                      style={{ backgroundColor: color }}
                    >
                      {sev}
                    </span>
                    <h3
                      className={`font-semibold text-[#e6e9ef] m-0 truncate ${isHigh ? 'text-[17px]' : 'text-[15px]'}`}
                    >
                      {d.title}
                    </h3>
                  </div>
                  <button
                    type="button"
                    data-testid="investigate-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      onInvestigate({ id: d.id, title: d.title, severity: sev });
                    }}
                    className="shrink-0 flex items-center gap-1.5 text-[12px] font-medium px-3 py-1.5 rounded border cursor-pointer transition-colors hover:brightness-125"
                    style={{
                      color: isHigh ? '#fff' : color,
                      backgroundColor: isHigh ? color : 'transparent',
                      borderColor: color,
                    }}
                  >
                    Investigate
                    <ArrowRight size={13} />
                  </button>
                </div>

                <p className={`leading-relaxed mb-3 m-0 ${isHigh ? 'text-[14px] text-[#c4c9d4]' : 'text-[13.5px] text-[#8b94a7]'}`}>
                  {d.summary}
                </p>

                {evidenceCount > 0 && (
                  <div onClick={(e) => e.stopPropagation()} className="cursor-default">
                    <button
                      type="button"
                      data-testid="inspect-evidence-btn"
                      onClick={() => toggleExpand(d.id)}
                      className="text-[12px] text-[#4a90d9] hover:underline font-mono cursor-pointer flex items-center gap-1.5"
                    >
                      <span>{isExpanded ? '[-] Hide Evidence' : `[+] Inspect Evidence (${evidenceCount} rows)`}</span>
                    </button>

                    {isExpanded && (
                      <div className="mt-3.5 border border-[#2a313d] rounded overflow-hidden max-h-72 overflow-y-auto">
                        <table className="w-full text-left text-[11.5px] font-mono border-collapse">
                          <thead className="bg-[#0f1419] text-[#8b94a7] sticky top-0 border-b border-[#2a313d]">
                            <tr>
                              {evidenceKeys.map((k) => (
                                <th key={k} className="py-2 px-3 font-medium uppercase text-[10.5px]">
                                  {k.replace(/_/g, ' ')}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[#2a313d] bg-[#1a1f29] text-[#e6e9ef]">
                            {d.evidence.map((row, rIdx) => (
                              <tr key={rIdx} className="hover:bg-[#232a35] transition-colors">
                                {evidenceKeys.map((k) => (
                                  <td key={k} className="py-1.5 px-3 whitespace-nowrap text-[#c4c9d4]">
                                    {row[k] !== null && row[k] !== undefined ? String(row[k]) : '—'}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
};
