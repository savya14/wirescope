import React, { useRef, useState } from 'react';
import type { ConversationMatrix } from '../types';
import { SEV_COLOR } from '../lib/severity';
import { FloatingTipLayer, type FloatingTip } from './ChartTooltip';

interface ConversationHeatmapProps {
  matrix: ConversationMatrix;
  threatColors: Map<string, string>;
  activePair: { src: string; dst: string } | null;
  onSelectPair: (src: string, dst: string) => void;
}

const hexToRgb = (hex: string): [number, number, number] => [
  parseInt(hex.slice(1, 3), 16),
  parseInt(hex.slice(3, 5), 16),
  parseInt(hex.slice(5, 7), 16),
];

const mix = (from: string, to: string, t: number): string => {
  const a = hexToRgb(from);
  const b = hexToRgb(to);
  const c = a.map((v, i) => Math.round(v + (b[i] - v) * t));
  return `rgb(${c[0]}, ${c[1]}, ${c[2]})`;
};

const BASE = '#1b2432';
const BENIGN_HI = '#4a90d9';

export const ConversationHeatmap: React.FC<ConversationHeatmapProps> = ({
  matrix,
  threatColors,
  activePair,
  onSelectPair,
}) => {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [tip, setTip] = useState<FloatingTip | null>(null);

  const maxZ = Math.max(1, ...matrix.z.flat());
  // Log scale so one chatty pair doesn't flatten every other cell to the same shade.
  const intensity = (c: number) => (c <= 0 ? 0 : Math.log(1 + c) / Math.log(1 + maxZ));
  const hasThreatRow = matrix.sources.some((s) => threatColors.has(s));

  return (
    <div ref={wrapRef} className="relative">
      <div className="overflow-x-auto">
        <table className="w-full text-[10.5px] font-mono border-separate" style={{ borderSpacing: 2 }}>
          <thead>
            <tr>
              <th className="sticky left-0 bg-[#1a1f29] z-10 text-left text-[#8b94a7] font-medium pr-2 align-bottom pb-1">
                Source ↓ / Destination →
              </th>
              {matrix.destinations.map((dst) => (
                <th key={dst} className="font-medium text-[#8b94a7] align-bottom pb-1 min-w-[34px]">
                  <span
                    className="inline-block whitespace-nowrap"
                    style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}
                  >
                    {dst}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.sources.map((src, i) => {
              const rowColor = threatColors.get(src);
              return (
                <tr key={src}>
                  <td
                    className="sticky left-0 bg-[#1a1f29] z-10 pr-2 whitespace-nowrap text-right"
                    style={{ color: rowColor ?? '#c4c9d4', fontWeight: rowColor ? 600 : 400 }}
                  >
                    {src}
                  </td>
                  {matrix.destinations.map((dst, j) => {
                    const count = matrix.z[i]?.[j] || 0;
                    const t = intensity(count);
                    const bg =
                      count === 0
                        ? '#12171f'
                        : mix(rowColor ? '#2b1c22' : BASE, rowColor ?? BENIGN_HI, 0.18 + 0.82 * t);
                    const isActive = activePair?.src === src && activePair?.dst === dst;
                    return (
                      <td
                        key={dst}
                        data-cell={`${src}>${dst}`}
                        onClick={count > 0 ? () => onSelectPair(src, dst) : undefined}
                        onMouseMove={(e) => {
                          const r = wrapRef.current?.getBoundingClientRect();
                          if (!r) return;
                          setTip({
                            title: `${src} → ${dst}`,
                            rows: [{ label: 'Packets', value: count.toLocaleString(), color: rowColor ?? BENIGN_HI }],
                            hint: count > 0 ? 'Click to filter this flow' : undefined,
                            x: e.clientX - r.left,
                            y: e.clientY - r.top,
                            w: r.width,
                          });
                        }}
                        onMouseLeave={() => setTip(null)}
                        className={`h-[26px] min-w-[34px] text-center rounded-sm transition-colors ${
                          count > 0 ? 'cursor-pointer hover:brightness-125' : ''
                        }`}
                        style={{
                          backgroundColor: bg,
                          outline: isActive ? '2px solid #ffffff' : undefined,
                          outlineOffset: -2,
                          color: count === 0 ? '#2f3a48' : t > 0.45 ? '#ffffff' : '#c4c9d4',
                        }}
                      >
                        {count > 0 ? count : ''}
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-[#8b94a7] mt-3 pt-3 border-t border-[#2a313d]">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: BENIGN_HI }} /> Normal host
          </span>
          {hasThreatRow && (
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: SEV_COLOR.HIGH }} /> Threat source
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <span>1</span>
          <span
            className="w-24 h-2.5 rounded-sm"
            style={{ background: `linear-gradient(to right, ${BASE}, ${BENIGN_HI})` }}
          />
          <span>{maxZ.toLocaleString()} pkts (log)</span>
        </div>
      </div>
      <FloatingTipLayer tip={tip} />
    </div>
  );
};
