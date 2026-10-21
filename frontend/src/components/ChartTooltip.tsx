import React from 'react';

export interface TipRow {
  label: string;
  value: string;
  color?: string;
}

export interface TipContent {
  title?: string;
  rows: TipRow[];
  hint?: string;
}

// One tooltip look for every chart (recharts and hand-built SVG alike).
export const TipBox: React.FC<TipContent> = ({ title, rows, hint }) => (
  <div className="bg-[#1a1f29] border border-[#2a313d] rounded px-2.5 py-2 text-[11px] font-mono shadow-lg pointer-events-none min-w-[140px]">
    {title && <div className="text-[#e6e9ef] font-semibold mb-1">{title}</div>}
    {rows.map((r, i) => (
      <div key={i} className="flex items-center gap-2 text-[#e6e9ef]">
        <span className="w-2 h-2 rounded-sm shrink-0" style={{ backgroundColor: r.color ?? '#4a90d9' }} />
        <span className="text-[#8b94a7]">{r.label}</span>
        <span className="font-semibold ml-auto pl-3">{r.value}</span>
      </div>
    ))}
    {hint && <div className="text-[#6c7689] mt-1.5 pt-1.5 border-t border-[#2a313d]">{hint}</div>}
  </div>
);

interface ChartTooltipProps {
  active?: boolean;
  payload?: any[];
  build: (datum: any) => TipContent;
}

// Recharts <Tooltip content={<ChartTooltip build={...} />} />
export const ChartTooltip: React.FC<ChartTooltipProps> = ({ active, payload, build }) => {
  if (!active || !payload || payload.length === 0) return null;
  return <TipBox {...build(payload[0].payload)} />;
};

export interface FloatingTip extends TipContent {
  x: number;
  y: number;
  w: number; // container width, for edge flipping
}

// Positions a TipBox inside a `relative` container, flipping near the right edge.
export const FloatingTipLayer: React.FC<{ tip: FloatingTip | null }> = ({ tip }) => {
  if (!tip) return null;
  const flip = tip.x > tip.w - 240;
  return (
    <div
      className="absolute z-20 pointer-events-none"
      style={{ left: flip ? tip.x - 14 : tip.x + 14, top: tip.y + 14, transform: flip ? 'translateX(-100%)' : undefined }}
    >
      <TipBox {...tip} />
    </div>
  );
};
