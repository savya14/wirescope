import React, { useMemo, useRef, useState } from 'react';
import type { HostFlowItem } from '../types';
import { BENIGN, formatBytes } from '../lib/severity';
import { FloatingTipLayer, type FloatingTip } from './ChartTooltip';

interface FlowSankeyProps {
  flows: HostFlowItem[];
  threatColors: Map<string, string>;
  activePair: { src: string; dst: string } | null;
  activeHost: string;
  onSelectPair: (src: string, dst: string) => void;
  onSelectHost: (ip: string) => void;
}

interface NodeBox {
  ip: string;
  total: number;
  y: number;
  h: number;
  cursor: number;
}

const W = 1000;
const PAD_X = 190;
const NODE_W = 12;
const GAP = 9;
const PAD_Y = 8;
const MIN_LINK = 2.5;

// Bipartite Sankey: sources on the left, destinations on the right. Hosts appear on
// both sides as separate nodes, so mutual conversations never form a cycle.
export const FlowSankey: React.FC<FlowSankeyProps> = ({
  flows,
  threatColors,
  activePair,
  activeHost,
  onSelectPair,
  onSelectHost,
}) => {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [tip, setTip] = useState<FloatingTip | null>(null);

  const layout = useMemo(() => {
    const maxTotal = (side: 'src_ip' | 'dst_ip') => {
      const m = new Map<string, number>();
      for (const f of flows) m.set(f[side], (m.get(f[side]) ?? 0) + f.bytes);
      return m;
    };
    const srcTotals = maxTotal('src_ip');
    const dstTotals = maxTotal('dst_ip');
    // Ribbon width uses a square-root scale so one dominant flow can't flatten the rest.
    const w = (b: number) => Math.sqrt(b);
    // Both columns carry the same flows, so they share one weighted total.
    const biggestCol = Math.max(flows.reduce((s, f) => s + w(f.bytes), 0), 1);
    const rows = Math.max(srcTotals.size, dstTotals.size);
    const targetH = Math.max(300, rows * 26);
    const scale = (targetH - GAP * (rows - 1)) / biggestCol;
    const linkH = (b: number) => Math.max(MIN_LINK, w(b) * scale);

    const build = (totals: Map<string, number>, side: 'src_ip' | 'dst_ip') => {
      const sorted = [...totals.entries()].sort((a, b) => b[1] - a[1]);
      let y = PAD_Y;
      const nodes = new Map<string, NodeBox>();
      for (const [ip, total] of sorted) {
        const h = Math.max(
          8,
          flows.filter((f) => f[side] === ip).reduce((s, f) => s + linkH(f.bytes), 0)
        );
        nodes.set(ip, { ip, total, y, h, cursor: 0 });
        y += h + GAP;
      }
      return { nodes, bottom: y - GAP + PAD_Y };
    };
    const left = build(srcTotals, 'src_ip');
    const right = build(dstTotals, 'dst_ip');
    const height = Math.max(left.bottom, right.bottom);

    // Order links so ribbons leaving/entering the same node don't needlessly cross.
    const links = [...flows]
      .sort((a, b) => {
        const ay = right.nodes.get(a.dst_ip)!.y;
        const by = right.nodes.get(b.dst_ip)!.y;
        return ay - by || b.bytes - a.bytes;
      })
      .map((f) => {
        const h = linkH(f.bytes);
        const s = left.nodes.get(f.src_ip)!;
        const sy = s.y + s.cursor + h / 2;
        s.cursor += h;
        return { f, h, sy };
      })
      .sort((a, b) => {
        const ay = left.nodes.get(a.f.src_ip)!.y;
        const by = left.nodes.get(b.f.src_ip)!.y;
        return ay - by || a.sy - b.sy;
      })
      .map((l) => {
        const d = right.nodes.get(l.f.dst_ip)!;
        const dy = d.y + d.cursor + l.h / 2;
        d.cursor += l.h;
        return { ...l, dy };
      });

    return { left: left.nodes, right: right.nodes, height, links };
  }, [flows]);

  const moveTip = (e: React.MouseEvent, content: Omit<FloatingTip, 'x' | 'y' | 'w'>) => {
    const r = wrapRef.current?.getBoundingClientRect();
    if (!r) return;
    setTip({ ...content, x: e.clientX - r.left, y: e.clientY - r.top, w: r.width });
  };

  const xL = PAD_X;
  const xR = W - PAD_X - NODE_W;
  const linkKey = (src: string, dst: string) => `${src}>${dst}`;

  return (
    <div ref={wrapRef} className="relative overflow-x-auto">
      <svg
        viewBox={`0 0 ${W} ${layout.height}`}
        className="w-full min-w-[720px]"
        style={{ height: 'auto', aspectRatio: `${W} / ${layout.height}`, maxHeight: 520 }}
        role="img"
        aria-label="Host communication flow diagram"
      >
        <g>
          {layout.links.map(({ f, h, sy, dy }) => {
            const color = threatColors.get(f.src_ip) ?? BENIGN;
            const key = linkKey(f.src_ip, f.dst_ip);
            const isActive = activePair?.src === f.src_ip && activePair?.dst === f.dst_ip;
            const dim = (hover !== null && hover !== key) || (activePair !== null && !isActive);
            const x0 = xL + NODE_W;
            const mx = (x0 + xR) / 2;
            return (
              <path
                key={key}
                data-flow={key}
                d={`M${x0},${sy} C${mx},${sy} ${mx},${dy} ${xR},${dy}`}
                fill="none"
                stroke={color}
                strokeWidth={h}
                strokeOpacity={isActive || hover === key ? 0.85 : dim ? 0.1 : 0.38}
                className="cursor-pointer transition-[stroke-opacity] duration-150"
                onMouseEnter={() => setHover(key)}
                onMouseMove={(e) =>
                  moveTip(e, {
                    title: `${f.src_ip} → ${f.dst_ip}`,
                    rows: [{ label: 'Volume', value: formatBytes(f.bytes), color }],
                    hint: 'Click to filter this flow',
                  })
                }
                onMouseLeave={() => {
                  setHover(null);
                  setTip(null);
                }}
                onClick={() => onSelectPair(f.src_ip, f.dst_ip)}
              />
            );
          })}
        </g>

        {[...layout.left.values()].map((n) => {
          const color = threatColors.get(n.ip) ?? BENIGN;
          return (
            <g
              key={`L${n.ip}`}
              className="cursor-pointer"
              data-node={`src:${n.ip}`}
              onClick={() => onSelectHost(n.ip)}
              onMouseMove={(e) =>
                moveTip(e, {
                  title: n.ip,
                  rows: [{ label: 'Sent (top flows)', value: formatBytes(n.total), color }],
                  hint: 'Click to filter host',
                })
              }
              onMouseLeave={() => setTip(null)}
            >
              <rect x={xL} y={n.y} width={NODE_W} height={n.h} rx={2} fill={color} opacity={activeHost && activeHost !== n.ip ? 0.4 : 1} />
              <text x={xL - 8} y={n.y + n.h / 2} textAnchor="end" dominantBaseline="middle" className="font-mono" fontSize={11.5} fill={activeHost === n.ip ? '#ffffff' : '#c4c9d4'}>
                {n.ip}
              </text>
            </g>
          );
        })}

        {[...layout.right.values()].map((n) => {
          const color = threatColors.get(n.ip) ?? BENIGN;
          return (
            <g
              key={`R${n.ip}`}
              className="cursor-pointer"
              data-node={`dst:${n.ip}`}
              onClick={() => onSelectHost(n.ip)}
              onMouseMove={(e) =>
                moveTip(e, {
                  title: n.ip,
                  rows: [{ label: 'Received (top flows)', value: formatBytes(n.total), color }],
                  hint: 'Click to filter host',
                })
              }
              onMouseLeave={() => setTip(null)}
            >
              <rect x={xR} y={n.y} width={NODE_W} height={n.h} rx={2} fill={color} opacity={activeHost && activeHost !== n.ip ? 0.4 : 1} />
              <text x={xR + NODE_W + 8} y={n.y + n.h / 2} dominantBaseline="middle" className="font-mono" fontSize={11.5} fill={activeHost === n.ip ? '#ffffff' : '#c4c9d4'}>
                {n.ip}
              </text>
            </g>
          );
        })}
      </svg>
      <FloatingTipLayer tip={tip} />
    </div>
  );
};
