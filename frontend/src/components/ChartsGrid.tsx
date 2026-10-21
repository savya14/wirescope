import React from 'react';
import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  LabelList,
  Line,
  Pie,
  PieChart,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { ChartsData, Detection, ExplorerFilter } from '../types';
import {
  BENIGN,
  BENIGN_MUTED,
  CLEAR_GREEN,
  SEV_COLOR,
  formatBytes,
  portColor,
  portLabel,
  threatHostColors,
} from '../lib/severity';
import { useReducedMotion } from '../lib/useReducedMotion';
import { ChartTooltip } from './ChartTooltip';
import { FlowSankey } from './FlowSankey';
import { ConversationHeatmap } from './ConversationHeatmap';

interface ChartsGridProps {
  charts: ChartsData;
  detections: Detection[];
  filter: ExplorerFilter;
  onFilter: (patch: Partial<ExplorerFilter>) => void;
}

// Protocols are informational, not threats: slate-blue / grey shades only.
const PROTOCOL_PALETTE = ['#4a90d9', '#7aa6d6', '#5a7fa3', '#9aa9bb', '#3f5f86', '#6c7689', '#a9b8c9', '#4b5768'];

const AXIS_TICK = { fill: '#8b94a7', fontSize: 10, fontFamily: 'IBM Plex Mono' };
const CURSOR = { fill: 'rgba(74, 144, 217, 0.08)' };

const Card: React.FC<{
  id: string;
  title: string;
  right?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}> = ({ id, title, right, className = '', children }) => (
  <div id={id} className={`bg-[#1a1f29] border border-[#2a313d] rounded p-5 flex flex-col ${className}`}>
    <div className="flex items-center justify-between gap-3 mb-3">
      <h3 className="text-[14px] font-semibold text-[#e6e9ef] m-0">{title}</h3>
      {right && <div className="text-[11px] font-mono text-[#8b94a7] flex items-center gap-3">{right}</div>}
    </div>
    {children}
  </div>
);

const Swatch: React.FC<{ color: string; label: string }> = ({ color, label }) => (
  <span className="flex items-center gap-1.5">
    <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: color }} />
    {label}
  </span>
);

export const ChartsGrid: React.FC<ChartsGridProps> = ({ charts, detections, filter, onFilter }) => {
  const reduceMotion = useReducedMotion();
  const anim = { isAnimationActive: !reduceMotion, animationDuration: 380 };

  const threatColors = threatHostColors(detections);
  const hasScan = charts.port_scan_points.length > 0;

  const totalPackets = charts.protocol_distribution.reduce((s, p) => s + p.count, 0);
  const talkers = charts.top_talkers;
  const ports = charts.top_dst_ports.map((p) => ({ ...p, label: portLabel(p.port), color: portColor(p.port) }));
  const pairOrHost = filter.host;
  const pairActive = filter.pair;

  const talkerLegend: [string, string][] = [];
  if (talkers.some((t) => threatColors.get(t.src_ip) === SEV_COLOR.HIGH)) talkerLegend.push([SEV_COLOR.HIGH, 'Port-scan source']);
  if (talkers.some((t) => threatColors.get(t.src_ip) === SEV_COLOR.MEDIUM)) talkerLegend.push([SEV_COLOR.MEDIUM, 'Heavy talker']);
  talkerLegend.push([BENIGN, 'Normal']);

  const portLegend: [string, string][] = [];
  if (ports.some((p) => p.color === SEV_COLOR.HIGH)) portLegend.push([SEV_COLOR.HIGH, 'C2 / backdoor']);
  if (ports.some((p) => p.color === SEV_COLOR.MEDIUM)) portLegend.push([SEV_COLOR.MEDIUM, 'Plaintext']);
  portLegend.push([BENIGN, 'Standard']);

  const viewCount = hasScan ? 8 : 7;

  const donut = (
    <Card
      key="donut"
      id="chart-protocol-donut"
      title="Protocol Distribution"
      right={<span>Click a slice to filter</span>}
    >
      <div className="flex flex-col sm:flex-row items-center gap-4 flex-1">
        <div className="relative w-full sm:w-[58%] h-[290px]">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={charts.protocol_distribution}
                dataKey="count"
                nameKey="protocol"
                cx="50%"
                cy="50%"
                innerRadius="62%"
                outerRadius="92%"
                paddingAngle={1.5}
                stroke="#1a1f29"
                strokeWidth={2}
                cursor="pointer"
                {...anim}
                onClick={(_: any, i: number) => onFilter({ protocol: charts.protocol_distribution[i].protocol })}
              >
                {charts.protocol_distribution.map((p, i) => (
                  <Cell
                    key={p.protocol}
                    fill={PROTOCOL_PALETTE[i % PROTOCOL_PALETTE.length]}
                    fillOpacity={filter.protocol && filter.protocol.toUpperCase() !== p.protocol.toUpperCase() ? 0.3 : 1}
                  />
                ))}
              </Pie>
              <Tooltip
                content={
                  <ChartTooltip
                    build={(d) => ({
                      title: d.protocol,
                      rows: [
                        { label: 'Packets', value: Number(d.count).toLocaleString(), color: BENIGN },
                        { label: 'Share', value: `${((d.count / totalPackets) * 100).toFixed(1)}%` },
                      ],
                      hint: 'Click to filter packets',
                    })}
                  />
                }
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-[26px] font-semibold font-mono text-[#e6e9ef] leading-none">
              {totalPackets.toLocaleString()}
            </span>
            <span className="text-[10.5px] tracking-[0.08em] uppercase text-[#8b94a7] mt-1.5">packets</span>
            <span className="text-[10.5px] font-mono text-[#6c7689] mt-0.5">
              {charts.protocol_distribution.length} protocols
            </span>
          </div>
        </div>

        <ul className="w-full sm:flex-1 list-none p-0 m-0 space-y-1">
          {charts.protocol_distribution.map((p, i) => {
            const active = filter.protocol.toUpperCase() === p.protocol.toUpperCase();
            return (
              <li key={p.protocol}>
                <button
                  type="button"
                  data-protocol={p.protocol}
                  onClick={() => onFilter({ protocol: p.protocol })}
                  className={`w-full flex items-center gap-2.5 px-2 py-1.5 rounded text-[12px] cursor-pointer transition-colors ${
                    active ? 'bg-[#232a35]' : 'hover:bg-[#232a35]'
                  }`}
                >
                  <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: PROTOCOL_PALETTE[i % PROTOCOL_PALETTE.length] }} />
                  <span className="text-[#e6e9ef] font-medium">{p.protocol}</span>
                  <span className="ml-auto font-mono text-[#c4c9d4]">{p.count.toLocaleString()}</span>
                  <span className="font-mono text-[#8b94a7] w-[44px] text-right">
                    {((p.count / totalPackets) * 100).toFixed(1)}%
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </Card>
  );

  const talkersCard = (
    <Card
      key="talkers"
      id="chart-top-talkers"
      title="Top Talkers by Volume"
      right={
        <>
          {talkerLegend.map(([c, l]) => (
            <Swatch key={l} color={c} label={l} />
          ))}
          <span className="text-[#6c7689]">√ scale</span>
        </>
      }
    >
      <div className="h-[290px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={talkers}
            layout="vertical"
            margin={{ top: 4, right: 84, bottom: 0, left: 0 }}
            barCategoryGap={6}
          >
            <CartesianGrid stroke="#232a35" horizontal={false} />
            <XAxis type="number" scale="sqrt" domain={[0, "dataMax"]} hide />
            <YAxis
              dataKey="src_ip"
              type="category"
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#c4c9d4', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
              width={104}
            />
            <Tooltip
              cursor={CURSOR}
              content={
                <ChartTooltip
                  build={(d) => ({
                    title: d.src_ip,
                    rows: [
                      {
                        label: 'Sent',
                        value: `${Number(d.bytes).toLocaleString()} B`,
                        color: threatColors.get(d.src_ip) ?? BENIGN,
                      },
                    ],
                    hint: 'Click to filter host',
                  })}
                />
              }
            />
            <Bar
              dataKey="bytes"
              name="Bytes"
              radius={[0, 2, 2, 0]}
              cursor="pointer"
              {...anim}
              onClick={(_: any, i: number) => onFilter({ host: talkers[i].src_ip })}
            >
              {talkers.map((t) => (
                <Cell
                  key={t.src_ip}
                  fill={threatColors.get(t.src_ip) ?? BENIGN}
                  fillOpacity={pairOrHost && pairOrHost !== t.src_ip ? 0.35 : 1}
                />
              ))}
              <LabelList
                dataKey="bytes"
                position="right"
                formatter={(v: any) => formatBytes(Number(v))}
                style={{ fill: '#c4c9d4', fontSize: 10.5, fontFamily: 'IBM Plex Mono' }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );

  const portsCard = (
    <Card
      key="ports"
      id="chart-dst-ports"
      title="Top Destination Ports"
      right={portLegend.map(([c, l]) => (
        <Swatch key={l} color={c} label={l} />
      ))}
    >
      <div className="h-[290px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={ports}
            layout="vertical"
            margin={{ top: 4, right: 56, bottom: 0, left: 0 }}
            barCategoryGap={6}
          >
            <CartesianGrid stroke="#232a35" horizontal={false} />
            <XAxis type="number" hide />
            <YAxis
              dataKey="label"
              type="category"
              axisLine={false}
              tickLine={false}
              tick={{ fill: '#c4c9d4', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
              width={132}
            />
            <Tooltip
              cursor={CURSOR}
              content={
                <ChartTooltip
                  build={(d) => ({
                    title: `Port ${d.label}`,
                    rows: [{ label: 'Packets', value: Number(d.count).toLocaleString(), color: d.color }],
                    hint: 'Click to filter port',
                  })}
                />
              }
            />
            <Bar
              dataKey="count"
              name="Packets"
              radius={[0, 2, 2, 0]}
              cursor="pointer"
              {...anim}
              onClick={(_: any, i: number) => onFilter({ port: String(ports[i].port) })}
            >
              {ports.map((p) => (
                <Cell
                  key={p.port}
                  fill={p.color}
                  fillOpacity={filter.port && filter.port !== String(p.port) ? 0.35 : 1}
                />
              ))}
              <LabelList
                dataKey="count"
                position="right"
                style={{ fill: '#c4c9d4', fontSize: 10.5, fontFamily: 'IBM Plex Mono' }}
              />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );

  const scatterCard = (
    <Card
      key="scatter"
      id="chart-port-scan-scatter"
      title="Port Scan Temporal Sweep"
      right={<Swatch color={SEV_COLOR.HIGH} label="Scan probe" />}
    >
      <div className="h-[290px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 10, right: 16, bottom: 4, left: 0 }}>
            <CartesianGrid stroke="#232a35" />
            <XAxis dataKey="elapsed" type="number" name="Elapsed" unit="s" tick={AXIS_TICK} stroke="#2a313d" />
            <YAxis dataKey="dst_port" type="number" name="Port" tick={AXIS_TICK} stroke="#2a313d" width={48} />
            <Tooltip
              cursor={{ stroke: '#2a313d' }}
              content={
                <ChartTooltip
                  build={(d) => ({
                    title: `Probe from ${d.src_ip}`,
                    rows: [
                      { label: 'Elapsed', value: `${d.elapsed}s`, color: threatColors.get(d.src_ip) ?? SEV_COLOR.HIGH },
                      { label: 'Target port', value: String(d.dst_port) },
                    ],
                    hint: 'Click to filter scanner host',
                  })}
                />
              }
            />
            <Scatter
              name="Probes"
              data={charts.port_scan_points}
              cursor="pointer"
              {...anim}
              onClick={(d: any) => d?.src_ip && onFilter({ host: d.src_ip })}
            >
              {charts.port_scan_points.map((pt, i) => (
                <Cell key={i} fill={threatColors.get(pt.src_ip) ?? SEV_COLOR.HIGH} fillOpacity={0.85} />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );

  const timelineCard = (
    <Card
      key="timeline"
      id="chart-traffic-timeline"
      title="Traffic Timeline"
      className={hasScan ? '' : 'lg:col-span-2'}
      right={
        <>
          <Swatch color={BENIGN} label="Packets / s" />
          <Swatch color="#9aa9bb" label="Bytes / s" />
        </>
      }
    >
      <div className="h-[290px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={charts.traffic_timeline} margin={{ top: 10, right: 4, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="#232a35" />
            <XAxis dataKey="second" tick={AXIS_TICK} stroke="#2a313d" unit="s" />
            <YAxis yAxisId="left" tick={{ ...AXIS_TICK, fill: BENIGN }} stroke="#2a313d" width={38} />
            <YAxis
              yAxisId="right"
              orientation="right"
              tick={{ ...AXIS_TICK, fill: '#9aa9bb' }}
              stroke="#2a313d"
              width={52}
              tickFormatter={(v) => formatBytes(Number(v))}
            />
            <Tooltip
              content={
                <ChartTooltip
                  build={(d) => ({
                    title: `t = ${d.second}s`,
                    rows: [
                      { label: 'Packets', value: Number(d.packets).toLocaleString(), color: BENIGN },
                      { label: 'Bytes', value: `${Number(d.bytes).toLocaleString()} B`, color: '#9aa9bb' },
                    ],
                  })}
                />
              }
            />
            <Area
              yAxisId="left"
              type="monotone"
              dataKey="packets"
              fill="rgba(74, 144, 217, 0.15)"
              stroke={BENIGN}
              strokeWidth={1.5}
              {...anim}
            />
            <Line
              yAxisId="right"
              type="monotone"
              dataKey="bytes"
              stroke="#9aa9bb"
              strokeWidth={1.5}
              strokeDasharray="3 3"
              dot={false}
              {...anim}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );

  const sizesCard = (
    <Card key="sizes" id="chart-packet-sizes" title="Packet Length Distribution" right={<span>Frame buckets</span>}>
      <div className="h-[290px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={charts.packet_sizes} margin={{ top: 18, right: 4, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="#232a35" vertical={false} />
            <XAxis dataKey="bucket" tick={AXIS_TICK} stroke="#2a313d" />
            <YAxis tick={AXIS_TICK} stroke="#2a313d" width={38} />
            <Tooltip
              cursor={CURSOR}
              content={
                <ChartTooltip
                  build={(d) => ({
                    title: d.bucket,
                    rows: [{ label: 'Packets', value: Number(d.count).toLocaleString(), color: BENIGN_MUTED }],
                  })}
                />
              }
            />
            <Bar dataKey="count" fill={BENIGN_MUTED} radius={[2, 2, 0, 0]} {...anim}>
              <LabelList dataKey="count" position="top" style={{ fill: '#c4c9d4', fontSize: 10.5, fontFamily: 'IBM Plex Mono' }} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );

  // With no scan the scatter card is dropped, so the timeline takes the full last row.
  const secondaryCards = hasScan
    ? [donut, talkersCard, portsCard, scatterCard, timelineCard, sizesCard]
    : [donut, talkersCard, portsCard, sizesCard, timelineCard];

  return (
    <section id="charts-section" className="mb-10">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-[16px] font-semibold text-[#e6e9ef] tracking-tight m-0">
          Traffic Analytics & Forensic Visualizations
        </h2>
        <span className="text-[12px] text-[#8b94a7] font-mono flex items-center gap-3">
          {!hasScan && (
            <span className="flex items-center gap-1.5" style={{ color: CLEAR_GREEN }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: CLEAR_GREEN }} />
              No port-scan activity
            </span>
          )}
          {viewCount} Statistical Views
        </span>
      </div>
      <div className="h-px bg-[#2a313d] mb-5" />

      <div className="space-y-5 mb-5">
        <Card
          id="chart-host-flow-sankey"
          title="Host Communication Flow"
          right={<span>Bytes · top {charts.host_flow.length} pairs · ribbon width √ scale · click a node or flow</span>}
        >
          {charts.host_flow.length === 0 ? (
            <div className="py-10 text-center text-[13px] text-[#8b94a7]">No communication flows recorded.</div>
          ) : (
            <FlowSankey
              flows={charts.host_flow}
              threatColors={threatColors}
              activePair={pairActive}
              activeHost={filter.host}
              onSelectPair={(src, dst) => onFilter({ pair: { src, dst } })}
              onSelectHost={(ip) => onFilter({ host: ip })}
            />
          )}
        </Card>

        <Card
          id="chart-conversation-heatmap"
          title="Host Conversation Matrix"
          right={<span>Packet density per pair · click a cell</span>}
        >
          {charts.conversation_matrix.sources.length === 0 ? (
            <div className="py-10 text-center text-[13px] text-[#8b94a7]">No correlation matrix available.</div>
          ) : (
            <ConversationHeatmap
              matrix={charts.conversation_matrix}
              threatColors={threatColors}
              activePair={pairActive}
              onSelectPair={(src, dst) => onFilter({ pair: { src, dst } })}
            />
          )}
        </Card>
      </div>

      <div id="primary-charts-grid" className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {secondaryCards}
      </div>
    </section>
  );
};
