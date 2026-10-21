import React, { useEffect, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { fetchPackets } from '../api';
import type { ExplorerFilter, PacketRow } from '../types';
import { EMPTY_FILTER } from '../types';
import { SEV_COLOR } from '../lib/severity';

interface PacketExplorerProps {
  availableProtocols: string[];
  filter: ExplorerFilter;
  onChange: (next: ExplorerFilter) => void;
}

interface Chip {
  key: string;
  label: string;
  color?: string;
  clear: () => void;
}

export const PacketExplorer: React.FC<PacketExplorerProps> = ({ availableProtocols, filter, onChange }) => {
  const [packets, setPackets] = useState<PacketRow[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [offset, setOffset] = useState<number>(0);
  const [limit] = useState<number>(50);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [resultKey, setResultKey] = useState<number>(0);
  const reqId = useRef(0);

  const set = (patch: Partial<ExplorerFilter>) => onChange({ ...filter, ...patch });

  const loadData = async (currentOffset: number) => {
    const id = ++reqId.current;
    setIsLoading(true);
    try {
      const portNum = filter.port ? parseInt(filter.port, 10) : undefined;
      const res = await fetchPackets({
        protocol: filter.protocol || undefined,
        search: filter.search.trim() || undefined,
        port: portNum && !isNaN(portNum) ? portNum : undefined,
        host: filter.host || undefined,
        src: filter.pair?.src,
        dst: filter.pair?.dst,
        alert: filter.alert?.id,
        limit,
        offset: currentOffset,
      });
      if (id !== reqId.current) return; // a newer filter superseded this response
      setPackets(res.packets);
      setTotal(res.total);
      setResultKey((k) => k + 1);
    } catch (err) {
      console.error('Failed to load packets:', err);
    } finally {
      if (id === reqId.current) setIsLoading(false);
    }
  };

  useEffect(() => {
    setOffset(0);
    loadData(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  const handlePrev = () => {
    const nextOffset = Math.max(0, offset - limit);
    setOffset(nextOffset);
    loadData(nextOffset);
  };

  const handleNext = () => {
    if (offset + limit < total) {
      const nextOffset = offset + limit;
      setOffset(nextOffset);
      loadData(nextOffset);
    }
  };

  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const chips: Chip[] = [];
  if (filter.alert)
    chips.push({
      key: 'alert',
      label: `Alert: ${filter.alert.title}`,
      color: SEV_COLOR[filter.alert.severity],
      clear: () => set({ alert: null }),
    });
  if (filter.protocol) chips.push({ key: 'protocol', label: `Protocol: ${filter.protocol}`, clear: () => set({ protocol: '' }) });
  if (filter.host) chips.push({ key: 'host', label: `Host: ${filter.host}`, clear: () => set({ host: '' }) });
  if (filter.pair)
    chips.push({ key: 'pair', label: `Flow: ${filter.pair.src} → ${filter.pair.dst}`, clear: () => set({ pair: null }) });
  if (filter.port) chips.push({ key: 'port', label: `Port: ${filter.port}`, clear: () => set({ port: '' }) });
  if (filter.search.trim()) chips.push({ key: 'search', label: `Search: ${filter.search.trim()}`, clear: () => set({ search: '' }) });

  const inputCls =
    'w-full bg-[#0f1419] border border-[#2a313d] rounded px-3 py-2 text-[13px] text-[#e6e9ef] font-mono focus:border-[#4a90d9] focus:outline-none';
  const labelCls = 'block text-[11px] font-medium uppercase tracking-wider text-[#8b94a7] mb-1.5';

  return (
    <section id="packet-explorer-section" className="mb-10 scroll-mt-4">
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-[16px] font-semibold text-[#e6e9ef] tracking-tight m-0">Packet Explorer</h2>
        <span className="text-[12px] text-[#8b94a7] font-mono">SQL Database Query Engine</span>
      </div>
      <div className="h-px bg-[#2a313d] mb-4" />

      {/* Filter Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5 mb-4 bg-[#1a1f29] border border-[#2a313d] rounded p-4">
        <div>
          <label className={labelCls}>Protocol Filter</label>
          <select
            value={filter.protocol}
            onChange={(e) => set({ protocol: e.target.value })}
            className={inputCls}
          >
            <option value="">All Protocols</option>
            {availableProtocols.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className={labelCls}>Host IP Search</label>
          <input
            type="text"
            value={filter.search}
            onChange={(e) => set({ search: e.target.value })}
            placeholder="e.g. 192.168.1.99"
            className={inputCls}
          />
        </div>

        <div>
          <label className={labelCls}>Port Filter</label>
          <input
            type="number"
            value={filter.port}
            onChange={(e) => set({ port: e.target.value })}
            placeholder="e.g. 80, 443, 22"
            min={1}
            max={65535}
            className={inputCls}
          />
        </div>
      </div>

      {/* Active filter chips */}
      <div id="active-filters" className="flex flex-wrap items-center gap-2 mb-4 min-h-[30px]">
        {chips.length === 0 ? (
          <span className="text-[12px] text-[#6c7689]">
            No filters applied — click a chart element or threat alert to drill in.
          </span>
        ) : (
          <>
            <span className="text-[11px] font-mono uppercase tracking-wider text-[#8b94a7]">Filtered by</span>
            {chips.map((c) => (
              <span
                key={c.key}
                data-filter-chip={c.key}
                className="enter-fade inline-flex items-center gap-1.5 pl-3 pr-1.5 py-1 rounded border text-[12px] font-mono"
                style={{
                  color: c.color ?? '#e6e9ef',
                  borderColor: c.color ? `${c.color}88` : '#4a90d9',
                  backgroundColor: c.color ? `${c.color}1a` : 'rgba(74, 144, 217, 0.12)',
                }}
              >
                {c.label}
                <button
                  type="button"
                  aria-label={`Remove filter ${c.label}`}
                  onClick={c.clear}
                  className="w-5 h-5 rounded flex items-center justify-center cursor-pointer hover:bg-white/10"
                >
                  <X size={13} />
                </button>
              </span>
            ))}
            {chips.length > 1 && (
              <button
                type="button"
                onClick={() => onChange(EMPTY_FILTER)}
                className="text-[12px] text-[#8b94a7] hover:text-[#e6e9ef] underline cursor-pointer ml-1"
              >
                Clear all
              </button>
            )}
          </>
        )}
      </div>

      {/* Results Meta & Table */}
      <div className="bg-[#1a1f29] border border-[#2a313d] rounded overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-[#2a313d] bg-[#1a1f29] text-[12px] font-mono">
          <div className="text-[#8b94a7]">
            Matching records:{' '}
            <span id="match-count" className="text-[#e6e9ef] font-semibold">
              {total.toLocaleString()}
            </span>{' '}
            packets
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[#8b94a7]">
              Page {currentPage} of {totalPages}
            </span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handlePrev}
                disabled={offset === 0 || isLoading}
                className="px-2.5 py-1 text-[11px] font-mono rounded bg-[#0f1419] border border-[#2a313d] text-[#e6e9ef] disabled:opacity-40 hover:bg-[#232a35] cursor-pointer"
              >
                Prev
              </button>
              <button
                type="button"
                onClick={handleNext}
                disabled={offset + limit >= total || isLoading}
                className="px-2.5 py-1 text-[11px] font-mono rounded bg-[#0f1419] border border-[#2a313d] text-[#e6e9ef] disabled:opacity-40 hover:bg-[#232a35] cursor-pointer"
              >
                Next
              </button>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[460px] min-h-[200px]">
          <table className="w-full text-left text-[11.5px] font-mono border-collapse">
            <thead className="bg-[#0f1419] text-[#8b94a7] sticky top-0 border-b border-[#2a313d] z-10">
              <tr>
                <th className="py-2.5 px-3 font-medium">#</th>
                <th className="py-2.5 px-3 font-medium">Time (UTC)</th>
                <th className="py-2.5 px-3 font-medium">Source IP</th>
                <th className="py-2.5 px-3 font-medium">Port</th>
                <th className="py-2.5 px-3 font-medium">Destination IP</th>
                <th className="py-2.5 px-3 font-medium">Port</th>
                <th className="py-2.5 px-3 font-medium">Protocol</th>
                <th className="py-2.5 px-3 font-medium">App Layer</th>
                <th className="py-2.5 px-3 font-medium">TCP Flags</th>
                <th className="py-2.5 px-3 font-medium text-right">Length</th>
              </tr>
            </thead>
            <tbody
              key={resultKey}
              className={`enter-fade divide-y divide-[#2a313d] text-[#c4c9d4] transition-opacity ${
                isLoading ? 'opacity-50' : ''
              }`}
            >
              {packets.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-[#8b94a7]">
                    {isLoading ? 'Loading packet records...' : 'No packets match the filter criteria.'}
                  </td>
                </tr>
              ) : (
                packets.map((p) => (
                  <tr key={p.packet_no} className="hover:bg-[#232a35] transition-colors">
                    <td className="py-1.5 px-3 text-[#8b94a7]">{p.packet_no}</td>
                    <td className="py-1.5 px-3 whitespace-nowrap">{p.time_utc || '—'}</td>
                    <td className="py-1.5 px-3 text-[#e6e9ef]">{p.src_ip || '—'}</td>
                    <td className="py-1.5 px-3 text-[#8b94a7]">{p.src_port ?? '—'}</td>
                    <td className="py-1.5 px-3 text-[#e6e9ef]">{p.dst_ip || '—'}</td>
                    <td className="py-1.5 px-3 text-[#8b94a7]">{p.dst_port ?? '—'}</td>
                    <td className="py-1.5 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-[#0f1419] border border-[#2a313d] text-[#4a90d9] text-[10.5px]">
                        {p.protocol}
                      </span>
                    </td>
                    <td className="py-1.5 px-3 text-[#8b94a7]">{p.app_protocol || '—'}</td>
                    <td className="py-1.5 px-3 text-[#8b94a7]">{p.tcp_flags || '—'}</td>
                    <td className="py-1.5 px-3 text-right">{p.length} B</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};
