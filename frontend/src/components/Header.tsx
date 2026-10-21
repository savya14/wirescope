import React from 'react';
import type { HealthInfo } from '../types';

interface HeaderProps {
  health: HealthInfo | null;
}

export const Header: React.FC<HeaderProps> = ({ health }) => {
  return (
    <header className="border-b border-[#2a313d] pb-4 mb-4">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-[22px] font-semibold text-[#e6e9ef] tracking-tight m-0">
            PCAP Analyzer
          </h1>
          <p className="text-[13px] text-[#8b94a7] mt-1 m-0">
            Forensic network traffic dissection, relational SQLite analysis, and threat detection
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          <div
            id="parser-engine-badge"
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded border border-[#2a313d] bg-[#1a1f29] text-[12px] font-mono text-[#8b94a7]"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-[#4a90d9]" />
            <span>Engine:</span>
            <span className="text-[#e6e9ef] font-medium">
              {health?.parser_used || 'Initializing...'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
