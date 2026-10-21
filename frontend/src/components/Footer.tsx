import React from 'react';
import { getDownloadUrl } from '../api';

export const Footer: React.FC = () => {
  return (
    <footer className="border-t border-[#2a313d] pt-8 pb-12 mt-12">
      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        {/* Module credits */}
        <div className="text-[12px] text-[#8b94a7]">
          <span>Implemented Lab Modules: </span>
          <span className="text-[#e6e9ef] font-mono">
            PCAP to SQLite &bull; PCAP to XML &bull; PyShark Traffic Analysis
          </span>
        </div>

        {/* Download buttons */}
        <div className="flex flex-wrap items-center gap-3">
          <a
            href={getDownloadUrl('packets.db')}
            download="packets.db"
            className="px-3.5 py-2 rounded bg-[#1a1f29] border border-[#2a313d] hover:border-[#4a90d9] hover:bg-[#232a35] text-[#e6e9ef] text-[12.5px] font-medium transition-colors"
          >
            Download SQLite DB
          </a>
          <a
            href={getDownloadUrl('packets.xml')}
            download="packets.xml"
            className="px-3.5 py-2 rounded bg-[#1a1f29] border border-[#2a313d] hover:border-[#4a90d9] hover:bg-[#232a35] text-[#e6e9ef] text-[12.5px] font-medium transition-colors"
          >
            Download XML Capture
          </a>
          <a
            href={getDownloadUrl('packets.csv')}
            download="packets.csv"
            className="px-3.5 py-2 rounded bg-[#1a1f29] border border-[#2a313d] hover:border-[#4a90d9] hover:bg-[#232a35] text-[#e6e9ef] text-[12.5px] font-medium transition-colors"
          >
            Download Packets CSV
          </a>
        </div>
      </div>
    </footer>
  );
};
