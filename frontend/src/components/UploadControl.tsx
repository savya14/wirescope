import React, { useRef, useState } from 'react';

interface UploadControlProps {
  currentCaptureName: string;
  isLoading: boolean;
  onUpload: (file: File) => void;
  onLoadSample: () => void;
}

export const UploadControl: React.FC<UploadControlProps> = ({
  currentCaptureName,
  isLoading,
  onUpload,
  onLoadSample,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragOver, setIsDragOver] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onUpload(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      onUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <section className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-5">
      <div className="flex items-center gap-2 text-[12px] text-[#8b94a7] min-w-0">
        <span>Active capture</span>
        <span className="font-mono text-[#e6e9ef] font-medium truncate max-w-[420px]">{currentCaptureName}</span>
      </div>

      <div className="flex items-center gap-2">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragOver(true);
          }}
          onDragLeave={() => setIsDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`px-3.5 py-1.5 border border-dashed rounded cursor-pointer transition-colors text-[12px] ${
            isDragOver
              ? 'border-[#4a90d9] bg-[#232a35] text-[#e6e9ef]'
              : 'border-[#2a313d] hover:border-[#4a90d9] text-[#8b94a7] hover:text-[#e6e9ef]'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={handleFileChange}
            className="hidden"
          />
          Upload or drop a capture (.pcap, .pcapng)
        </div>
        <button
          type="button"
          onClick={onLoadSample}
          disabled={isLoading}
          className="px-3.5 py-1.5 rounded border border-[#2a313d] bg-[#1a1f29] hover:bg-[#232a35] hover:border-[#4a90d9] text-[#e6e9ef] text-[12px] font-medium transition-colors disabled:opacity-50 cursor-pointer"
        >
          Load sample
        </button>
      </div>
    </section>
  );
};
