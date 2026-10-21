import React, { useCallback, useEffect, useState } from 'react';
import {
  fetchHealth,
  fetchSampleAnalysis,
  fetchScenarios,
  fetchScenarioAnalysis,
  uploadAndAnalyzeCapture,
} from './api';
import type { AlertFilter, AnalysisResponse, ExplorerFilter, HealthInfo, ScenarioInfo } from './types';
import { EMPTY_FILTER } from './types';
import { topSeverity } from './lib/severity';
import { Header } from './components/Header';
import { ScenarioSwitcher } from './components/ScenarioSwitcher';
import { UploadControl } from './components/UploadControl';
import { KpiRow } from './components/KpiRow';
import { ThreatSignals } from './components/ThreatSignals';
import { ChartsGrid } from './components/ChartsGrid';
import { PacketExplorer } from './components/PacketExplorer';
import { Footer } from './components/Footer';

export const App: React.FC = () => {
  const [data, setData] = useState<AnalysisResponse | null>(null);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>('full_attack');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ExplorerFilter>(EMPTY_FILTER);
  // Bumps on every successful load so the dashboard remounts and replays its entrance motion.
  const [dataVersion, setDataVersion] = useState<number>(0);

  const showData = (res: AnalysisResponse) => {
    setData(res);
    setFilter(EMPTY_FILTER);
    setDataVersion((v) => v + 1);
  };

  const scrollToExplorer = () => {
    requestAnimationFrame(() => {
      const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      document
        .getElementById('packet-explorer-section')
        ?.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    });
  };

  // Clicking an already-active chart element clears that filter (toggle).
  const applyFilter = useCallback((patch: Partial<ExplorerFilter>) => {
    setFilter((prev) => {
      const next = { ...prev };
      for (const [k, v] of Object.entries(patch) as [keyof ExplorerFilter, any][]) {
        const same = JSON.stringify(prev[k]) === JSON.stringify(v);
        (next as any)[k] = same ? EMPTY_FILTER[k] : v;
      }
      // A flow already pins both ends, so a separate host filter would be redundant.
      if (patch.pair) next.host = '';
      if (patch.host) next.pair = null;
      return next;
    });
    scrollToExplorer();
  }, []);

  const investigate = useCallback((alert: AlertFilter) => {
    setFilter((prev) => ({ ...EMPTY_FILTER, alert: prev.alert?.id === alert.id ? null : alert }));
    scrollToExplorer();
  }, []);

  const initData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Concurrently fetch health, scenarios list, and the default full_attack scenario
      const [healthRes, scenariosRes, analysisRes] = await Promise.all([
        fetchHealth().catch(() => null),
        fetchScenarios().catch(() => [
          {
            id: 'full_attack',
            name: 'Full Attack Chain',
            description: 'All 5 threat signals active: port scan, plaintext, C2, heavy talker, ICMP flood.',
            severity_tag: 'CRITICAL' as const,
            expected_alerts: 5,
          },
          {
            id: 'port_scan',
            name: 'Port Scan',
            description: 'SYN port scan from 192.168.1.99 probing 42 distinct ports.',
            severity_tag: 'HIGH' as const,
            expected_alerts: 1,
          },
          {
            id: 'malware_c2',
            name: 'Malware C2 & Plaintext',
            description: 'C2 channels on ports 4444, 31337, 6667, 1337 + unencrypted credentials.',
            severity_tag: 'MEDIUM' as const,
            expected_alerts: 2,
          },
          {
            id: 'normal',
            name: 'Benign Baseline',
            description: 'Clean background traffic only (DNS, HTTPS, SSH, ICMP). Zero alerts.',
            severity_tag: 'CLEAR' as const,
            expected_alerts: 0,
          },
        ]),
        fetchScenarioAnalysis('full_attack').catch(() => fetchSampleAnalysis()),
      ]);

      setHealth(healthRes);
      setScenarios(scenariosRes);
      showData(analysisRes);
      setSelectedScenarioId('full_attack');
    } catch (err: any) {
      console.error('Initialization error:', err);
      setError(err?.message || 'Unable to connect to the PCAP analysis backend.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    initData();
  }, []);

  const handleSelectScenario = async (scenarioId: string) => {
    if (isLoading || scenarioId === selectedScenarioId) return;
    const previousId = selectedScenarioId;
    setIsLoading(true);
    setError(null);
    setSelectedScenarioId(scenarioId);
    try {
      const res = await fetchScenarioAnalysis(scenarioId);
      showData(res);
      fetchHealth().then(setHealth).catch(() => null);
    } catch (err: any) {
      console.error('Scenario switch error:', err);
      setSelectedScenarioId(previousId);
      setError(err?.message || `Failed to load scenario '${scenarioId}'.`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUpload = async (file: File) => {
    setIsLoading(true);
    setError(null);
    setSelectedScenarioId(null); // Custom upload has no active preset scenario
    try {
      const res = await uploadAndAnalyzeCapture(file);
      showData(res);
      fetchHealth().then(setHealth).catch(() => null);
    } catch (err: any) {
      console.error('Upload error:', err);
      setError(err?.message || 'Failed to analyze uploaded capture file.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadSample = async () => {
    await handleSelectScenario('full_attack');
  };

  return (
    <div className="min-h-screen bg-[#0f1419] text-[#e6e9ef]">
      <div className="max-w-[1400px] mx-auto px-6 py-6">
        {error && (
          <div className="bg-[#1a1f29] border border-[#d65353] border-l-[3px] border-l-[#d65353] rounded p-4 mb-6">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[14px] font-semibold text-[#d65353]">
                  System Communication Error
                </span>
                <p className="text-[12.5px] text-[#8b94a7] mt-1 m-0">{error}</p>
              </div>
              <button
                type="button"
                onClick={initData}
                className="px-3 py-1.5 rounded bg-[#0f1419] border border-[#2a313d] hover:border-[#4a90d9] text-[#e6e9ef] text-[12px] font-mono cursor-pointer"
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {isLoading && !data ? (
          <div>
            <Header health={health} />
            <div className="py-24 flex flex-col items-center justify-center text-center">
              <div className="w-8 h-8 rounded-full border-2 border-[#4a90d9] border-t-transparent animate-spin mb-4" />
              <p className="text-[14px] text-[#e6e9ef] font-medium m-0">
                Dissecting packet capture & initializing SQLite database...
              </p>
              <p className="text-[12px] text-[#8b94a7] mt-1 m-0">
                Evaluating protocol trees and running threat detection heuristics.
              </p>
            </div>
          </div>
        ) : data ? (
          <>
            <div id="header-kpis-section">
              <Header health={health} />

              <ScenarioSwitcher
                scenarios={scenarios}
                selectedScenarioId={selectedScenarioId}
                isLoading={isLoading}
                onSelectScenario={handleSelectScenario}
              />

              <UploadControl
                currentCaptureName={data.meta.capture_name}
                isLoading={isLoading}
                onUpload={handleUpload}
                onLoadSample={handleLoadSample}
              />
            </div>

            <div
              key={dataVersion}
              className={`transition-opacity duration-150 ${isLoading ? 'opacity-50 pointer-events-none' : ''}`}
            >
              <div className="enter enter-1">
                <KpiRow meta={data.meta} topSeverity={topSeverity(data.detections)} />
              </div>

              <div className="enter enter-2">
                <ThreatSignals
                  detections={data.detections}
                  activeAlertId={filter.alert?.id ?? null}
                  onInvestigate={investigate}
                />
              </div>

              <div className="enter enter-3">
                <ChartsGrid
                  charts={data.charts}
                  detections={data.detections}
                  filter={filter}
                  onFilter={applyFilter}
                />
              </div>

              <div className="enter enter-4">
                <PacketExplorer
                  availableProtocols={data.charts.protocol_distribution.map((p) => p.protocol)}
                  filter={filter}
                  onChange={setFilter}
                />
              </div>
            </div>

            <Footer />
          </>
        ) : null}
      </div>
    </div>
  );
};

export default App;
