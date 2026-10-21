import React from 'react';
import type { ScenarioInfo } from '../types';
import { CLEAR_GREEN, SEV_COLOR } from '../lib/severity';

interface ScenarioSwitcherProps {
  scenarios: ScenarioInfo[];
  selectedScenarioId: string | null;
  isLoading: boolean;
  onSelectScenario: (scenarioId: string) => void;
}

const tagColor = (tag: ScenarioInfo['severity_tag']): string =>
  tag === 'CLEAR' ? CLEAR_GREEN : tag === 'MEDIUM' ? SEV_COLOR.MEDIUM : SEV_COLOR.HIGH;

export const ScenarioSwitcher: React.FC<ScenarioSwitcherProps> = ({
  scenarios,
  selectedScenarioId,
  isLoading,
  onSelectScenario,
}) => {
  const active = scenarios.find((s) => s.id === selectedScenarioId);

  return (
    <section className="mb-4">
      <div
        role="tablist"
        aria-label="Traffic scenarios"
        className="flex flex-wrap border border-[#2a313d] rounded bg-[#12171f] overflow-hidden"
      >
        {scenarios.map((scenario, i) => {
          const isSelected = selectedScenarioId === scenario.id;
          return (
            <button
              key={scenario.id}
              id={`scenario-btn-${scenario.id}`}
              data-scenario-id={scenario.id}
              role="tab"
              aria-selected={isSelected}
              type="button"
              disabled={isLoading}
              onClick={() => onSelectScenario(scenario.id)}
              className={`relative flex-1 min-w-[170px] flex items-center justify-between gap-3 px-4 py-2.5 text-left cursor-pointer transition-colors disabled:cursor-wait ${
                i > 0 ? 'border-l border-[#2a313d]' : ''
              } ${
                isSelected
                  ? 'bg-[#212936] text-white'
                  : 'text-[#8b94a7] hover:bg-[#181f2b] hover:text-[#e6e9ef]'
              }`}
            >
              <span className="text-[13px] font-medium truncate">{scenario.name}</span>
              <span
                className="text-[10.5px] font-mono font-semibold px-1.5 py-0.5 rounded border shrink-0 tabular-nums"
                style={{
                  color: tagColor(scenario.severity_tag),
                  borderColor: `${tagColor(scenario.severity_tag)}55`,
                  backgroundColor: `${tagColor(scenario.severity_tag)}14`,
                }}
                title={`${scenario.expected_alerts} alerts expected`}
              >
                {scenario.expected_alerts}
              </span>
              {isSelected && <span className="absolute left-0 right-0 bottom-0 h-[2px] bg-[#4a90d9]" />}
            </button>
          );
        })}
      </div>
      <div className="flex items-center justify-between gap-3 mt-2 min-h-[20px]">
        <p className="text-[12.5px] text-[#8b94a7] m-0">{active?.description ?? 'Custom capture'}</p>
        {isLoading && (
          <span className="flex items-center gap-2 text-[11.5px] font-mono text-[#4a90d9] shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-[#4a90d9] animate-ping" />
            Analyzing capture...
          </span>
        )}
      </div>
    </section>
  );
};
