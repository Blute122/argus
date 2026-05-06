import { useState, useEffect } from 'react';
import { getScenarios, getScenarioDetail, runSimulation, getSimulationHistory } from '../services/api';

export default function SimulationsPage() {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [detail, setDetail] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);

  useEffect(() => {
    getScenarios().then((r) => setScenarios(r.data)).catch(() => {});
    getSimulationHistory().then((r) => setHistory(r.data)).catch(() => {});
  }, []);

  const selectScenario = async (s: any) => {
    setSelected(s);
    setResult(null);
    const res = await getScenarioDetail(s.id);
    setDetail(res.data);
  };

  const handleRun = async (id: string) => {
    setRunning(id);
    setResult(null);
    try {
      const res = await runSimulation(id);
      setResult(res.data);
      getSimulationHistory().then((r) => setHistory(r.data)).catch(() => {});
    } finally {
      setRunning(null);
    }
  };

  const attackIcons: Record<string, string> = {
    brute_force: '🔓', phishing: '🎣', lateral_movement: '🔀',
    exfiltration: '📤', ransomware: '💀', command_and_control: '🖥️',
  };

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold">⚔️ Attack Simulation</h1>
        <p className="text-sm text-[var(--text-muted)] font-mono">
          Safe, sandboxed attack chain simulations — educational only
        </p>
      </div>

      <div className="flex gap-4">
        {/* Scenario grid */}
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-[var(--text-muted)] mb-3 font-mono uppercase tracking-wider">Available Scenarios</h3>
          <div className="grid grid-cols-2 gap-3">
            {scenarios.map((s) => (
              <div
                key={s.id}
                onClick={() => selectScenario(s)}
                className={`glass-card p-4 cursor-pointer ${selected?.id === s.id ? 'border-[var(--accent-cyan)]' : ''}`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-2xl">{attackIcons[s.attack_type] || '⚡'}</span>
                  <h4 className="text-sm font-semibold">{s.name}</h4>
                </div>
                <p className="text-xs text-[var(--text-secondary)] mb-2">{s.description}</p>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">
                    {s.mitre_technique}
                  </span>
                  <span className="text-[10px] font-mono text-[var(--text-muted)]">{s.attack_type}</span>
                </div>
              </div>
            ))}
          </div>

          {/* History */}
          <h3 className="text-sm font-semibold text-[var(--text-muted)] mt-6 mb-3 font-mono uppercase tracking-wider">Simulation History</h3>
          <div className="space-y-2 max-h-[200px] overflow-y-auto">
            {history.map((h) => (
              <div key={h.id} className="flex items-center gap-3 p-3 glass-card text-sm">
                <span className={`text-xs font-mono px-2 py-0.5 rounded ${
                  h.status === 'completed' ? 'bg-green-500/15 text-green-400' : 'bg-yellow-500/15 text-yellow-400'
                }`}>{h.status}</span>
                <span className="flex-1 truncate">{h.name}</span>
                <span className="text-xs text-[var(--text-muted)] font-mono">{h.generated_logs} logs / {h.generated_alerts} alerts</span>
              </div>
            ))}
          </div>
        </div>

        {/* Detail panel */}
        {detail && (
          <div className="w-[380px] glass-card p-5 animate-slide-in self-start">
            <h3 className="text-lg font-bold mb-1">{detail.name}</h3>
            <p className="text-sm text-[var(--text-secondary)] mb-4">{detail.description}</p>

            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30">
                <span className="text-xs text-purple-400 font-mono">MITRE ATT&CK</span>
                <p className="text-sm font-medium text-purple-300">{detail.mitre_technique} — {detail.mitre_technique_name}</p>
              </div>

              <div>
                <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">KILL CHAIN STEPS</label>
                <div className="space-y-2">
                  {detail.steps?.map((step: any, i: number) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded bg-[var(--bg-input)] border border-[var(--border-color)]">
                      <span className="w-5 h-5 rounded-full bg-[var(--accent-cyan)]/20 text-[var(--accent-cyan)] flex items-center justify-center text-[10px] font-bold">
                        {i + 1}
                      </span>
                      <div>
                        <p className="text-xs font-medium text-[var(--accent-cyan)]">{step.action}</p>
                        <p className="text-[11px] text-[var(--text-secondary)]">{step.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <button
                onClick={() => handleRun(selected.id)}
                disabled={running === selected.id}
                className="btn-danger w-full mt-4"
              >
                {running === selected.id ? '⏳ Running Simulation...' : '▶ Execute Simulation'}
              </button>

              {result && (
                <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/30">
                  <p className="text-xs text-green-400 font-mono">✓ SIMULATION COMPLETE</p>
                  <p className="text-sm">Logs: {result.logs_generated} | Alerts: {result.alerts_generated}</p>
                </div>
              )}

              <p className="text-[10px] text-[var(--text-muted)] font-mono text-center">
                ⚠ EDUCATIONAL ONLY — No real attacks executed
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
