import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../store/AuthContext';
import {
  autorunCampaign,
  getCampaignRun,
  getCampaignRuns,
  getCampaigns,
  getScenarioDetail,
  getScenarios,
  getSimulationHistory,
  runNextCampaignStage,
  runSimulation,
  startCampaign,
} from '../services/api';

export default function SimulationsPage() {
  const { user } = useAuth();
  const canRunSim = user?.role === 'admin' || user?.role === 'threat_hunter';
  const [view, setView] = useState<'campaigns' | 'scenarios'>('campaigns');
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [campaignRuns, setCampaignRuns] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [detail, setDetail] = useState<any>(null);
  const [activeRun, setActiveRun] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [running, setRunning] = useState<string | number | null>(null);
  const [result, setResult] = useState<any>(null);

  useEffect(() => {
    refresh();
  }, []);

  const refresh = () => {
    getScenarios().then((r) => setScenarios(r.data)).catch(() => {});
    getCampaigns().then((r) => setCampaigns(r.data)).catch(() => {});
    getCampaignRuns().then((r) => setCampaignRuns(r.data)).catch(() => {});
    getSimulationHistory().then((r) => setHistory(r.data)).catch(() => {});
  };

  const selectScenario = async (scenario: any) => {
    setSelected(scenario);
    setResult(null);
    setActiveRun(null);
    const res = await getScenarioDetail(scenario.id);
    setDetail(res.data);
  };

  const handleRunScenario = async (id: string) => {
    setRunning(id);
    setResult(null);
    try {
      const res = await runSimulation(id);
      setResult(res.data);
      refresh();
    } finally {
      setRunning(null);
    }
  };

  const handleStartCampaign = async (campaignId: string) => {
    setRunning(campaignId);
    try {
      const res = await startCampaign(campaignId);
      setActiveRun(res.data);
      setSelected(campaigns.find((campaign) => campaign.id === campaignId));
      refresh();
    } finally {
      setRunning(null);
    }
  };

  const handleRunNext = async () => {
    if (!activeRun) return;
    setRunning(activeRun.id);
    try {
      const res = await runNextCampaignStage(activeRun.id);
      setActiveRun(res.data);
      refresh();
    } finally {
      setRunning(null);
    }
  };

  const handleAutorun = async () => {
    if (!activeRun) return;
    setRunning(activeRun.id);
    try {
      const res = await autorunCampaign(activeRun.id);
      setActiveRun(res.data.run);
      refresh();
    } finally {
      setRunning(null);
    }
  };

  const loadCampaignRun = async (runId: number) => {
    const res = await getCampaignRun(runId);
    setActiveRun(res.data);
    setSelected(campaigns.find((campaign) => campaign.id === res.data.campaign_id) || null);
    setView('campaigns');
  };

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Attack Simulation</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">Safe staged campaigns, one-shot simulations, and purple-team detection coverage</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setView('campaigns')} className={`text-xs font-mono px-3 py-1.5 rounded-lg border ${view === 'campaigns' ? 'border-[var(--accent-cyan)] text-[var(--accent-cyan)] bg-cyan-500/10' : 'border-[var(--border-color)] text-[var(--text-muted)]'}`}>Campaigns</button>
          <button onClick={() => setView('scenarios')} className={`text-xs font-mono px-3 py-1.5 rounded-lg border ${view === 'scenarios' ? 'border-[var(--accent-cyan)] text-[var(--accent-cyan)] bg-cyan-500/10' : 'border-[var(--border-color)] text-[var(--text-muted)]'}`}>Scenarios</button>
        </div>
      </div>

      {view === 'campaigns' ? (
        <CampaignView
          campaigns={campaigns}
          campaignRuns={campaignRuns}
          activeRun={activeRun}
          selected={selected}
          canRunSim={canRunSim}
          running={running}
          onStart={handleStartCampaign}
          onRunNext={handleRunNext}
          onAutorun={handleAutorun}
          onLoadRun={loadCampaignRun}
        />
      ) : (
        <ScenarioView
          scenarios={scenarios}
          selected={selected}
          detail={detail}
          history={history}
          result={result}
          canRunSim={canRunSim}
          running={running}
          onSelect={selectScenario}
          onRun={handleRunScenario}
        />
      )}
    </div>
  );
}

function CampaignView({ campaigns, campaignRuns, activeRun, selected, canRunSim, running, onStart, onRunNext, onAutorun, onLoadRun }: any) {
  const summary = useMemo(() => ({
    completed: activeRun?.stages?.filter((stage: any) => stage.status === 'completed').length || 0,
    detected: activeRun?.stages?.filter((stage: any) => stage.detected).length || 0,
    missed: activeRun?.stages?.filter((stage: any) => stage.status === 'completed' && !stage.detected).length || 0,
  }), [activeRun]);

  return (
    <div className="grid grid-cols-[minmax(420px,1fr)_430px] gap-4">
      <div className="space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-[var(--text-muted)] mb-3 font-mono uppercase tracking-wider">Campaign Library</h3>
          <div className="grid grid-cols-2 gap-3">
            {campaigns.map((campaign: any) => (
              <div key={campaign.id} className={`glass-card p-4 ${selected?.id === campaign.id ? 'border-[var(--accent-cyan)]' : ''}`}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h4 className="text-sm font-semibold">{campaign.name}</h4>
                    <p className="text-xs text-[var(--text-secondary)] mt-1">{campaign.description}</p>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">{campaign.difficulty}</span>
                </div>
                <div className="flex items-center gap-3 mt-3 text-[10px] font-mono text-[var(--text-muted)]">
                  <span>{campaign.stage_count} stages</span>
                  <span>{campaign.target_assets?.length || 0} assets</span>
                </div>
                <button
                  onClick={() => onStart(campaign.id)}
                  disabled={!canRunSim || running === campaign.id}
                  className="btn-primary w-full mt-4 text-sm disabled:opacity-50"
                >
                  {running === campaign.id ? 'Starting...' : 'Start Campaign'}
                </button>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h3 className="text-sm font-semibold text-[var(--text-muted)] mb-3 font-mono uppercase tracking-wider">Campaign Runs</h3>
          <div className="space-y-2 max-h-[220px] overflow-y-auto pr-2">
            {campaignRuns.map((run: any) => (
              <button key={run.id} onClick={() => onLoadRun(run.id)} className={`w-full text-left flex items-center gap-3 p-3 glass-card text-sm ${activeRun?.id === run.id ? 'border-[var(--accent-cyan)]' : ''}`}>
                <span className={`text-xs font-mono px-2 py-0.5 rounded ${run.status === 'completed' ? 'bg-green-500/15 text-green-400' : 'bg-yellow-500/15 text-yellow-400'}`}>{run.status}</span>
                <span className="flex-1 truncate">{run.name}</span>
                <span className="text-xs text-[var(--text-muted)] font-mono">{run.current_stage + 1}/{run.total_stages}</span>
                <span className="text-xs text-[var(--accent-cyan)] font-mono">{run.coverage}%</span>
              </button>
            ))}
            {campaignRuns.length === 0 && <p className="text-xs text-[var(--text-muted)] font-mono py-4">No campaign runs yet.</p>}
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {activeRun ? (
          <>
            <div className="glass-card p-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-mono text-[var(--accent-cyan)]">RUN-{activeRun.id}</p>
                  <h3 className="text-lg font-bold">{activeRun.name}</h3>
                  <p className="text-sm text-[var(--text-secondary)] mt-1">{activeRun.description}</p>
                </div>
                <span className={`text-xs font-mono px-2 py-1 rounded ${activeRun.status === 'completed' ? 'bg-green-500/15 text-green-400' : 'bg-yellow-500/15 text-yellow-400'}`}>{activeRun.status}</span>
              </div>

              <div className="grid grid-cols-4 gap-3 mt-4">
                <Metric label="Stages" value={`${summary.completed}/${activeRun.total_stages}`} />
                <Metric label="Detected" value={summary.detected} tone="text-green-400" />
                <Metric label="Missed" value={summary.missed} tone="text-red-400" />
                <Metric label="Coverage" value={`${activeRun.coverage}%`} tone="text-[var(--accent-cyan)]" />
              </div>

              <div className="flex gap-2 mt-4">
                <button onClick={onRunNext} disabled={!canRunSim || activeRun.status === 'completed' || running === activeRun.id} className="btn-primary flex-1 text-sm disabled:opacity-50">
                  {running === activeRun.id ? 'Running...' : 'Run Next Stage'}
                </button>
                <button onClick={onAutorun} disabled={!canRunSim || activeRun.status === 'completed' || running === activeRun.id} className="btn-primary flex-1 text-sm !bg-gradient-to-r !from-purple-600 !to-cyan-600 disabled:opacity-50">
                  Auto-Run
                </button>
              </div>
            </div>

            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold text-[var(--text-muted)] mb-3 font-mono uppercase tracking-wider">Purple-Team Coverage</h3>
              <div className="space-y-2 max-h-[520px] overflow-y-auto pr-2">
                {activeRun.stages?.map((stage: any) => (
                  <div key={stage.index} className={`p-3 rounded border ${stage.status === 'completed' ? (stage.detected ? 'border-green-500/30 bg-green-500/10' : 'border-red-500/30 bg-red-500/10') : 'border-[var(--border-color)] bg-[var(--bg-input)]'}`}>
                    <div className="flex items-center gap-2">
                      <span className="w-6 h-6 rounded-full bg-[var(--bg-card)] border border-[var(--border-color)] text-[10px] font-bold flex items-center justify-center">{stage.index + 1}</span>
                      <div className="flex-1">
                        <p className="text-sm font-medium">{stage.name}</p>
                        <p className="text-[10px] font-mono text-purple-400">{stage.technique} - {stage.technique_name}</p>
                      </div>
                      <span className={`text-[10px] font-mono ${stage.status !== 'completed' ? 'text-[var(--text-muted)]' : stage.detected ? 'text-green-400' : 'text-red-400'}`}>
                        {stage.status !== 'completed' ? 'PENDING' : stage.detected ? 'DETECTED' : 'MISSED'}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--text-secondary)] mt-2">{stage.objective}</p>
                    {stage.status === 'completed' && (
                      <p className="text-[10px] font-mono text-[var(--text-muted)] mt-2">{stage.logs_generated} logs / {stage.alerts_generated} alerts</p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </>
        ) : (
          <div className="glass-card p-8 text-center text-[var(--text-muted)] font-mono">Start or select a campaign run to view staged execution.</div>
        )}
      </div>
    </div>
  );
}

function ScenarioView({ scenarios, selected, detail, history, result, canRunSim, running, onSelect, onRun }: any) {
  const attackIcons: Record<string, string> = {
    brute_force: 'BF',
    phishing: 'PH',
    lateral_movement: 'LM',
    exfiltration: 'EX',
    ransomware: 'RW',
    command_and_control: 'C2',
    apt_campaign: 'APT',
  };

  return (
    <div className="flex gap-4">
      <div className="flex-1">
        <h3 className="text-sm font-semibold text-[var(--text-muted)] mb-3 font-mono uppercase tracking-wider">Available Scenarios</h3>
        <div className="grid grid-cols-2 gap-3">
          {scenarios.map((scenario: any) => (
            <div key={scenario.id} onClick={() => onSelect(scenario)} className={`glass-card p-4 cursor-pointer ${selected?.id === scenario.id ? 'border-[var(--accent-cyan)]' : ''}`}>
              <div className="flex items-center gap-2 mb-2">
                <span className="w-8 text-center text-[10px] font-mono font-bold text-[var(--accent-cyan)]">{attackIcons[scenario.attack_type] || 'SIM'}</span>
                <h4 className="text-sm font-semibold">{scenario.name}</h4>
              </div>
              <p className="text-xs text-[var(--text-secondary)] mb-2">{scenario.description}</p>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">{scenario.mitre_technique}</span>
                <span className="text-[10px] font-mono text-[var(--text-muted)]">{scenario.attack_type}</span>
              </div>
            </div>
          ))}
        </div>

        <h3 className="text-sm font-semibold text-[var(--text-muted)] mt-6 mb-3 font-mono uppercase tracking-wider">Simulation History</h3>
        <div className="space-y-2 max-h-[200px] overflow-y-auto">
          {history.map((item: any) => (
            <div key={item.id} className="flex items-center gap-3 p-3 glass-card text-sm">
              <span className={`text-xs font-mono px-2 py-0.5 rounded ${item.status === 'completed' ? 'bg-green-500/15 text-green-400' : 'bg-yellow-500/15 text-yellow-400'}`}>{item.status}</span>
              <span className="flex-1 truncate">{item.name}</span>
              <span className="text-xs text-[var(--text-muted)] font-mono">{item.generated_logs} logs / {item.generated_alerts} alerts</span>
            </div>
          ))}
        </div>
      </div>

      {detail && (
        <div className="w-[380px] glass-card p-5 animate-slide-in self-start">
          <h3 className="text-lg font-bold mb-1">{detail.name}</h3>
          <p className="text-sm text-[var(--text-secondary)] mb-4">{detail.description}</p>
          <div className="space-y-3">
            <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30">
              <span className="text-xs text-purple-400 font-mono">MITRE ATT&CK</span>
              <p className="text-sm font-medium text-purple-300">{detail.mitre_technique} - {detail.mitre_technique_name}</p>
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">KILL CHAIN STEPS</label>
              <div className="space-y-2">
                {detail.steps?.map((step: any, index: number) => (
                  <div key={index} className="flex items-center gap-2 p-2 rounded bg-[var(--bg-input)] border border-[var(--border-color)]">
                    <span className="w-5 h-5 rounded-full bg-[var(--accent-cyan)]/20 text-[var(--accent-cyan)] flex items-center justify-center text-[10px] font-bold">{index + 1}</span>
                    <div><p className="text-xs font-medium text-[var(--accent-cyan)]">{step.action}</p><p className="text-[11px] text-[var(--text-secondary)]">{step.detail}</p></div>
                  </div>
                ))}
              </div>
            </div>
            <button onClick={() => onRun(selected.id)} disabled={!canRunSim || running === selected.id} className={`btn-primary w-full mt-4 ${!canRunSim ? 'opacity-50 cursor-not-allowed' : ''}`}>
              {running === selected.id ? 'Running Simulation...' : 'Execute Simulation'}
            </button>
            {result && <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/30"><p className="text-xs text-green-400 font-mono">SIMULATION COMPLETE</p><p className="text-sm">Logs: {result.logs_generated} | Alerts: {result.alerts_generated}</p></div>}
            <p className="text-[10px] text-[var(--text-muted)] font-mono text-center">EDUCATIONAL ONLY - No real attacks executed</p>
          </div>
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, tone = 'text-[var(--text-primary)]' }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)]">
      <p className={`text-lg font-bold ${tone}`}>{value}</p>
      <p className="text-[10px] text-[var(--text-muted)] font-mono">{label}</p>
    </div>
  );
}
