import { useEffect, useMemo, useState } from 'react';
import {
  attachHuntToIncident,
  createIncidentFromHunt,
  getHuntHistory,
  getIncidents,
  getSavedHunts,
  runHuntQuery,
  saveHunt,
} from '../services/api';

const EXAMPLE_QUERIES = [
  { label: 'Failed Logins', query: 'source=windows AND event_id=4625' },
  { label: 'Encoded PowerShell', query: 'process_name=powershell.exe AND command_line=*enc*' },
  { label: 'C2 or DNS', query: 'event_type=c2_beacon OR dns_query=*c2*' },
  { label: 'Not Info', query: 'NOT severity=info' },
  { label: 'Last 24h Critical', query: 'severity=critical AND earliest=-24h' },
  { label: 'Port 4444', query: 'destination_port=4444' },
  { label: 'Lateral Movement', query: 'event_type=lateral_movement' },
  { label: 'Wildcard Host', query: 'hostname=WS-*' },
];

const FIELD_HINTS = [
  'source', 'event_id', 'event_type', 'severity', 'hostname', 'username', 'process_name',
  'source_ip', 'destination_ip', 'destination_port', 'mitre_technique', 'dns_query',
  'AND', 'OR', 'NOT', 'earliest=-24h', 'latest=2026-06-20T18:00:00',
];

export default function HuntingPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [resultCount, setResultCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<any[]>([]);
  const [saved, setSaved] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [tab, setTab] = useState<'results' | 'history' | 'saved'>('results');
  const [targetIncidentId, setTargetIncidentId] = useState<number | ''>('');
  const [newIncident, setNewIncident] = useState({ title: '', severity: 'medium', description: '' });
  const [workflowMessage, setWorkflowMessage] = useState('');

  useEffect(() => {
    refreshSideData();
  }, []);

  const refreshSideData = () => {
    getHuntHistory().then((r) => setHistory(r.data)).catch(() => {});
    getSavedHunts().then((r) => setSaved(r.data)).catch(() => {});
    getIncidents().then((r) => setIncidents(r.data)).catch(() => {});
  };

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setWorkflowMessage('');
    try {
      const res = await runHuntQuery(query);
      setResults(res.data.results || []);
      setResultCount(res.data.results_count || 0);
      setSelectedIds([]);
      setTab('results');
      refreshSideData();
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (id: number) => {
    await saveHunt(id);
    refreshSideData();
  };

  const selectedLogs = useMemo(() => results.filter((r) => selectedIds.includes(r.id)), [results, selectedIds]);

  const toggleResult = (id: number) => {
    setSelectedIds((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]);
  };

  const selectAllVisible = () => {
    setSelectedIds(results.slice(0, 100).map((r) => r.id));
  };

  const handleCreateIncident = async () => {
    if (!selectedIds.length || !newIncident.title.trim()) return;
    const res = await createIncidentFromHunt({
      query,
      log_ids: selectedIds,
      title: newIncident.title,
      severity: newIncident.severity,
      description: newIncident.description || undefined,
    });
    setWorkflowMessage(`Created INC-${res.data.incident_id} from ${res.data.logs_attached} selected hunt result(s).`);
    setNewIncident({ title: '', severity: 'medium', description: '' });
    setSelectedIds([]);
    refreshSideData();
  };

  const handleAttach = async () => {
    if (!selectedIds.length || !targetIncidentId) return;
    const res = await attachHuntToIncident(Number(targetIncidentId), { query, log_ids: selectedIds });
    setWorkflowMessage(`Attached ${res.data.logs_attached} hunt result(s) to INC-${res.data.incident_id}.`);
    setSelectedIds([]);
    refreshSideData();
  };

  const sevColor: Record<string, string> = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
    info: 'text-slate-400',
  };

  return (
    <div className="space-y-4 animate-fade-in h-[calc(100vh-120px)] flex flex-col">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold">Threat Hunting</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">SPL/KQL-style search with selectable evidence workflow</p>
        </div>
        <div className="text-right text-xs text-[var(--text-muted)] font-mono">
          <p>{selectedIds.length} selected</p>
          <p>{resultCount} matches</p>
        </div>
      </div>

      <div className="flex gap-2">
        <div className="flex-1 relative">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="source=windows AND event_id=4625 NOT username=guest earliest=-24h"
            className="input-field font-mono text-sm pr-20"
          />
          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-[var(--text-muted)] font-mono">ENTER</span>
        </div>
        <button onClick={handleSearch} disabled={loading} className="btn-primary px-6">{loading ? 'Searching...' : 'Hunt'}</button>
      </div>

      <div className="flex flex-wrap gap-2">
        {EXAMPLE_QUERIES.map((eq) => (
          <button key={eq.query} onClick={() => setQuery(eq.query)}
            className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-[var(--bg-card)] border border-[var(--border-color)] text-[var(--text-secondary)] hover:border-[var(--accent-cyan)] hover:text-[var(--accent-cyan)] transition-all">
            {eq.label}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-2 text-[10px] font-mono">
        {FIELD_HINTS.map((hint) => <span key={hint} className="px-2 py-1 rounded bg-[var(--bg-input)] border border-[var(--border-color)] text-[var(--text-muted)]">{hint}</span>)}
      </div>

      {workflowMessage && <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/30 text-sm text-green-400">{workflowMessage}</div>}

      {selectedIds.length > 0 && (
        <div className="grid grid-cols-2 gap-4">
          <div className="glass-card p-4 space-y-2">
            <h3 className="text-sm font-semibold">Create Incident From Hunt</h3>
            <div className="grid grid-cols-[1fr_130px] gap-2">
              <input value={newIncident.title} onChange={(e) => setNewIncident({ ...newIncident, title: e.target.value })} placeholder="Incident title" className="input-field text-sm" />
              <select value={newIncident.severity} onChange={(e) => setNewIncident({ ...newIncident, severity: e.target.value })} className="input-field text-sm">
                <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
              </select>
            </div>
            <textarea value={newIncident.description} onChange={(e) => setNewIncident({ ...newIncident, description: e.target.value })} placeholder="Optional description" className="input-field text-sm h-16 resize-none" />
            <button onClick={handleCreateIncident} className="btn-primary text-sm">Create Case With {selectedIds.length} Logs</button>
          </div>
          <div className="glass-card p-4 space-y-2">
            <h3 className="text-sm font-semibold">Attach Hunt Results To Existing Incident</h3>
            <select value={targetIncidentId} onChange={(e) => setTargetIncidentId(e.target.value ? Number(e.target.value) : '')} className="input-field text-sm">
              <option value="">Select incident...</option>
              {incidents.map((incident) => <option key={incident.id} value={incident.id}>INC-{incident.id} - {incident.title}</option>)}
            </select>
            <p className="text-xs text-[var(--text-muted)]">Selected logs become evidence, with IOCs and MITRE fields merged into the case.</p>
            <button onClick={handleAttach} className="btn-primary text-sm">Attach Evidence</button>
          </div>
        </div>
      )}

      <div className="flex gap-4 border-b border-[var(--border-color)] pb-1">
        {(['results', 'history', 'saved'] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`text-sm font-medium pb-2 transition-all ${tab === t ? 'text-[var(--accent-cyan)] border-b-2 border-[var(--accent-cyan)]' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'}`}>
            {t === 'results' ? `Results (${resultCount})` : t === 'history' ? 'History' : 'Saved'}
          </button>
        ))}
        {tab === 'results' && results.length > 0 && (
          <div className="ml-auto flex gap-2">
            <button onClick={selectAllVisible} className="text-xs text-[var(--accent-cyan)] hover:underline">Select top 100</button>
            <button onClick={() => setSelectedIds([])} className="text-xs text-[var(--text-muted)] hover:underline">Clear</button>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {tab === 'results' && (
          <div className="terminal-panel overflow-hidden">
            <div className="terminal-header">
              <div className="dot dot-red" /><div className="dot dot-yellow" /><div className="dot dot-green" />
              <span className="ml-2 text-xs text-[var(--text-muted)] font-mono">hunt-results - {resultCount} matches - {selectedLogs.length} selected</span>
            </div>
            <div className="overflow-y-auto max-h-[calc(100vh-430px)]">
              {results.length === 0 ? (
                <p className="text-center py-12 text-[var(--text-muted)] font-mono text-sm">No results. Run a hunt query above.</p>
              ) : results.map((r) => (
                <div key={r.id} className={`log-line ${selectedIds.includes(r.id) ? 'bg-cyan-500/10' : ''}`}>
                  <input type="checkbox" checked={selectedIds.includes(r.id)} onChange={() => toggleResult(r.id)} className="mt-0.5" />
                  <span className="timestamp">{r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : ''}</span>
                  <span className={`source-badge source-${r.source}`}>{r.source}</span>
                  <span className={`text-xs font-mono min-w-[55px] ${sevColor[r.severity] || ''}`}>{r.severity}</span>
                  <span className="text-xs font-mono text-[var(--text-muted)] min-w-[100px]">{r.event_type}</span>
                  <span className="text-xs font-mono text-[var(--text-secondary)] flex-1 truncate">{r.raw_log}</span>
                  {r.mitre_technique && <span className="text-[10px] text-purple-400 font-mono">{r.mitre_technique}</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'history' && (
          <div className="space-y-2">
            {history.map((h: any) => (
              <div key={h.id} className="flex items-center gap-3 p-3 glass-card">
                <span className="flex-1 text-sm font-mono text-[var(--text-secondary)] truncate">{h.query}</span>
                <span className="text-xs text-[var(--text-muted)]">{h.results_count} results</span>
                <button onClick={() => { setQuery(h.query); setTab('results'); }} className="text-xs text-[var(--accent-cyan)] hover:underline">Re-run</button>
                <button onClick={() => handleSave(h.id)} className="text-xs text-[var(--accent-green)] hover:underline">Save</button>
              </div>
            ))}
          </div>
        )}

        {tab === 'saved' && (
          <div className="space-y-2">
            {saved.map((s: any) => (
              <div key={s.id} className="flex items-center gap-3 p-3 glass-card">
                <span className="text-sm font-medium">{s.name}</span>
                <span className="flex-1 text-xs font-mono text-[var(--text-muted)] truncate">{s.query}</span>
                <button onClick={() => { setQuery(s.query); setTab('results'); }} className="text-xs text-[var(--accent-cyan)] hover:underline">Run</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
