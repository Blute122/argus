import { useEffect, useState } from 'react';
import { getIncidentReport, getIncidents } from '../services/api';

export default function ReportsPage() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<number | ''>('');
  const [report, setReport] = useState('');
  const [jsonReport, setJsonReport] = useState<any>(null);
  const [view, setView] = useState<'markdown' | 'json'>('markdown');

  useEffect(() => {
    getIncidents().then((r) => setIncidents(r.data)).catch(() => {});
  }, []);

  const generateReport = async () => {
    if (!selectedId) return;
    const res = await getIncidentReport(Number(selectedId), view);
    if (view === 'json') {
      setJsonReport(res.data);
      setReport('');
    } else {
      setReport(res.data.content || '');
      setJsonReport(null);
    }
  };

  const selectedIncident = incidents.find((incident) => incident.id === selectedId);

  return (
    <div className="space-y-4 animate-fade-in h-[calc(100vh-120px)] flex flex-col">
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-sm text-[var(--text-muted)] font-mono">Generate analyst-ready incident reports from case data, evidence, alerts, IOCs, and timeline notes</p>
      </div>

      <div className="glass-card p-4 flex items-end gap-3">
        <div className="flex-1">
          <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">INCIDENT</label>
          <select value={selectedId} onChange={(e) => setSelectedId(e.target.value ? Number(e.target.value) : '')} className="input-field">
            <option value="">Select incident...</option>
            {incidents.map((incident) => (
              <option key={incident.id} value={incident.id}>INC-{incident.id} - {incident.title}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">FORMAT</label>
          <select value={view} onChange={(e) => setView(e.target.value as 'markdown' | 'json')} className="input-field w-40">
            <option value="markdown">Markdown</option>
            <option value="json">JSON</option>
          </select>
        </div>
        <button onClick={generateReport} className="btn-primary">Generate</button>
      </div>

      {selectedIncident && (
        <div className="grid grid-cols-4 gap-4">
          <div className="stat-card"><div className="stat-value">INC-{selectedIncident.id}</div><div className="stat-label">Case</div></div>
          <div className="stat-card"><div className="stat-value text-red-400">{selectedIncident.severity}</div><div className="stat-label">Severity</div></div>
          <div className="stat-card"><div className="stat-value text-cyan-400">{selectedIncident.status}</div><div className="stat-label">Status</div></div>
          <div className="stat-card"><div className="stat-value text-purple-400">{selectedIncident.alert_count || 0}</div><div className="stat-label">Alerts</div></div>
        </div>
      )}

      <div className="terminal-panel flex-1 overflow-hidden flex flex-col">
        <div className="terminal-header">
          <div className="dot dot-red" /><div className="dot dot-yellow" /><div className="dot dot-green" />
          <span className="ml-2 text-xs text-[var(--text-muted)] font-mono">incident-report-output</span>
        </div>
        <div className="flex-1 overflow-y-auto p-5">
          {!report && !jsonReport && (
            <p className="text-center py-16 text-[var(--text-muted)] font-mono text-sm">Select an incident and generate a report.</p>
          )}
          {report && <pre className="whitespace-pre-wrap text-sm leading-6 text-[var(--text-secondary)]">{report}</pre>}
          {jsonReport && <pre className="whitespace-pre-wrap text-xs leading-5 text-[var(--text-secondary)]">{JSON.stringify(jsonReport, null, 2)}</pre>}
        </div>
      </div>
    </div>
  );
}
