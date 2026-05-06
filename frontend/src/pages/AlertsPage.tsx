import { useEffect, useState, useCallback } from 'react';
import { getAlerts, updateAlertStatus } from '../services/api';
import { useWebSocket } from '../websocket/useWebSocket';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [filter, setFilter] = useState({ severity: '', status: '' });
  const [selected, setSelected] = useState<any>(null);

  const loadAlerts = useCallback(() => {
    const params: any = { limit: 200 };
    if (filter.severity) params.severity = filter.severity;
    if (filter.status) params.status = filter.status;
    getAlerts(params).then((r) => setAlerts(r.data)).catch(() => {});
  }, [filter]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const onWsMsg = useCallback((msg: any) => {
    if (msg.type === 'alert') {
      setAlerts((prev) => [msg.data, ...prev].slice(0, 200));
    }
  }, []);
  useWebSocket('alerts', { onMessage: onWsMsg });

  const handleStatusChange = async (id: number, status: string) => {
    await updateAlertStatus(id, status);
    loadAlerts();
  };

  const sevColors: Record<string, string> = {
    critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low', info: 'severity-info',
  };

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">🚨 Security Alerts</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">Correlated alert management — {alerts.length} alerts</p>
        </div>
        <div className="flex gap-2">
          <select value={filter.severity} onChange={(e) => setFilter({...filter, severity: e.target.value})}
            className="input-field w-auto text-sm py-1.5 px-3">
            <option value="">All Severity</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={filter.status} onChange={(e) => setFilter({...filter, status: e.target.value})}
            className="input-field w-auto text-sm py-1.5 px-3">
            <option value="">All Status</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      <div className="flex gap-4">
        {/* Alert list */}
        <div className="flex-1 space-y-2 max-h-[calc(100vh-180px)] overflow-y-auto pr-2">
          {alerts.map((alert, i) => (
            <div
              key={alert.id || i}
              onClick={() => setSelected(alert)}
              className={`glass-card p-4 cursor-pointer transition-all ${selected?.id === alert.id ? 'border-[var(--accent-cyan)]' : ''}`}
            >
              <div className="flex items-center gap-3 mb-2">
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${sevColors[alert.severity] || 'severity-info'}`}>
                  {alert.severity?.toUpperCase()}
                </span>
                <span className="flex-1 text-sm font-medium truncate">{alert.title}</span>
                <span className="text-[10px] font-mono text-[var(--text-muted)]">
                  {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ''}
                </span>
              </div>
              <p className="text-xs text-[var(--text-secondary)] truncate">{alert.description}</p>
              <div className="flex items-center gap-2 mt-2">
                {alert.mitre_technique && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400">
                    {alert.mitre_technique}
                  </span>
                )}
                {alert.source_ip && (
                  <span className="text-[10px] font-mono text-[var(--text-muted)]">SRC: {alert.source_ip}</span>
                )}
                {alert.rule_name && (
                  <span className="text-[10px] font-mono text-[var(--accent-cyan)]">Rule: {alert.rule_name}</span>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="w-[380px] glass-card p-5 max-h-[calc(100vh-180px)] overflow-y-auto animate-slide-in">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold">Alert Details</h3>
              <button onClick={() => setSelected(null)} className="text-[var(--text-muted)] hover:text-white text-lg">✕</button>
            </div>
            <div className="space-y-3 text-sm">
              <div>
                <span className={`text-xs font-bold px-2 py-1 rounded ${sevColors[selected.severity]}`}>{selected.severity?.toUpperCase()}</span>
              </div>
              <div><label className="text-[var(--text-muted)] text-xs font-mono">TITLE</label><p className="font-medium">{selected.title}</p></div>
              <div><label className="text-[var(--text-muted)] text-xs font-mono">DESCRIPTION</label><p className="text-[var(--text-secondary)]">{selected.description}</p></div>
              <div className="grid grid-cols-2 gap-2">
                <div><label className="text-[var(--text-muted)] text-xs font-mono">SOURCE IP</label><p className="font-mono text-[var(--accent-cyan)]">{selected.source_ip || 'N/A'}</p></div>
                <div><label className="text-[var(--text-muted)] text-xs font-mono">DEST IP</label><p className="font-mono">{selected.destination_ip || 'N/A'}</p></div>
              </div>
              <div><label className="text-[var(--text-muted)] text-xs font-mono">RULE</label><p>{selected.rule_name}</p></div>
              {selected.mitre_technique && (
                <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30">
                  <label className="text-purple-400 text-xs font-mono">MITRE ATT&CK</label>
                  <p className="text-purple-300 font-medium">{selected.mitre_technique} — {selected.mitre_technique_name}</p>
                  <p className="text-xs text-[var(--text-muted)] mt-1">{selected.mitre_tactic}</p>
                </div>
              )}
              {selected.recommended_action && (
                <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30">
                  <label className="text-cyan-400 text-xs font-mono">RECOMMENDED ACTION</label>
                  <p className="text-sm text-[var(--text-secondary)]">{selected.recommended_action}</p>
                </div>
              )}
              <div className="flex gap-2 mt-4">
                <button onClick={() => handleStatusChange(selected.id, 'investigating')} className="btn-primary text-xs py-2 px-3">Investigate</button>
                <button onClick={() => handleStatusChange(selected.id, 'resolved')} className="btn-primary text-xs py-2 px-3 !bg-gradient-to-r !from-green-600 !to-emerald-600">Resolve</button>
                <button onClick={() => handleStatusChange(selected.id, 'false_positive')} className="text-xs py-2 px-3 rounded-lg border border-[var(--border-color)] text-[var(--text-muted)] hover:border-[var(--text-muted)]">False +</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
