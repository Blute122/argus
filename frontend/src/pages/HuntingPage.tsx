import { useState, useEffect } from 'react';
import { runHuntQuery, getHuntHistory, getSavedHunts, saveHunt } from '../services/api';

const EXAMPLE_QUERIES = [
  { label: 'Failed Logins (Win)', query: 'source=windows event_id=4625' },
  { label: 'PowerShell Exec', query: 'process_name=powershell.exe' },
  { label: 'Port 4444 Activity', query: 'destination_port=4444' },
  { label: 'SSH Brute Force', query: 'source=linux event_type=ssh_failed_login' },
  { label: 'C2 Beacons', query: 'event_type=c2_beacon' },
  { label: 'Critical Severity', query: 'severity=critical' },
  { label: 'Lateral Movement', query: 'event_type=lateral_movement' },
  { label: 'DNS to Malicious', query: 'source=network event_type=dns_query' },
];

export default function HuntingPage() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<any[]>([]);
  const [resultCount, setResultCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<any[]>([]);
  const [saved, setSaved] = useState<any[]>([]);
  const [tab, setTab] = useState<'results' | 'history' | 'saved'>('results');

  useEffect(() => {
    getHuntHistory().then((r) => setHistory(r.data)).catch(() => {});
    getSavedHunts().then((r) => setSaved(r.data)).catch(() => {});
  }, []);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await runHuntQuery(query);
      setResults(res.data.results || []);
      setResultCount(res.data.results_count || 0);
      setTab('results');
      // Refresh history
      getHuntHistory().then((r) => setHistory(r.data)).catch(() => {});
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (id: number) => {
    await saveHunt(id);
    getSavedHunts().then((r) => setSaved(r.data)).catch(() => {});
  };

  const sevColor: Record<string, string> = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400',
    low: 'text-blue-400', info: 'text-slate-400',
  };

  return (
    <div className="space-y-4 animate-fade-in h-[calc(100vh-120px)] flex flex-col">
      <div>
        <h1 className="text-2xl font-bold">🔍 Threat Hunting</h1>
        <p className="text-sm text-[var(--text-muted)] font-mono">Query-based log search — Splunk-like syntax</p>
      </div>

      {/* Search bar */}
      <div className="flex gap-2">
        <div className="flex-1 relative">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="source=windows eventid=4625 username=admin"
            className="input-field font-mono text-sm pr-20"
          />
          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-[var(--text-muted)] font-mono">
            ENTER ↵
          </span>
        </div>
        <button onClick={handleSearch} disabled={loading} className="btn-primary px-6">
          {loading ? 'Searching...' : 'Hunt'}
        </button>
      </div>

      {/* Quick queries */}
      <div className="flex flex-wrap gap-2">
        {EXAMPLE_QUERIES.map((eq) => (
          <button
            key={eq.query}
            onClick={() => { setQuery(eq.query); }}
            className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-[var(--bg-card)] border border-[var(--border-color)] text-[var(--text-secondary)] hover:border-[var(--accent-cyan)] hover:text-[var(--accent-cyan)] transition-all"
          >
            {eq.label}
          </button>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-4 border-b border-[var(--border-color)] pb-1">
        {(['results', 'history', 'saved'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`text-sm font-medium pb-2 transition-all ${
              tab === t
                ? 'text-[var(--accent-cyan)] border-b-2 border-[var(--accent-cyan)]'
                : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
            }`}
          >
            {t === 'results' ? `Results (${resultCount})` : t === 'history' ? 'History' : 'Saved'}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {tab === 'results' && (
          <div className="terminal-panel overflow-hidden">
            <div className="terminal-header">
              <div className="dot dot-red" /><div className="dot dot-yellow" /><div className="dot dot-green" />
              <span className="ml-2 text-xs text-[var(--text-muted)] font-mono">hunt-results — {resultCount} matches</span>
            </div>
            <div className="overflow-y-auto max-h-[calc(100vh-400px)]">
              {results.length === 0 ? (
                <p className="text-center py-12 text-[var(--text-muted)] font-mono text-sm">
                  No results — enter a query above
                </p>
              ) : results.map((r, i) => (
                <div key={i} className="log-line">
                  <span className="timestamp">{r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : ''}</span>
                  <span className={`source-badge source-${r.source}`}>{r.source}</span>
                  <span className={`text-xs font-mono min-w-[55px] ${sevColor[r.severity] || ''}`}>{r.severity}</span>
                  <span className="text-xs font-mono text-[var(--text-secondary)] flex-1 truncate">{r.raw_log}</span>
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
