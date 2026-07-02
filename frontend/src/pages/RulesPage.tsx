import { useCallback, useEffect, useMemo, useState } from 'react';
import { useAuth } from '../store/AuthContext';
import {
  getDetectionRules, getDetectionRule, enableDetectionRule,
  disableDetectionRule, testDetectionRule,
} from '../services/api';

type Rule = {
  id: string;
  title: string;
  description?: string;
  rule_type: string;
  severity: string;
  mitre_technique?: string;
  tags: string[];
  source: string;
  enabled: boolean;
  match_count: number;
  last_fired_at?: string | null;
};

const severityColors: Record<string, string> = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  info: 'status-closed',
};

export default function RulesPage() {
  const { user } = useAuth();
  const canManage = user?.role === 'admin' || user?.role === 'threat_hunter';
  const [rules, setRules] = useState<Rule[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<any>(null);
  const [testResult, setTestResult] = useState<any>(null);
  const [filter, setFilter] = useState('');

  const load = useCallback(() => {
    getDetectionRules().then((r) => setRules(r.data)).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!selected) { setDetail(null); return; }
    setTestResult(null);
    getDetectionRule(selected).then((r) => setDetail(r.data)).catch(() => {});
  }, [selected]);

  const toggle = async (rule: Rule) => {
    if (!canManage) return;
    if (rule.enabled) await disableDetectionRule(rule.id);
    else await enableDetectionRule(rule.id);
    load();
  };

  const runTest = async (id: string) => {
    setTestResult({ loading: true });
    try {
      const r = await testDetectionRule(id);
      setTestResult(r.data);
    } catch {
      setTestResult({ error: true });
    }
  };

  const filtered = useMemo(() => {
    const q = filter.toLowerCase();
    return rules.filter((r) =>
      !q || r.title.toLowerCase().includes(q) || (r.mitre_technique || '').toLowerCase().includes(q)
      || r.tags.some((t) => t.toLowerCase().includes(q)));
  }, [rules, filter]);

  const stats = useMemo(() => ({
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    threshold: rules.filter((r) => r.rule_type === 'threshold').length,
    firing: rules.filter((r) => r.match_count > 0).length,
  }), [rules]);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Detection Rules</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">Sigma-style rules evaluated on every event and on a schedule</p>
        </div>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by title, technique, tag..." className="input-field w-80 text-sm py-1.5" />
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="stat-card"><div className="stat-value">{stats.total}</div><div className="stat-label">Total Rules</div></div>
        <div className="stat-card"><div className="stat-value text-emerald-400">{stats.enabled}</div><div className="stat-label">Enabled</div></div>
        <div className="stat-card"><div className="stat-value text-cyan-400">{stats.threshold}</div><div className="stat-label">Scheduled</div></div>
        <div className="stat-card"><div className="stat-value text-orange-400">{stats.firing}</div><div className="stat-label">Have Fired</div></div>
      </div>

      <div className="grid grid-cols-[1fr_420px] gap-4">
        <div className="space-y-2 max-h-[calc(100vh-320px)] overflow-y-auto pr-2">
          {filtered.map((rule) => (
            <div key={rule.id} onClick={() => setSelected(rule.id)}
              className={`glass-card p-4 cursor-pointer ${selected === rule.id ? 'border-[var(--accent-cyan)]' : ''} ${!rule.enabled ? 'opacity-60' : ''}`}>
              <div className="flex items-center gap-2 mb-2">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${severityColors[rule.severity] || 'status-closed'}`}>{rule.severity.toUpperCase()}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border-color)] text-[var(--text-muted)]">{rule.rule_type === 'threshold' ? 'SCHEDULED' : 'STREAMING'}</span>
                <span className="text-sm font-semibold flex-1">{rule.title}</span>
                {rule.mitre_technique && <span className="text-xs text-[var(--accent-cyan)] font-mono">{rule.mitre_technique}</span>}
                <button onClick={(e) => { e.stopPropagation(); toggle(rule); }} disabled={!canManage}
                  title={!canManage ? 'Only admins / threat hunters can toggle rules' : ''}
                  className={`text-[10px] font-mono px-2 py-1 rounded border ${!canManage ? 'opacity-50 cursor-not-allowed' : ''} ${rule.enabled ? 'border-emerald-500 text-emerald-400' : 'border-[var(--border-color)] text-[var(--text-muted)]'}`}>
                  {rule.enabled ? 'ENABLED' : 'DISABLED'}
                </button>
              </div>
              <div className="flex items-center justify-between text-xs text-[var(--text-secondary)]">
                <span className="truncate pr-2">{rule.description}</span>
                <span className="font-mono whitespace-nowrap text-[var(--text-muted)]">fired {rule.match_count}×</span>
              </div>
            </div>
          ))}
          {filtered.length === 0 && <div className="glass-card p-5 text-sm text-[var(--text-muted)] font-mono">No rules match the filter.</div>}
        </div>

        {detail ? (
          <div className="glass-card p-5 self-start animate-slide-in">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-lg font-bold">{detail.title}</h3>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${severityColors[detail.severity] || 'status-closed'}`}>{detail.severity.toUpperCase()}</span>
            </div>
            <div className="space-y-3 text-sm">
              <p className="text-[var(--text-secondary)]">{detail.description}</p>
              <div className="grid grid-cols-2 gap-2">
                <div><label className="text-xs text-[var(--text-muted)] font-mono">TYPE</label><p>{detail.rule_type}</p></div>
                <div><label className="text-xs text-[var(--text-muted)] font-mono">TECHNIQUE</label><p>{detail.mitre_technique || '—'}</p></div>
                <div><label className="text-xs text-[var(--text-muted)] font-mono">SOURCE</label><p>{detail.source}</p></div>
                <div><label className="text-xs text-[var(--text-muted)] font-mono">TIMES FIRED</label><p>{detail.match_count}</p></div>
              </div>
              {detail.tags?.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {detail.tags.map((t: string) => (
                    <span key={t} className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--bg-input)] border border-[var(--border-color)] text-[var(--text-muted)]">{t}</span>
                  ))}
                </div>
              )}
              {detail.yaml && (
                <div>
                  <label className="text-xs text-[var(--text-muted)] font-mono mb-1 block">RULE DEFINITION</label>
                  <pre className="text-[11px] font-mono bg-[var(--bg-darker)] border border-[var(--border-color)] rounded p-3 overflow-x-auto whitespace-pre">{detail.yaml}</pre>
                </div>
              )}
              <div>
                <button onClick={() => runTest(detail.id)} disabled={!canManage} className="btn-primary text-xs py-1.5">Test against recent logs</button>
                {testResult && !testResult.loading && !testResult.error && (
                  <div className="mt-2 p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)] text-xs">
                    <p className="font-mono">
                      {testResult.type === 'threshold'
                        ? `${testResult.matches} group(s) over threshold`
                        : `${testResult.matches} match(es) in ${testResult.scanned} recent logs`}
                    </p>
                  </div>
                )}
                {testResult?.loading && <p className="mt-2 text-xs text-[var(--text-muted)] font-mono">Running…</p>}
                {testResult?.error && <p className="mt-2 text-xs text-red-400 font-mono">Test failed.</p>}
              </div>
            </div>
          </div>
        ) : (
          <div className="glass-card p-5 text-sm text-[var(--text-muted)] font-mono">Select a rule to view its definition and test it.</div>
        )}
      </div>
    </div>
  );
}
