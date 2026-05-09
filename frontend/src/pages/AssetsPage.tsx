import { useCallback, useEffect, useMemo, useState } from 'react';
import ReactECharts from 'echarts-for-react';
import { createAsset, getAssetStats, getAssets, updateAsset } from '../services/api';

type Vulnerability = {
  id: number;
  cve_id?: string;
  title: string;
  severity: string;
  cvss_score?: string;
  status: string;
};

type Asset = {
  id: number;
  hostname: string;
  ip_address: string;
  asset_type: string;
  operating_system?: string;
  owner?: string;
  business_unit?: string;
  criticality: string;
  risk_score: number;
  status: string;
  location?: string;
  last_seen?: string;
  alert_count: number;
  log_count: number;
  notes?: string;
  vulnerabilities?: Vulnerability[];
};

const emptyForm = {
  hostname: '',
  ip_address: '',
  asset_type: 'workstation',
  operating_system: '',
  owner: '',
  business_unit: '',
  criticality: 'medium',
  risk_score: 30,
  status: 'online',
  location: '',
  notes: '',
};

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [query, setQuery] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState(emptyForm);

  const loadAssets = useCallback(() => {
    const params = query ? { query } : undefined;
    getAssets(params).then((r) => setAssets(r.data)).catch(() => { });
    getAssetStats().then((r) => setStats(r.data)).catch(() => { });
  }, [query]);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const handleCreate = async () => {
    await createAsset(form);
    setForm(emptyForm);
    setShowCreate(false);
    loadAssets();
  };

  const handleStatus = async (asset: Asset, status: string) => {
    const res = await updateAsset(asset.id, { status });
    setSelected(res.data);
    loadAssets();
  };

  const statusColors: Record<string, string> = {
    online: 'status-resolved',
    degraded: 'status-investigating',
    isolated: 'severity-critical',
    offline: 'status-closed',
  };

  const criticalityColors: Record<string, string> = {
    critical: 'severity-critical',
    high: 'severity-high',
    medium: 'severity-medium',
    low: 'severity-low',
  };

  const riskChart = useMemo(() => ({
    tooltip: { trigger: 'axis', backgroundColor: '#1a2235', borderColor: '#1e3a5f', textStyle: { color: '#e2e8f0' } },
    xAxis: {
      type: 'category',
      data: assets.slice(0, 10).map((a) => a.hostname),
      axisLabel: { color: '#94a3b8', fontSize: 10, rotate: 25 },
      axisLine: { lineStyle: { color: '#1e3a5f' } },
    },
    yAxis: {
      type: 'value',
      max: 100,
      axisLabel: { color: '#64748b', fontSize: 10 },
      splitLine: { lineStyle: { color: '#1e3a5f', type: 'dashed' } },
    },
    series: [{
      type: 'bar',
      data: assets.slice(0, 10).map((asset) => ({
        value: asset.risk_score,
        itemStyle: { color: asset.risk_score >= 70 ? '#ef4444' : asset.risk_score >= 50 ? '#f59e0b' : '#06b6d4', borderRadius: [4, 4, 0, 0] },
      })),
    }],
    grid: { left: 35, right: 10, top: 10, bottom: 60 },
  }), [assets]);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Asset Inventory</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">Endpoint and infrastructure context for investigations</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary">+ Add Asset</button>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="stat-card"><div className="stat-value">{stats?.total || 0}</div><div className="stat-label">Tracked Assets</div></div>
        <div className="stat-card"><div className="stat-value text-red-400">{stats?.high_risk || 0}</div><div className="stat-label">High Risk</div></div>
        <div className="stat-card"><div className="stat-value text-purple-400">{stats?.isolated || 0}</div><div className="stat-label">Isolated</div></div>
        <div className="stat-card"><div className="stat-value text-emerald-400">{stats?.by_status?.online || 0}</div><div className="stat-label">Online</div></div>
      </div>

      {showCreate && (
        <div className="glass-card p-5 space-y-3">
          <h3 className="text-lg font-bold">Register Asset</h3>
          <div className="grid grid-cols-3 gap-2">
            <input value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} placeholder="Hostname" className="input-field" />
            <input value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} placeholder="IP address" className="input-field" />
            <select value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value })} className="input-field">
              <option value="workstation">Workstation</option><option value="server">Server</option>
              <option value="domain_controller">Domain Controller</option><option value="cloud">Cloud</option>
              <option value="network">Network</option>
            </select>
          </div>
          <div className="grid grid-cols-4 gap-2">
            <input value={form.operating_system} onChange={(e) => setForm({ ...form, operating_system: e.target.value })} placeholder="Operating system" className="input-field" />
            <input value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} placeholder="Owner" className="input-field" />
            <select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })} className="input-field">
              <option value="critical">Critical</option><option value="high">High</option>
              <option value="medium">Medium</option><option value="low">Low</option>
            </select>
            <input type="number" min="0" max="100" value={form.risk_score} onChange={(e) => setForm({ ...form, risk_score: Number(e.target.value) })} className="input-field" />
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} className="btn-primary">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg border border-[var(--border-color)] text-[var(--text-muted)]">Cancel</button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-[1fr_390px] gap-4">
        <div className="space-y-4">
          <div className="glass-card p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold">Risk Score by Asset</h3>
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search hostname, IP, owner..." className="input-field w-72 text-sm py-1.5" />
            </div>
            <ReactECharts option={riskChart} style={{ height: 240 }} />
          </div>

          <div className="space-y-2 max-h-[calc(100vh-530px)] overflow-y-auto pr-2">
            {assets.map((asset) => (
              <div key={asset.id} onClick={() => setSelected(asset)} className={`glass-card p-4 cursor-pointer ${selected?.id === asset.id ? 'border-[var(--accent-cyan)]' : ''}`}>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${criticalityColors[asset.criticality]}`}>{asset.criticality.toUpperCase()}</span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${statusColors[asset.status]}`}>{asset.status.toUpperCase()}</span>
                  <span className="text-sm font-semibold flex-1">{asset.hostname}</span>
                  <span className="text-xs text-[var(--accent-cyan)] font-mono">{asset.ip_address}</span>
                  <span className="text-xs font-mono text-red-400">Risk {asset.risk_score}</span>
                </div>
                <div className="grid grid-cols-4 gap-2 text-xs text-[var(--text-secondary)]">
                  <span>{asset.asset_type}</span><span>{asset.operating_system || 'Unknown OS'}</span>
                  <span>{asset.owner || 'Unassigned'}</span>
                  <span className="flex items-center gap-1">
                    {asset.vulnerabilities && asset.vulnerabilities.length > 0 && <span title="Vulnerabilities Found">⚠️ {asset.vulnerabilities.length}</span>}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {selected ? (
          <div className="glass-card p-5 self-start animate-slide-in">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold">{selected.hostname}</h3>
              <span className="text-xs font-mono text-[var(--accent-cyan)]">{selected.ip_address}</span>
            </div>
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div><label className="text-xs text-[var(--text-muted)] font-mono">TYPE</label><p>{selected.asset_type}</p></div>
                <div><label className="text-xs text-[var(--text-muted)] font-mono">OS</label><p>{selected.operating_system || 'Unknown'}</p></div>
                <div><label className="text-xs text-[var(--text-muted)] font-mono">OWNER</label><p>{selected.owner || 'Unassigned'}</p></div>
                <div><label className="text-xs text-[var(--text-muted)] font-mono">LOCATION</label><p>{selected.location || 'Unknown'}</p></div>
              </div>
              <div className="p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)]">
                <label className="text-xs text-[var(--text-muted)] font-mono">INVESTIGATION CONTEXT</label>
                <p className="text-sm mt-1">{selected.alert_count} related alerts and {selected.log_count} telemetry events.</p>
              </div>

              {selected.vulnerabilities && selected.vulnerabilities.length > 0 && (
                <div className="mt-4">
                  <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">KNOWN VULNERABILITIES</label>
                  <div className="space-y-2 max-h-[150px] overflow-y-auto pr-1">
                    {selected.vulnerabilities.map(v => (
                      <div key={v.id} className="p-2 rounded border border-[var(--border-color)] bg-[var(--bg-darker)] text-xs">
                        <div className="flex justify-between mb-1">
                          <span className={`font-mono font-bold ${v.severity === 'critical' ? 'text-red-500' : v.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'}`}>{v.cve_id || 'Vuln'} - {v.title}</span>
                          {v.cvss_score && <span className="text-[var(--text-muted)]">CVSS: {v.cvss_score}</span>}
                        </div>
                        <span className={`text-[10px] px-1 rounded ${v.status === 'open' ? 'bg-red-900/30 text-red-400' : 'bg-green-900/30 text-green-400'}`}>{v.status.toUpperCase()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-4">
                <label className="text-xs text-[var(--text-muted)] font-mono mb-2 block">CONTAINMENT</label>
                <div className="flex flex-wrap gap-2">
                  {['online', 'degraded', 'isolated', 'offline'].map((status) => (
                    <button key={status} onClick={() => handleStatus(selected, status)}
                      className={`text-[10px] font-mono px-2 py-1 rounded border ${selected.status === status ? 'border-[var(--accent-cyan)] text-[var(--accent-cyan)]' : 'border-[var(--border-color)] text-[var(--text-muted)]'}`}>
                      {status.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="glass-card p-5 text-sm text-[var(--text-muted)] font-mono">Select an asset to view investigation context.</div>
        )}
      </div>
    </div>
  );
}