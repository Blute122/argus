import { useEffect, useState, useCallback, useRef } from 'react';
import ReactECharts from 'echarts-for-react';
import { getDashboardStats } from '../services/api';
import { useWebSocket } from '../websocket/useWebSocket';

type Stats = {
  total_logs: number;
  total_alerts: number;
  active_alerts: number;
  critical_alerts: number;
  severity_distribution: Record<string, number>;
  source_distribution: Record<string, number>;
  top_attackers: { ip: string; count: number }[];
  eps?: number;
  ws_connections?: number;
};

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [eps, setEps] = useState(0);
  const logCountRef = useRef(0);

  // Fetch initial stats
  useEffect(() => {
    getDashboardStats().then((res) => setStats(res.data)).catch(() => {});
    const interval = setInterval(() => {
      getDashboardStats().then((res) => setStats(res.data)).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // WebSocket for real-time updates
  const onDashboardMsg = useCallback((msg: any) => {
    if (msg.type === 'stats') {
      setStats((prev) => ({ ...prev, ...msg.data }));
      if (msg.data.eps) setEps(msg.data.eps);
    }
    if (msg.type === 'alert') {
      setRecentAlerts((prev) => [msg.data, ...prev].slice(0, 20));
    }
  }, []);

  useWebSocket('dashboard', { onMessage: onDashboardMsg });

  // EPS counter from log stream
  const onLogMsg = useCallback(() => {
    logCountRef.current++;
  }, []);
  useWebSocket('logs', { onMessage: onLogMsg });

  useEffect(() => {
    const interval = setInterval(() => {
      setEps(logCountRef.current);
      logCountRef.current = 0;
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Chart options
  const severityChartOption = {
    tooltip: { trigger: 'item', backgroundColor: '#1a2235', borderColor: '#1e3a5f', textStyle: { color: '#e2e8f0' } },
    series: [{
      type: 'pie', radius: ['50%', '75%'], center: ['50%', '50%'],
      itemStyle: { borderRadius: 6, borderColor: '#0a0e17', borderWidth: 2 },
      label: { show: true, color: '#94a3b8', fontSize: 11 },
      data: [
        { value: stats?.severity_distribution?.critical || 0, name: 'Critical', itemStyle: { color: '#ef4444' } },
        { value: stats?.severity_distribution?.high || 0, name: 'High', itemStyle: { color: '#f97316' } },
        { value: stats?.severity_distribution?.medium || 0, name: 'Medium', itemStyle: { color: '#f59e0b' } },
        { value: stats?.severity_distribution?.low || 0, name: 'Low', itemStyle: { color: '#3b82f6' } },
      ],
    }],
  };

  const sourceChartOption = {
    tooltip: { trigger: 'axis', backgroundColor: '#1a2235', borderColor: '#1e3a5f', textStyle: { color: '#e2e8f0' } },
    xAxis: {
      type: 'category',
      data: Object.keys(stats?.source_distribution || {}),
      axisLabel: { color: '#64748b', fontSize: 10 },
      axisLine: { lineStyle: { color: '#1e3a5f' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#64748b', fontSize: 10 },
      splitLine: { lineStyle: { color: '#1e3a5f', type: 'dashed' } },
    },
    series: [{
      type: 'bar', barWidth: '60%',
      data: Object.values(stats?.source_distribution || {}).map((v, i) => ({
        value: v,
        itemStyle: {
          color: ['#3b82f6', '#f97316', '#8b5cf6', '#10b981', '#06b6d4'][i % 5],
          borderRadius: [4, 4, 0, 0],
        },
      })),
    }],
    grid: { left: 40, right: 20, top: 10, bottom: 30 },
  };

  const topAttackersOption = {
    tooltip: { trigger: 'axis', backgroundColor: '#1a2235', borderColor: '#1e3a5f', textStyle: { color: '#e2e8f0' } },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#64748b', fontSize: 10 },
      splitLine: { lineStyle: { color: '#1e3a5f', type: 'dashed' } },
    },
    yAxis: {
      type: 'category',
      data: (stats?.top_attackers || []).slice(0, 8).map((a) => a.ip).reverse(),
      axisLabel: { color: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
      axisLine: { lineStyle: { color: '#1e3a5f' } },
    },
    series: [{
      type: 'bar', barWidth: '60%',
      data: (stats?.top_attackers || []).slice(0, 8).map((a) => a.count).reverse(),
      itemStyle: { color: '#ef4444', borderRadius: [0, 4, 4, 0] },
    }],
    grid: { left: 120, right: 20, top: 10, bottom: 20 },
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">SOC Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">Security Operations Center — Live Overview</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/30">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs text-green-400 font-mono">LIVE</span>
          </div>
          <div className="px-3 py-1.5 rounded-lg bg-[var(--bg-card)] border border-[var(--border-color)]">
            <span className="text-xs text-[var(--text-muted)] font-mono">EPS: </span>
            <span className="text-sm text-[var(--accent-cyan)] font-mono font-bold">{eps}</span>
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="stat-value">{(stats?.total_logs || 0).toLocaleString()}</div>
          <div className="stat-label">Total Events</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-amber-400" style={{ background: 'linear-gradient(135deg, #f59e0b, #f97316)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            {stats?.total_alerts || 0}
          </div>
          <div className="stat-label">Total Alerts</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ background: 'linear-gradient(135deg, #ef4444, #dc2626)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            {stats?.active_alerts || 0}
          </div>
          <div className="stat-label">Active Alerts</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ background: 'linear-gradient(135deg, #ef4444, #b91c1c)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            {stats?.critical_alerts || 0}
          </div>
          <div className="stat-label">Critical</div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="glass-card p-4">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Alert Severity Distribution</h3>
          <ReactECharts option={severityChartOption} style={{ height: 220 }} />
        </div>
        <div className="glass-card p-4">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Events by Source</h3>
          <ReactECharts option={sourceChartOption} style={{ height: 220 }} />
        </div>
        <div className="glass-card p-4">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Top Attackers</h3>
          <ReactECharts option={topAttackersOption} style={{ height: 220 }} />
        </div>
      </div>

      {/* Recent alerts feed */}
      <div className="glass-card p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">🚨 Live Alert Feed</h3>
          <span className="text-xs text-[var(--text-muted)] font-mono">{recentAlerts.length} recent</span>
        </div>
        <div className="space-y-2 max-h-[300px] overflow-y-auto">
          {recentAlerts.length === 0 && (
            <p className="text-center text-[var(--text-muted)] text-sm py-8 font-mono">Waiting for alerts...</p>
          )}
          {recentAlerts.map((alert, i) => (
            <div
              key={i}
              className="flex items-center gap-3 p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)] animate-slide-in"
            >
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded severity-${alert.severity}`}>
                {alert.severity?.toUpperCase()}
              </span>
              <span className="flex-1 text-sm text-[var(--text-primary)] truncate">{alert.title}</span>
              {alert.mitre_technique && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">
                  {alert.mitre_technique}
                </span>
              )}
              <span className="text-xs text-[var(--text-muted)] font-mono">{alert.source_ip}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
