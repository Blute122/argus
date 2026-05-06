import { useState, useCallback, useRef, useEffect } from 'react';
import { useWebSocket } from '../websocket/useWebSocket';

export default function LogStreamPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(false);

  useEffect(() => { pausedRef.current = paused; }, [paused]);

  const onMsg = useCallback((msg: any) => {
    if (msg.type === 'log' && !pausedRef.current) {
      setLogs((prev) => [msg.data, ...prev].slice(0, 500));
    }
  }, []);

  useWebSocket('logs', { onMessage: onMsg });

  const filtered = filter
    ? logs.filter((l) =>
        JSON.stringify(l).toLowerCase().includes(filter.toLowerCase())
      )
    : logs;

  const sourceClass: Record<string, string> = {
    windows: 'source-windows', linux: 'source-linux', network: 'source-network',
    email: 'source-email', cloud: 'source-cloud', attack_simulation: 'source-network',
  };

  const sevColor: Record<string, string> = {
    critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400',
    low: 'text-blue-400', info: 'text-slate-400',
  };

  return (
    <div className="space-y-4 animate-fade-in h-[calc(100vh-120px)] flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">📜 Live Log Stream</h1>
          <p className="text-sm text-[var(--text-muted)] font-mono">{logs.length} events in buffer</p>
        </div>
        <div className="flex gap-2 items-center">
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter logs..."
            className="input-field w-60 text-sm py-1.5 font-mono"
          />
          <button
            onClick={() => setPaused(!paused)}
            className={`px-4 py-1.5 rounded-lg text-sm font-mono border transition-all ${
              paused
                ? 'border-green-500/50 text-green-400 bg-green-500/10'
                : 'border-red-500/50 text-red-400 bg-red-500/10'
            }`}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button
            onClick={() => setLogs([])}
            className="px-4 py-1.5 rounded-lg text-sm font-mono border border-[var(--border-color)] text-[var(--text-muted)] hover:text-white"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="terminal-panel flex-1 overflow-hidden flex flex-col">
        <div className="terminal-header">
          <div className="dot dot-red" />
          <div className="dot dot-yellow" />
          <div className="dot dot-green" />
          <span className="ml-2 text-[var(--text-muted)] text-xs font-mono">soc-telemetry-stream</span>
          <div className="ml-auto flex items-center gap-2">
            {!paused && <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />}
            <span className="text-xs text-[var(--text-muted)] font-mono">{paused ? 'PAUSED' : 'STREAMING'}</span>
          </div>
        </div>
        <div ref={containerRef} className="flex-1 overflow-y-auto py-1">
          {filtered.map((log, i) => (
            <div key={i} className="log-line">
              <span className="timestamp">
                {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '--:--:--'}
              </span>
              <span className={`source-badge ${sourceClass[log.source] || ''}`}>
                {log.source}
              </span>
              <span className={`text-xs font-mono min-w-[55px] ${sevColor[log.severity] || 'text-slate-400'}`}>
                {log.severity}
              </span>
              <span className="text-xs font-mono text-[var(--text-muted)] min-w-[100px]">
                {log.event_type}
              </span>
              <span className="text-xs font-mono text-[var(--text-secondary)] flex-1 truncate">
                {log.raw_log}
              </span>
              {log.source_ip && (
                <span className="text-[10px] font-mono text-[var(--accent-cyan)]">{log.source_ip}</span>
              )}
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="text-center py-12 text-[var(--text-muted)] font-mono text-sm">
              {paused ? 'Stream paused — click Resume' : 'Waiting for log events...'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
