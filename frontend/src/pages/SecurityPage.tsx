import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../store/AuthContext';
import { getMe, enrollMfa, activateMfa, disableMfa, getAuditLog } from '../services/api';

type AuditEntry = {
  id: number;
  timestamp: string;
  actor: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  detail: string | null;
  source_ip: string | null;
  outcome: string;
};

export default function SecurityPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [enroll, setEnroll] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [msg, setMsg] = useState<string | null>(null);

  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [actionFilter, setActionFilter] = useState('');

  const refreshMe = useCallback(() => {
    getMe().then((r) => setMfaEnabled(r.data.mfa_enabled)).catch(() => {});
  }, []);

  const loadAudit = useCallback(() => {
    if (!isAdmin) return;
    const params = actionFilter ? { action: actionFilter } : undefined;
    getAuditLog(params).then((r) => setAudit(r.data)).catch(() => {});
  }, [isAdmin, actionFilter]);

  useEffect(() => { refreshMe(); }, [refreshMe]);
  useEffect(() => { loadAudit(); }, [loadAudit]);

  const startEnroll = async () => {
    setMsg(null);
    const r = await enrollMfa();
    setEnroll(r.data);
  };

  const confirmEnroll = async () => {
    try {
      await activateMfa(code);
      setMsg('MFA enabled.');
      setEnroll(null); setCode(''); refreshMe();
    } catch {
      setMsg('Invalid code — try again.');
    }
  };

  const turnOff = async () => {
    try {
      await disableMfa(code);
      setMsg('MFA disabled.'); setCode(''); refreshMe();
    } catch {
      setMsg('Invalid code.');
    }
  };

  const outcomeColor = (o: string) => (o === 'failure' ? 'text-red-400' : 'text-emerald-400');

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold">Security</h1>
        <p className="text-sm text-[var(--text-muted)] font-mono">Multi-factor authentication and account audit trail</p>
      </div>

      <div className="glass-card p-5 max-w-2xl">
        <h3 className="text-lg font-bold mb-1">Two-Factor Authentication (TOTP)</h3>
        <p className="text-sm text-[var(--text-secondary)] mb-3">
          Status: <span className={mfaEnabled ? 'text-emerald-400' : 'text-[var(--text-muted)]'}>{mfaEnabled ? 'Enabled' : 'Disabled'}</span>
        </p>

        {!mfaEnabled && !enroll && <button onClick={startEnroll} className="btn-primary text-sm py-1.5">Enable MFA</button>}

        {!mfaEnabled && enroll && (
          <div className="space-y-3">
            <p className="text-sm">Add this secret to your authenticator app (manual entry), then enter the 6-digit code:</p>
            <div className="p-3 rounded-lg bg-[var(--bg-input)] border border-[var(--border-color)] font-mono text-sm break-all">{enroll.secret}</div>
            <p className="text-[11px] font-mono text-[var(--text-muted)] break-all">{enroll.otpauth_uri}</p>
            <div className="flex gap-2">
              <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" className="input-field w-40" />
              <button onClick={confirmEnroll} className="btn-primary text-sm py-1.5">Verify & Enable</button>
            </div>
          </div>
        )}

        {mfaEnabled && (
          <div className="flex gap-2 items-center">
            <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="Code to disable" className="input-field w-48" />
            <button onClick={turnOff} className="text-sm py-1.5 px-4 rounded-lg border border-[var(--accent-red)] text-[var(--accent-red)]">Disable MFA</button>
          </div>
        )}
        {msg && <p className="text-xs mt-2 font-mono text-[var(--accent-cyan)]">{msg}</p>}
      </div>

      {isAdmin && (
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-lg font-bold">Audit Log</h3>
            <input value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} placeholder="Filter by action (e.g. login.success)" className="input-field w-80 text-sm py-1.5" />
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-[var(--text-muted)] font-mono border-b border-[var(--border-color)]">
                <tr>
                  <th className="text-left py-2 pr-3">Time</th><th className="text-left pr-3">Actor</th>
                  <th className="text-left pr-3">Action</th><th className="text-left pr-3">Target</th>
                  <th className="text-left pr-3">IP</th><th className="text-left pr-3">Outcome</th>
                  <th className="text-left">Detail</th>
                </tr>
              </thead>
              <tbody>
                {audit.map((e) => (
                  <tr key={e.id} className="border-b border-[var(--border-color)]/40">
                    <td className="py-1.5 pr-3 font-mono text-[var(--text-muted)] whitespace-nowrap">{e.timestamp?.slice(0, 19)}</td>
                    <td className="pr-3">{e.actor || '—'}</td>
                    <td className="pr-3 font-mono text-[var(--accent-cyan)]">{e.action}</td>
                    <td className="pr-3">{e.target_type ? `${e.target_type}:${e.target_id}` : '—'}</td>
                    <td className="pr-3 font-mono">{e.source_ip || '—'}</td>
                    <td className={`pr-3 font-mono ${outcomeColor(e.outcome)}`}>{e.outcome}</td>
                    <td className="text-[var(--text-secondary)]">{e.detail || ''}</td>
                  </tr>
                ))}
                {audit.length === 0 && <tr><td colSpan={7} className="py-3 text-[var(--text-muted)] font-mono">No audit entries.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
