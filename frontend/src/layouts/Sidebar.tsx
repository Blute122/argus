import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';

const NAV_ITEMS = [
  { path: '/dashboard', label: 'Dashboard', icon: 'DB' },
  { path: '/alerts', label: 'Alerts', icon: 'AL' },
  { path: '/incidents', label: 'Incidents', icon: 'IR' },
  { path: '/assets', label: 'Assets', icon: 'AS' },
  { path: '/logs', label: 'Log Stream', icon: 'LG' },
  { path: '/hunting', label: 'Threat Hunt', icon: 'TH' },
  { path: '/simulations', label: 'Attack Sim', icon: 'SIM' },
  { path: '/mitre', label: 'MITRE ATT&CK', icon: 'MT' },
  { path: '/reports', label: 'Reports', icon: 'RP' },
];

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const roleLabels: Record<string, string> = {
    admin: 'Administrator',
    analyst_l1: 'L1 Analyst',
    analyst_l2: 'L2 Analyst',
    analyst_l3: 'L3 Analyst',
    threat_hunter: 'Threat Hunter',
    incident_responder: 'IR Specialist',
  };

  return (
    <aside className="flex flex-col h-full w-[240px] min-w-[240px] border-r border-[var(--border-color)] bg-[var(--bg-secondary)]">
      <div className="p-5 border-b border-[var(--border-color)]">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold text-sm">
            SC
          </div>
          <div>
            <h1 className="text-sm font-bold text-[var(--text-primary)] tracking-wide">SOC COMMAND</h1>
            <p className="text-[10px] text-[var(--accent-cyan)] font-mono tracking-widest">v1.0 SIMULATOR</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <span className="w-7 text-center text-[10px] font-mono font-bold text-[var(--accent-cyan)]">{item.icon}</span>
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-[var(--border-color)]">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold">
            {user?.full_name?.charAt(0) || 'U'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-[var(--text-primary)] truncate">{user?.full_name}</p>
            <p className="text-[10px] text-[var(--accent-cyan)] font-mono">{roleLabels[user?.role || ''] || user?.role}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="w-full text-xs text-[var(--text-muted)] hover:text-[var(--accent-red)] transition-colors py-1.5 rounded border border-[var(--border-color)] hover:border-[var(--accent-red)]"
        >
          Sign Out
        </button>
      </div>
    </aside>
  );
}
