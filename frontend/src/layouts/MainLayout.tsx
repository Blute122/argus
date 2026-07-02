import { Outlet, Navigate } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';
import Sidebar from './Sidebar';

export default function MainLayout() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-[var(--bg-primary)]">
        <div className="rounded border border-[var(--border-color)] bg-[var(--bg-secondary)] px-5 py-4 font-mono text-xs uppercase tracking-wider text-[var(--accent-cyan)] shadow-lg shadow-cyan-950/20">
          Validating session...
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[var(--bg-primary)]">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}
