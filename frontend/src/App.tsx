import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './store/AuthContext';
import MainLayout from './layouts/MainLayout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import LogStreamPage from './pages/LogStreamPage';
import HuntingPage from './pages/HuntingPage';
import IncidentsPage from './pages/IncidentsPage';
import SimulationsPage from './pages/SimulationsPage';
import MitrePage from './pages/MitrePage';
import AssetsPage from './pages/AssetsPage';
import ReportsPage from './pages/ReportsPage';
import RulesPage from './pages/RulesPage';

export default function App() {
  return (
    <AuthProvider>
      <HashRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<MainLayout />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/logs" element={<LogStreamPage />} />
            <Route path="/hunting" element={<HuntingPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/simulations" element={<SimulationsPage />} />
            <Route path="/mitre" element={<MitrePage />} />
            <Route path="/reports" element={<ReportsPage />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </HashRouter>
    </AuthProvider>
  );
}
