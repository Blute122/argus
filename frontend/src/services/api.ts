import axios from 'axios';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soc_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Handle 401 → redirect to login
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('soc_token');
      localStorage.removeItem('soc_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// Auth
export const login = (username: string, password: string) => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);
  return api.post('/auth/login', formData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
};
export const register = (data: any) => api.post('/auth/register', data);
export const getMe = () => api.get('/auth/me');
export const getUsers = () => api.get('/auth/users');

// Dashboard
export const getDashboardStats = () => api.get('/dashboard/stats');

// Alerts
export const getAlerts = (params?: any) => api.get('/alerts/', { params });
export const getAlertStats = () => api.get('/alerts/stats');
export const updateAlertStatus = (id: number, status: string) =>
  api.patch(`/alerts/${id}/status`, null, { params: { status } });

// Incidents
export const getIncidents = (params?: any) => api.get('/incidents/', { params });
export const createIncident = (data: any) => api.post('/incidents/', data);
export const updateIncidentStatus = (id: number, status: string) =>
  api.patch(`/incidents/${id}/status`, null, { params: { status } });
export const getIncidentNotes = (id: number) => api.get(`/incidents/${id}/notes`);
export const addIncidentNote = (id: number, data: any) => api.post(`/incidents/${id}/notes`, data);
export const getIncidentStats = () => api.get('/incidents/stats');

// Logs & Hunting
export const getLogs = (params?: any) => api.get('/logs', { params });
export const getLogStats = () => api.get('/logs/stats');
export const runHuntQuery = (query: string) => api.post('/hunt', null, { params: { query } });
export const getHuntHistory = () => api.get('/hunts/history');
export const getSavedHunts = () => api.get('/hunts/saved');
export const saveHunt = (id: number) => api.post(`/hunts/${id}/save`);

// Attack Simulations
export const getScenarios = () => api.get('/simulations/scenarios');
export const getScenarioDetail = (id: string) => api.get(`/simulations/scenarios/${id}`);
export const runSimulation = (id: string) => api.post(`/simulations/run/${id}`);
export const getSimulationHistory = () => api.get('/simulations/history');

// MITRE
export const getMitreTactics = () => api.get('/mitre/tactics');
export const getMitreTechniques = () => api.get('/mitre/techniques');
export const getMitreTechniqueDetail = (id: string) => api.get(`/mitre/techniques/${id}`);

export default api;
