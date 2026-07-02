import axios from 'axios';

const API_BASE = '/api';

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
});

let protectedRequestController = new AbortController();

const isLoginRoute = () => window.location.hash.includes('/login');
const isPublicAuthUrl = (url: string) => url.includes('/auth/login') || url.includes('/auth/register');

export const cancelProtectedRequests = () => {
  protectedRequestController.abort();
  protectedRequestController = new AbortController();
};

export const setAuthToken = (token: string | null) => {
  if (token) {
    api.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    delete api.defaults.headers.common.Authorization;
  }
};

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('soc_token');
  const url = config.url || '';
  const isPublicAuthRequest = isPublicAuthUrl(url);

  if ((!token || isLoginRoute()) && !isPublicAuthRequest) {
    return Promise.reject(new axios.CanceledError('Authentication token is not available.'));
  }

  if (!isPublicAuthRequest) {
    config.signal = config.signal || protectedRequestController.signal;
  }

  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (axios.isCancel(err)) {
      return Promise.reject(err);
    }

    const isLoginRequest = err.config?.url?.includes('/auth/login');
    const headers = err.config?.headers;
    const requestAuth =
      typeof headers?.get === 'function'
        ? headers.get('Authorization')
        : headers?.Authorization || headers?.authorization;
    const currentToken = localStorage.getItem('soc_token');
    const isCurrentSessionRequest = Boolean(
      currentToken && requestAuth === `Bearer ${currentToken}`
    );

    if (err.response?.status === 401 && !isLoginRequest && !isLoginRoute() && isCurrentSessionRequest) {
      cancelProtectedRequests();
      localStorage.removeItem('soc_token');
      localStorage.removeItem('soc_user');
      setAuthToken(null);
      window.dispatchEvent(new Event('soc:logout'));
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
export const getAlertContext = (id: number) => api.get(`/alerts/${id}/context`);
export const updateAlertStatus = (id: number, status: string) =>
  api.patch(`/alerts/${id}/status`, null, { params: { status } });
export const createIncidentFromAlert = (id: number) => api.post(`/alerts/${id}/incident`);

// Incidents
export const getIncidents = (params?: any) => api.get('/incidents/', { params });
export const getIncidentDetail = (id: number) => api.get(`/incidents/${id}`);
export const createIncident = (data: any) => api.post('/incidents/', data);
export const updateIncidentStatus = (id: number, status: string) =>
  api.patch(`/incidents/${id}/status`, null, { params: { status } });
export const getIncidentNotes = (id: number) => api.get(`/incidents/${id}/notes`);
export const addIncidentNote = (id: number, data: any) => api.post(`/incidents/${id}/notes`, data);
export const addIncidentEvidence = (id: number, data: any) => api.post(`/incidents/${id}/evidence`, data);
export const getIncidentTimeline = (id: number) => api.get(`/incidents/${id}/timeline`);
export const getIncidentStats = () => api.get('/incidents/stats');
export const enrichIncident = (id: number) => api.post(`/incidents/${id}/enrich`);

// Assets
export const getAssets = (params?: any) => api.get('/assets/', { params });
export const createAsset = (data: any) => api.post('/assets/', data);
export const updateAsset = (id: number, data: any) => api.patch(`/assets/${id}`, data);
export const getAssetStats = () => api.get('/assets/stats');
export const getAssetTelemetry = (id: number) => api.get(`/assets/${id}/telemetry`);

// Logs & Hunting
export const getLogs = (params?: any) => api.get('/logs', { params });
export const getLogStats = () => api.get('/logs/stats');
export const runHuntQuery = (query: string) => api.post('/hunt', null, { params: { query } });
export const createIncidentFromHunt = (data: any) => api.post('/hunt/create-incident', data);
export const attachHuntToIncident = (incidentId: number, data: any) => api.post(`/hunt/attach-incident/${incidentId}`, data);
export const getHuntHistory = () => api.get('/hunts/history');
export const getSavedHunts = () => api.get('/hunts/saved');
export const saveHunt = (id: number) => api.post(`/hunts/${id}/save`);

// Attack Simulations
export const getScenarios = () => api.get('/simulations/scenarios');
export const getScenarioDetail = (id: string) => api.get(`/simulations/scenarios/${id}`);
export const runSimulation = (id: string) => api.post(`/simulations/run/${id}`);
export const getSimulationHistory = () => api.get('/simulations/history');
export const getCampaigns = () => api.get('/simulations/campaigns');
export const getCampaignRuns = () => api.get('/simulations/campaigns/runs');
export const getCampaignRun = (id: number) => api.get(`/simulations/campaigns/runs/${id}`);
export const startCampaign = (id: string) => api.post(`/simulations/campaigns/start/${id}`);
export const runNextCampaignStage = (id: number) => api.post(`/simulations/campaigns/runs/${id}/next`);
export const autorunCampaign = (id: number) => api.post(`/simulations/campaigns/runs/${id}/autorun`);

// MITRE
export const getMitreTactics = () => api.get('/mitre/tactics');
export const getMitreTechniques = () => api.get('/mitre/techniques');
export const getMitreTechniqueDetail = (id: string) => api.get(`/mitre/techniques/${id}`);

// Reports
export const getIncidentReport = (id: number, format = 'markdown') => api.get(`/reports/incident/${id}`, { params: { format } });

export default api;
