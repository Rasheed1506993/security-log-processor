import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const apiService = {
  // Logs endpoints
  getLogs: async (params = {}) => {
    const response = await api.get('/api/logs', { params });
    return response.data;
  },

  getLogByIndex: async (index) => {
    const response = await api.get(`/api/logs/${index}`);
    return response.data;
  },

  // Alerts endpoints
  getAlerts: async (params = {}) => {
    const response = await api.get('/api/alerts', { params });
    return response.data;
  },

  getAlertById: async (alertId) => {
    const response = await api.get(`/api/alerts/${alertId}`);
    return response.data;
  },

  getAlertsBySeverity: async (severity) => {
    const response = await api.get(`/api/alerts/severity/${severity}`);
    return response.data;
  },

  // Statistics
  getStatistics: async () => {
    const response = await api.get('/api/statistics');
    return response.data;
  },

  getDashboardData: async () => {
    const response = await api.get('/api/dashboard');
    return response.data;
  },

  // MITRE ATT&CK
  getMitreCoverage: async () => {
    const response = await api.get('/api/mitre');
    return response.data;
  },

  // Health check
  healthCheck: async () => {
    const response = await api.get('/api/health');
    return response.data;
  },

  // Export
  exportLogs: async () => {
    const response = await api.get('/api/export/logs', {
      responseType: 'blob',
    });
    return response.data;
  },

  exportAlerts: async () => {
    const response = await api.get('/api/export/alerts', {
      responseType: 'blob',
    });
    return response.data;
  },
};

export default apiService;
