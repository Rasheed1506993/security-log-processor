import React, { useState, useEffect } from 'react';
import apiService from '../services/api';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6',
};

function Dashboard() {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const data = await apiService.getDashboardData();
      setDashboardData(data);
      setError(null);
    } catch (err) {
      setError('Failed to load dashboard data: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container">
        <h2>Error</h2>
        <p>{error}</p>
        <button onClick={loadDashboardData}>Retry</button>
      </div>
    );
  }

  if (!dashboardData) {
    return <div className="no-data">No data available</div>;
  }

  const { overview, severity_distribution, alert_severity_distribution, top_event_types, recent_alerts, risk_level } = dashboardData;

  // Prepare chart data
  const alertSeverityChartData = Object.entries(alert_severity_distribution || {}).map(([severity, count]) => ({
    name: severity,
    value: count,
    color: SEVERITY_COLORS[severity] || '#6b7280',
  }));

  const eventTypesChartData = Object.entries(top_event_types || {}).map(([type, count]) => ({
    name: type,
    count: count,
  }));

  const getRiskLevelColor = (level) => {
    const colors = {
      CRITICAL: '#dc2626',
      HIGH: '#ea580c',
      MEDIUM: '#f59e0b',
      LOW: '#3b82f6',
      UNKNOWN: '#6b7280',
    };
    return colors[level] || colors.UNKNOWN;
  };

  return (
    <div className="dashboard">
      <div className="page-header">
        <h2>Security Dashboard</h2>
        <button onClick={loadDashboardData} className="refresh-btn">
          🔄 Refresh
        </button>
      </div>

      {/* Overview Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <p className="stat-label">Total Logs</p>
            <p className="stat-value">{overview.total_logs.toLocaleString()}</p>
          </div>
        </div>

        <div className="stat-card alert-card">
          <div className="stat-icon">🚨</div>
          <div className="stat-content">
            <p className="stat-label">Total Alerts</p>
            <p className="stat-value">{overview.total_alerts.toLocaleString()}</p>
          </div>
        </div>

        <div className="stat-card critical-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-content">
            <p className="stat-label">High Priority</p>
            <p className="stat-value">{overview.high_priority_alerts}</p>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">👥</div>
          <div className="stat-content">
            <p className="stat-label">Unique Users</p>
            <p className="stat-value">{overview.unique_users}</p>
          </div>
        </div>
      </div>

      {/* Risk Level Indicator */}
      <div className="risk-indicator" style={{ borderLeftColor: getRiskLevelColor(risk_level) }}>
        <h3>Risk Level</h3>
        <div className="risk-badge" style={{ backgroundColor: getRiskLevelColor(risk_level) }}>
          {risk_level}
        </div>
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        {/* Alert Severity Distribution */}
        {alertSeverityChartData.length > 0 && (
          <div className="chart-card">
            <h3>Alert Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={alertSeverityChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {alertSeverityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Top Event Types */}
        {eventTypesChartData.length > 0 && (
          <div className="chart-card">
            <h3>Top Event Types</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={eventTypesChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Recent Alerts */}
      {recent_alerts && recent_alerts.length > 0 && (
        <div className="recent-alerts-section">
          <h3>Recent Alerts</h3>
          <div className="alerts-list">
            {recent_alerts.map((alert) => (
              <div key={alert.alert_id} className="alert-item" style={{ borderLeftColor: SEVERITY_COLORS[alert.severity] }}>
                <div className="alert-header">
                  <span className="alert-severity" style={{ backgroundColor: SEVERITY_COLORS[alert.severity] }}>
                    {alert.severity}
                  </span>
                  <span className="alert-rule">Rule #{alert.rule_id}</span>
                </div>
                <h4>{alert.rule_name}</h4>
                <p className="alert-description">{alert.description}</p>
                <div className="alert-footer">
                  <span className="alert-timestamp">{new Date(alert.timestamp).toLocaleString()}</span>
                  {alert.mitre_technique && (
                    <span className="mitre-badge">{alert.mitre_technique}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default Dashboard;
