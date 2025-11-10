import React, { useState, useEffect } from 'react';
import apiService from '../services/api';
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

function Statistics() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStatistics();
  }, []);

  const loadStatistics = async () => {
    try {
      setLoading(true);
      const data = await apiService.getStatistics();
      setStats(data);
      setError(null);
    } catch (err) {
      setError('Failed to load statistics: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading statistics...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container">
        <h2>Error</h2>
        <p>{error}</p>
        <button onClick={loadStatistics}>Retry</button>
      </div>
    );
  }

  if (!stats) {
    return <div className="no-data">No statistics available</div>;
  }

  // Prepare chart data
  const logSeverityData = Object.entries(stats.logs?.by_severity || {}).map(([severity, count]) => ({
    name: severity,
    value: count,
  }));

  const eventTypesData = Object.entries(stats.logs?.by_event_type || {})
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10)
    .map(([type, count]) => ({
      name: type,
      count: count,
    }));

  return (
    <div className="statistics-page">
      <div className="page-header">
        <h2>System Statistics</h2>
        <button onClick={loadStatistics} className="btn-secondary">
          🔄 Refresh
        </button>
      </div>

      {/* Overview Stats */}
      <div className="stats-section">
        <h3>Log Processing Overview</h3>
        <div className="stats-grid">
          <div className="stat-item">
            <p className="stat-label">Total Logs Processed</p>
            <p className="stat-value">{stats.logs?.total.toLocaleString() || 0}</p>
          </div>
          <div className="stat-item">
            <p className="stat-label">Unique Users</p>
            <p className="stat-value">{stats.logs?.unique_users || 0}</p>
          </div>
          <div className="stat-item">
            <p className="stat-label">Unknown Logs</p>
            <p className="stat-value">{stats.processing?.unknown_logs_count || 0}</p>
          </div>
          {stats.alerts && (
            <div className="stat-item">
              <p className="stat-label">Total Alerts</p>
              <p className="stat-value">{stats.alerts.total || 0}</p>
            </div>
          )}
        </div>
      </div>

      {/* Time Range */}
      {stats.logs?.time_range && (
        <div className="stats-section">
          <h3>Time Range</h3>
          <div className="time-range-display">
            <div>
              <strong>Start:</strong> {stats.logs.time_range.start || 'N/A'}
            </div>
            <div>
              <strong>End:</strong> {stats.logs.time_range.end || 'N/A'}
            </div>
          </div>
        </div>
      )}

      {/* Charts Section */}
      <div className="charts-section">
        {/* Log Severity Distribution */}
        {logSeverityData.length > 0 && (
          <div className="chart-container">
            <h3>Log Severity Distribution</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={logSeverityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {logSeverityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={['#dc2626', '#f59e0b', '#3b82f6'][index % 3]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Top Event Types */}
        {eventTypesData.length > 0 && (
          <div className="chart-container">
            <h3>Top Event Types</h3>
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={eventTypesData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" width={150} />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Decoder Statistics */}
      {stats.decoders && (
        <div className="stats-section">
          <h3>Decoder Performance</h3>
          <div className="decoder-stats">
            {stats.decoders.basic_decoder && (
              <div className="decoder-card">
                <h4>Basic Decoder</h4>
                <p>Successful: {stats.decoders.basic_decoder.successful_decodes}</p>
              </div>
            )}
            {stats.decoders.windows_decoder && (
              <div className="decoder-card">
                <h4>Windows Decoder</h4>
                <p>Total: {stats.decoders.windows_decoder.windows_events_decoded}</p>
                <ul>
                  <li>Defender: {stats.decoders.windows_decoder.defender_events}</li>
                  <li>Security: {stats.decoders.windows_decoder.security_events}</li>
                  <li>Sysmon: {stats.decoders.windows_decoder.sysmon_events}</li>
                  <li>PowerShell: {stats.decoders.windows_decoder.powershell_events}</li>
                </ul>
              </div>
            )}
            {stats.decoders.generic_decoder && (
              <div className="decoder-card">
                <h4>Generic Decoder</h4>
                <ul>
                  <li>JSON: {stats.decoders.generic_decoder.json_decoded}</li>
                  <li>Key-Value: {stats.decoders.generic_decoder.kv_decoded}</li>
                  <li>XML: {stats.decoders.generic_decoder.xml_decoded}</li>
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Alert Statistics */}
      {stats.alerts && (
        <div className="stats-section">
          <h3>Alert Analysis</h3>
          <div className="alert-stats-grid">
            <div className="stat-item alert-stat">
              <p className="stat-label">Rules Triggered</p>
              <p className="stat-value">{stats.alerts.rules_triggered}</p>
            </div>
            {Object.entries(stats.alerts.by_severity || {}).map(([severity, count]) => (
              <div key={severity} className="stat-item alert-stat">
                <p className="stat-label">{severity} Alerts</p>
                <p className="stat-value">{count}</p>
              </div>
            ))}
          </div>

          {/* Risk Assessment */}
          {stats.alerts.risk_assessment && (
            <div className="risk-assessment-display">
              <h4>Risk Assessment</h4>
              <div className="risk-details">
                <div>
                  <strong>Risk Level:</strong> 
                  <span className={`risk-level-badge risk-${stats.alerts.risk_assessment.risk_level?.toLowerCase()}`}>
                    {stats.alerts.risk_assessment.risk_level}
                  </span>
                </div>
                <div>
                  <strong>Risk Score:</strong> {stats.alerts.risk_assessment.risk_score}
                </div>
                <div>
                  <strong>Critical Alerts:</strong> {stats.alerts.risk_assessment.critical_alerts}
                </div>
              </div>
            </div>
          )}

          {/* Top Rules */}
          {stats.alerts.top_rules && stats.alerts.top_rules.length > 0 && (
            <div className="top-rules-section">
              <h4>Top Triggered Rules</h4>
              <table className="top-rules-table">
                <thead>
                  <tr>
                    <th>Rule ID</th>
                    <th>Rule Name</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.alerts.top_rules.map((rule) => (
                    <tr key={rule.rule_id}>
                      <td>{rule.rule_id}</td>
                      <td>{rule.rule_name}</td>
                      <td>{rule.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* MITRE Coverage */}
          {stats.alerts.mitre_coverage && stats.alerts.mitre_coverage.length > 0 && (
            <div className="mitre-coverage-section">
              <h4>MITRE ATT&CK Coverage</h4>
              <div className="mitre-techniques">
                {stats.alerts.mitre_coverage.map((technique, idx) => (
                  <span key={idx} className="mitre-technique-badge">
                    {technique}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Processing Information */}
      <div className="stats-section">
        <h3>Processing Information</h3>
        <div className="processing-info">
          <div>
            <strong>Processed At:</strong> {stats.processing?.processed_at ? new Date(stats.processing.processed_at).toLocaleString() : 'N/A'}
          </div>
          <div>
            <strong>Source File:</strong> {stats.processing?.source_file || 'N/A'}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Statistics;
