import React, { useState, useEffect } from 'react';
import apiService from '../services/api';

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#f59e0b',
  LOW: '#3b82f6',
};

function AlertsView() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [pagination, setPagination] = useState({
    skip: 0,
    limit: 20,
    total: 0,
  });
  
  const [filters, setFilters] = useState({
    severity: '',
    rule_id: '',
  });

  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    loadAlerts();
  }, [pagination.skip, filters]);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const params = {
        skip: pagination.skip,
        limit: pagination.limit,
        ...filters,
      };
      
      const data = await apiService.getAlerts(params);
      setAlerts(data.alerts);
      setPagination(prev => ({ ...prev, total: data.total }));
      setError(null);
    } catch (err) {
      setError('Failed to load alerts: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, skip: 0 }));
  };

  const nextPage = () => {
    if (pagination.skip + pagination.limit < pagination.total) {
      setPagination(prev => ({ ...prev, skip: prev.skip + prev.limit }));
    }
  };

  const prevPage = () => {
    if (pagination.skip > 0) {
      setPagination(prev => ({ ...prev, skip: Math.max(0, prev.skip - prev.limit) }));
    }
  };

  return (
    <div className="alerts-view">
      <div className="page-header">
        <h2>Security Alerts</h2>
        <button onClick={loadAlerts} className="btn-secondary">
          🔄 Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="filters-section">
        <div className="filter-group">
          <label>Severity:</label>
          <select 
            value={filters.severity} 
            onChange={(e) => handleFilterChange('severity', e.target.value)}
          >
            <option value="">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Rule ID:</label>
          <input
            type="number"
            value={filters.rule_id}
            onChange={(e) => handleFilterChange('rule_id', e.target.value)}
            placeholder="Filter by rule ID..."
          />
        </div>

        {(filters.severity || filters.rule_id) && (
          <button 
            onClick={() => setFilters({ severity: '', rule_id: '' })}
            className="btn-clear-filters"
          >
            Clear Filters
          </button>
        )}
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Loading alerts...</p>
        </div>
      ) : error ? (
        <div className="error-container">
          <p>{error}</p>
          <button onClick={loadAlerts}>Retry</button>
        </div>
      ) : alerts.length === 0 ? (
        <div className="no-data">
          <p>No alerts found matching your filters.</p>
        </div>
      ) : (
        <>
          {/* Alerts Grid */}
          <div className="alerts-grid">
            {alerts.map((alert) => (
              <div 
                key={alert.alert_id} 
                className="alert-card-item"
                style={{ borderLeftColor: SEVERITY_COLORS[alert.severity] }}
                onClick={() => setSelectedAlert(alert)}
              >
                <div className="alert-card-header">
                  <span 
                    className="alert-severity-badge"
                    style={{ backgroundColor: SEVERITY_COLORS[alert.severity] }}
                  >
                    {alert.severity}
                  </span>
                  <span className="alert-rule-id">Rule #{alert.rule_id}</span>
                </div>
                
                <h3 className="alert-title">{alert.rule_name}</h3>
                <p className="alert-description">{alert.description}</p>
                
                <div className="alert-card-footer">
                  <span className="alert-timestamp">
                    {new Date(alert.timestamp).toLocaleString()}
                  </span>
                  {alert.mitre_technique && (
                    <span className="mitre-badge-small">
                      {alert.mitre_technique}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Pagination */}
          <div className="pagination">
            <button 
              onClick={prevPage} 
              disabled={pagination.skip === 0}
              className="btn-pagination"
            >
              ← Previous
            </button>
            <span className="pagination-info">
              Showing {pagination.skip + 1} - {Math.min(pagination.skip + pagination.limit, pagination.total)} of {pagination.total}
            </span>
            <button 
              onClick={nextPage} 
              disabled={pagination.skip + pagination.limit >= pagination.total}
              className="btn-pagination"
            >
              Next →
            </button>
          </div>
        </>
      )}

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{selectedAlert.rule_name}</h2>
              <button 
                className="modal-close" 
                onClick={() => setSelectedAlert(null)}
              >
                ✕
              </button>
            </div>
            
            <div className="modal-body">
              <div className="alert-detail-section">
                <h3>Alert Information</h3>
                <table className="detail-table">
                  <tbody>
                    <tr>
                      <td><strong>Alert ID:</strong></td>
                      <td>{selectedAlert.alert_id}</td>
                    </tr>
                    <tr>
                      <td><strong>Rule ID:</strong></td>
                      <td>{selectedAlert.rule_id}</td>
                    </tr>
                    <tr>
                      <td><strong>Severity:</strong></td>
                      <td>
                        <span 
                          className="severity-badge-large"
                          style={{ backgroundColor: SEVERITY_COLORS[selectedAlert.severity] }}
                        >
                          {selectedAlert.severity}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <td><strong>Level:</strong></td>
                      <td>{selectedAlert.level}</td>
                    </tr>
                    <tr>
                      <td><strong>Category:</strong></td>
                      <td>{selectedAlert.category}</td>
                    </tr>
                    <tr>
                      <td><strong>Timestamp:</strong></td>
                      <td>{new Date(selectedAlert.timestamp).toLocaleString()}</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {selectedAlert.mitre_technique && (
                <div className="alert-detail-section">
                  <h3>MITRE ATT&CK</h3>
                  <p><strong>Technique:</strong> {selectedAlert.mitre_technique}</p>
                  {selectedAlert.mitre_tactic && (
                    <p><strong>Tactic:</strong> {selectedAlert.mitre_tactic}</p>
                  )}
                </div>
              )}

              <div className="alert-detail-section">
                <h3>Description</h3>
                <p>{selectedAlert.description}</p>
              </div>

              {selectedAlert.matched_conditions && selectedAlert.matched_conditions.length > 0 && (
                <div className="alert-detail-section">
                  <h3>Matched Conditions</h3>
                  <ul className="conditions-list">
                    {selectedAlert.matched_conditions.map((condition, idx) => (
                      <li key={idx}>{condition}</li>
                    ))}
                  </ul>
                </div>
              )}

              {selectedAlert.matched_log && (
                <div className="alert-detail-section">
                  <h3>Matched Log Data</h3>
                  <pre className="log-data-pre">
                    {JSON.stringify(selectedAlert.matched_log, null, 2)}
                  </pre>
                </div>
              )}

              {selectedAlert.tags && selectedAlert.tags.length > 0 && (
                <div className="alert-detail-section">
                  <h3>Tags</h3>
                  <div className="tags-container">
                    {selectedAlert.tags.map((tag, idx) => (
                      <span key={idx} className="tag-badge">{tag}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AlertsView;
