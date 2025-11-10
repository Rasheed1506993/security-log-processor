import React, { useState, useEffect } from 'react';
import apiService from '../services/api';

function LogsView() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [pagination, setPagination] = useState({
    skip: 0,
    limit: 50,
    total: 0,
  });
  
  // Filters
  const [filters, setFilters] = useState({
    severity: '',
    event_type: '',
    search: '',
  });

  useEffect(() => {
    loadLogs();
  }, [pagination.skip, filters]);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const params = {
        skip: pagination.skip,
        limit: pagination.limit,
        ...filters,
      };
      
      const data = await apiService.getLogs(params);
      setLogs(data.logs);
      setPagination(prev => ({ ...prev, total: data.total }));
      setError(null);
    } catch (err) {
      setError('Failed to load logs: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPagination(prev => ({ ...prev, skip: 0 })); // Reset to first page
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

  const getSeverityClass = (severity) => {
    const severityMap = {
      high: 'severity-high',
      medium: 'severity-medium',
      low: 'severity-low',
    };
    return severityMap[severity?.toLowerCase()] || '';
  };

  return (
    <div className="logs-view">
      <div className="page-header">
        <h2>Security Logs</h2>
        <div className="header-actions">
          <button onClick={loadLogs} className="btn-secondary">
            🔄 Refresh
          </button>
        </div>
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
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Event Type:</label>
          <input
            type="text"
            value={filters.event_type}
            onChange={(e) => handleFilterChange('event_type', e.target.value)}
            placeholder="Filter by event type..."
          />
        </div>

        <div className="filter-group">
          <label>Search:</label>
          <input
            type="text"
            value={filters.search}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            placeholder="Search in logs..."
          />
        </div>

        {(filters.severity || filters.event_type || filters.search) && (
          <button 
            onClick={() => setFilters({ severity: '', event_type: '', search: '' })}
            className="btn-clear-filters"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Logs Table */}
      {loading ? (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Loading logs...</p>
        </div>
      ) : error ? (
        <div className="error-container">
          <p>{error}</p>
          <button onClick={loadLogs}>Retry</button>
        </div>
      ) : logs.length === 0 ? (
        <div className="no-data">
          <p>No logs found matching your filters.</p>
        </div>
      ) : (
        <>
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Severity</th>
                  <th>User</th>
                  <th>Source</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, index) => (
                  <tr key={index}>
                    <td className="timestamp-cell">
                      {log.timestamp || 'N/A'}
                    </td>
                    <td className="event-type-cell">
                      {log.event_type || 'Unknown'}
                    </td>
                    <td>
                      <span className={`severity-badge ${getSeverityClass(log.severity)}`}>
                        {log.severity || 'N/A'}
                      </span>
                    </td>
                    <td>{log.user || 'N/A'}</td>
                    <td>{log.source || 'N/A'}</td>
                    <td className="details-cell">
                      <details>
                        <summary>View Raw Log</summary>
                        <pre>{log.raw_log}</pre>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
    </div>
  );
}

export default LogsView;
