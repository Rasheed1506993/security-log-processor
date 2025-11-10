import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import LogsView from './pages/LogsView';
import AlertsView from './pages/AlertsView';
import Statistics from './pages/Statistics';
import './styles/App.css';

function App() {
  return (
    <Router>
      <div className="app">
        <nav className="navbar">
          <div className="navbar-brand">
            <h1>🛡️ EDR Log Processing System</h1>
          </div>
          <div className="navbar-menu">
            <Link to="/" className="nav-link">Dashboard</Link>
            <Link to="/logs" className="nav-link">Logs</Link>
            <Link to="/alerts" className="nav-link">Alerts</Link>
            <Link to="/statistics" className="nav-link">Statistics</Link>
          </div>
        </nav>

        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/logs" element={<LogsView />} />
            <Route path="/alerts" element={<AlertsView />} />
            <Route path="/statistics" element={<Statistics />} />
          </Routes>
        </main>

        <footer className="footer">
          <p>EDR Log Processing System v1.0.0 | Powered by FastAPI & React</p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
