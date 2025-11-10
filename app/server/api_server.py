"""
FastAPI Server for EDR Log Processing System
Provides REST API endpoints for accessing processed logs and alerts
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
from datetime import datetime
from pydantic import BaseModel

# Initialize FastAPI app
app = FastAPI(
    title="EDR Log Processing API",
    description="API for accessing security logs, alerts, and analysis results",
    version="1.0.0"
)

# Configure CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your React app's URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data paths
APP_DIR = Path(__file__).parent.parent
DATA_DIR = APP_DIR / "data" / "output"
CONTEXT_FILE = DATA_DIR / "processed_context.json"
ALERTS_FILE = DATA_DIR / "alerts.json"
DECODED_LOGS_FILE = DATA_DIR / "decoded_logs.json"


# Response models
class LogEntry(BaseModel):
    line_number: Optional[int] = None
    timestamp: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    user: Optional[str] = None
    decoder_used: Optional[str] = None
    raw_log: Optional[str] = None


class AlertEntry(BaseModel):
    alert_id: str
    rule_id: int
    rule_name: str
    severity: str
    description: str
    timestamp: str


class Statistics(BaseModel):
    total_logs: int
    total_alerts: int
    severity_distribution: Dict[str, int]
    event_types: Dict[str, int]


# Helper functions
def load_json_file(file_path: Path) -> Dict[str, Any]:
    """Load and parse JSON file"""
    try:
        if not file_path.exists():
            return None
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")
        return None


def get_context_data() -> Optional[Dict[str, Any]]:
    """Get processed context data"""
    return load_json_file(CONTEXT_FILE)


def get_alerts_data() -> Optional[Dict[str, Any]]:
    """Get alerts data"""
    return load_json_file(ALERTS_FILE)


def get_decoded_logs() -> Optional[Dict[str, Any]]:
    """Get decoded logs"""
    return load_json_file(DECODED_LOGS_FILE)


# API Endpoints
@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "EDR Log Processing API",
        "version": "1.0.0",
        "endpoints": {
            "logs": "/api/logs",
            "alerts": "/api/alerts",
            "statistics": "/api/statistics",
            "context": "/api/context",
            "health": "/api/health"
        }
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    context_exists = CONTEXT_FILE.exists()
    alerts_exists = ALERTS_FILE.exists()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "data_availability": {
            "context": context_exists,
            "alerts": alerts_exists,
            "decoded_logs": DECODED_LOGS_FILE.exists()
        }
    }


@app.get("/api/logs")
async def get_logs(
    skip: int = Query(0, ge=0, description="Number of logs to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of logs to return"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    search: Optional[str] = Query(None, description="Search in log content")
):
    """
    Get decoded logs with pagination and filtering
    """
    context = get_context_data()
    
    if not context:
        raise HTTPException(status_code=404, detail="Log data not found. Please process logs first.")
    
    logs = context.get('decoded_logs', [])
    
    # Apply filters
    filtered_logs = logs
    
    if severity:
        filtered_logs = [log for log in filtered_logs if log.get('severity', '').lower() == severity.lower()]
    
    if event_type:
        filtered_logs = [log for log in filtered_logs if event_type.lower() in log.get('event_type', '').lower()]
    
    if search:
        search_lower = search.lower()
        filtered_logs = [
            log for log in filtered_logs
            if search_lower in str(log.get('raw_log', '')).lower() or
               search_lower in str(log.get('user', '')).lower() or
               search_lower in str(log.get('event_type', '')).lower()
        ]
    
    # Pagination
    total = len(filtered_logs)
    paginated_logs = filtered_logs[skip:skip + limit]
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "count": len(paginated_logs),
        "logs": paginated_logs
    }


@app.get("/api/logs/{log_index}")
async def get_log_by_index(log_index: int):
    """Get a specific log by its index"""
    context = get_context_data()
    
    if not context:
        raise HTTPException(status_code=404, detail="Log data not found")
    
    logs = context.get('decoded_logs', [])
    
    if log_index < 0 or log_index >= len(logs):
        raise HTTPException(status_code=404, detail="Log not found")
    
    return logs[log_index]


@app.get("/api/alerts")
async def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    rule_id: Optional[int] = Query(None, description="Filter by rule ID")
):
    """
    Get security alerts with pagination and filtering
    """
    alerts_data = get_alerts_data()
    
    if not alerts_data:
        raise HTTPException(status_code=404, detail="Alerts data not found. Please run rules analysis first.")
    
    all_alerts = alerts_data.get('alerts', {}).get('all_alerts', [])
    
    # Apply filters
    filtered_alerts = all_alerts
    
    if severity:
        filtered_alerts = [alert for alert in filtered_alerts if alert.get('severity') == severity.upper()]
    
    if rule_id is not None:
        filtered_alerts = [alert for alert in filtered_alerts if alert.get('rule_id') == rule_id]
    
    # Pagination
    total = len(filtered_alerts)
    paginated_alerts = filtered_alerts[skip:skip + limit]
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "count": len(paginated_alerts),
        "alerts": paginated_alerts
    }


@app.get("/api/alerts/{alert_id}")
async def get_alert_by_id(alert_id: str):
    """Get a specific alert by its ID"""
    alerts_data = get_alerts_data()
    
    if not alerts_data:
        raise HTTPException(status_code=404, detail="Alerts data not found")
    
    all_alerts = alerts_data.get('alerts', {}).get('all_alerts', [])
    
    for alert in all_alerts:
        if alert.get('alert_id') == alert_id:
            return alert
    
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/api/alerts/severity/{severity}")
async def get_alerts_by_severity(severity: str):
    """Get all alerts of a specific severity"""
    alerts_data = get_alerts_data()
    
    if not alerts_data:
        raise HTTPException(status_code=404, detail="Alerts data not found")
    
    severity_alerts = alerts_data.get('alerts', {}).get('by_severity', {}).get(severity.upper(), [])
    
    return {
        "severity": severity.upper(),
        "count": len(severity_alerts),
        "alerts": severity_alerts
    }


@app.get("/api/statistics")
async def get_statistics():
    """Get comprehensive statistics"""
    context = get_context_data()
    alerts_data = get_alerts_data()
    
    if not context:
        raise HTTPException(status_code=404, detail="Context data not found")
    
    stats = {
        "logs": {
            "total": context.get('summary', {}).get('total_events', 0),
            "by_severity": context.get('summary', {}).get('severity_distribution', {}),
            "by_event_type": context.get('summary', {}).get('event_types', {}),
            "unique_users": context.get('summary', {}).get('unique_users', 0),
            "time_range": context.get('summary', {}).get('time_range', {})
        },
        "decoders": context.get('metadata', {}).get('decoder_statistics', {}),
        "processing": {
            "processed_at": context.get('metadata', {}).get('processed_at'),
            "source_file": context.get('metadata', {}).get('source_file'),
            "unknown_logs_count": context.get('metadata', {}).get('unknown_logs_count', 0)
        }
    }
    
    if alerts_data:
        stats["alerts"] = {
            "total": alerts_data.get('analysis_metadata', {}).get('total_alerts', 0),
            "by_severity": alerts_data.get('statistics', {}).get('severity_distribution', {}),
            "rules_triggered": alerts_data.get('analysis_metadata', {}).get('rules_triggered', 0),
            "risk_assessment": alerts_data.get('risk_summary', {}),
            "top_rules": alerts_data.get('statistics', {}).get('top_triggered_rules', []),
            "mitre_coverage": alerts_data.get('statistics', {}).get('mitre_coverage', [])
        }
    
    return stats


@app.get("/api/context")
async def get_full_context():
    """Get the complete processed context"""
    context = get_context_data()
    
    if not context:
        raise HTTPException(status_code=404, detail="Context data not found")
    
    # Return context without the full logs array to reduce payload size
    context_summary = {k: v for k, v in context.items() if k != 'decoded_logs'}
    context_summary['decoded_logs_count'] = len(context.get('decoded_logs', []))
    
    return context_summary


@app.get("/api/dashboard")
async def get_dashboard_data():
    """Get aggregated data for dashboard display"""
    context = get_context_data()
    alerts_data = get_alerts_data()
    
    if not context:
        raise HTTPException(status_code=404, detail="Data not found")
    
    summary = context.get('summary', {})
    
    dashboard = {
        "overview": {
            "total_logs": summary.get('total_events', 0),
            "total_alerts": alerts_data.get('analysis_metadata', {}).get('total_alerts', 0) if alerts_data else 0,
            "high_priority_alerts": 0,
            "unique_users": summary.get('unique_users', 0)
        },
        "severity_distribution": summary.get('severity_distribution', {}),
        "alert_severity_distribution": {},
        "top_event_types": dict(list(summary.get('event_types', {}).items())[:5]),
        "recent_alerts": [],
        "risk_level": context.get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
        "time_range": summary.get('time_range', {})
    }
    
    if alerts_data:
        alert_severity = alerts_data.get('statistics', {}).get('severity_distribution', {})
        dashboard["alert_severity_distribution"] = alert_severity
        dashboard["overview"]["high_priority_alerts"] = (
            alert_severity.get('CRITICAL', 0) + alert_severity.get('HIGH', 0)
        )
        
        # Get 10 most recent alerts
        all_alerts = alerts_data.get('alerts', {}).get('all_alerts', [])
        dashboard["recent_alerts"] = sorted(
            all_alerts,
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )[:10]
    
    return dashboard


@app.get("/api/mitre")
async def get_mitre_coverage():
    """Get MITRE ATT&CK coverage information"""
    alerts_data = get_alerts_data()
    
    if not alerts_data:
        return {"techniques": [], "tactics": [], "by_technique": {}}
    
    by_technique = alerts_data.get('alerts', {}).get('by_mitre_technique', {})
    
    mitre_info = {
        "techniques": list(by_technique.keys()),
        "techniques_count": len(by_technique),
        "by_technique": {
            technique: len(alerts)
            for technique, alerts in by_technique.items()
        }
    }
    
    return mitre_info


@app.get("/api/export/logs")
async def export_logs():
    """Export all logs as JSON"""
    context = get_context_data()
    
    if not context:
        raise HTTPException(status_code=404, detail="Log data not found")
    
    return JSONResponse(
        content=context.get('decoded_logs', []),
        headers={
            "Content-Disposition": f"attachment; filename=logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        }
    )


@app.get("/api/export/alerts")
async def export_alerts():
    """Export all alerts as JSON"""
    alerts_data = get_alerts_data()
    
    if not alerts_data:
        raise HTTPException(status_code=404, detail="Alerts data not found")
    
    return JSONResponse(
        content=alerts_data,
        headers={
            "Content-Disposition": f"attachment; filename=alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        }
    )


# Run the server
if __name__ == "__main__":
    import uvicorn
    print("=" * 80)
    print(" " * 25 + "EDR Log Processing API Server")
    print("=" * 80)
    print("\nStarting FastAPI server...")
    print("API Documentation: http://localhost:8000/docs")
    print("Alternative Docs: http://localhost:8000/redoc")
    print("\nPress Ctrl+C to stop the server\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
